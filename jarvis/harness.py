"""The harness — the loop that turns a model into an agent.

Without this file the rest of the project is a chatbot with a nice prompt. The
loop is small enough to read in one sitting, which is the point:

    ask the model
      → it either answers (done) or asks for tools
      → run the tools, hand back every result in one message
      → ask again
    until it answers, or the step budget runs out

Everything else here exists because that loop meets reality: policy refusals,
paused server-side tool turns, a model that runs out of output tokens mid-answer,
a user who denies an approval, and a step budget that has to end an unproductive
loop before it ends the user's rate limit.

Conversation state lives in `self.messages` and is append-only. The assistant's
`content` goes back verbatim — extracting the text and discarding the rest would
drop the `tool_use` blocks the next turn's `tool_result`s refer to, and the API
would reject the request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config
from .engine import Engine, EngineError, Turn
from .memory import Memory
from .prompts import VERIFIER_PROMPT, build_system_prompt
from .tools import Plan, ToolContext, Toolbox


def _noop(*_args, **_kwargs) -> None:
    return None


@dataclass
class UI:
    """Where the harness sends everything a human might want to see.

    Output only. Approval prompts are not here: they belong to `Toolbox`, which
    is the single place a model request turns into a side effect, and routing
    them through two owners would eventually mean two policies.
    """

    on_text: Callable[[str], None] = _noop           # streamed answer text
    on_thinking: Callable[[str], None] = _noop       # streamed reasoning summary
    on_tool: Callable[[str, dict], None] = _noop     # a tool is about to run
    on_tool_result: Callable[[str, str, bool], None] = _noop
    on_notice: Callable[[str], None] = _noop         # plan updates, memory writes
    on_warning: Callable[[str], None] = _noop


@dataclass
class TurnResult:
    text: str
    steps: int
    tool_calls: int
    stopped_early: bool = False
    refused: bool = False


@dataclass
class Session:
    started_at: str
    model: str
    workspace: str
    events: list[dict] = field(default_factory=list)


class Harness:
    def __init__(
        self,
        config: Config,
        engine: Engine,
        toolbox: Toolbox,
        memory: Memory,
        ui: UI | None = None,
    ):
        self.config = config
        self.engine = engine
        self.toolbox = toolbox
        self.memory = memory
        self.ui = ui or UI()
        self.plan = Plan()
        self.messages: list[dict] = []

        self.ctx = ToolContext(
            config=config,
            workspace=config.workspace,
            memory=memory,
            plan=self.plan,
            notify=self.ui.on_notice,
        )

        # Built once and never mutated: the system prompt sits at the front of
        # every request, so editing it mid-session would invalidate the cached
        # prefix for the entire conversation on the very next turn.
        self.system = [
            {
                "type": "text",
                "text": build_system_prompt(
                    workspace=str(config.workspace),
                    memory_digest=memory.digest(),
                    approval_mode=config.approval_mode,
                    tool_names=toolbox.names(),
                ),
                "cache_control": {"type": "ephemeral"},
            }
        ]

        self.session = Session(
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            model=config.model,
            workspace=str(config.workspace),
        )

    # ── The loop ──────────────────────────────────────────────────────────────

    def run_turn(self, user_input: str) -> TurnResult:
        """Handle one user message, running tools until the model is finished."""
        self.messages.append({"role": "user", "content": user_input})
        self._record("user", {"text": user_input})

        steps = 0
        tool_calls = 0
        final_text = ""
        stopped_early = False
        refused = False

        while steps < self.config.max_steps:
            steps += 1
            turn = self._model_turn()

            if turn.fell_back_to:
                self.ui.on_warning(
                    f"The primary model declined; {turn.fell_back_to} answered instead."
                )

            self.messages.append(
                {"role": "assistant", "content": self.engine.replayable(turn.message.content)}
            )

            if turn.refused:
                refused = True
                final_text = self._refusal_text(turn)
                self.ui.on_warning(final_text)
                break

            if turn.text:
                final_text = turn.text

            # A server-side tool hit its per-turn iteration cap. Re-sending the
            # conversation unchanged resumes it — adding a "continue" message
            # would only confuse the model about whose turn it is.
            if turn.stop_reason == "pause_turn":
                continue

            if turn.stop_reason == "max_tokens":
                self.ui.on_warning(
                    "The answer hit the output token limit and may be cut off. "
                    "Raise max_tokens or ask for a narrower piece of it."
                )
                break

            if turn.stop_reason == "model_context_window_exceeded":
                self.ui.on_warning(
                    "The conversation no longer fits in the context window. "
                    "Start a new session — anything worth keeping should be in memory."
                )
                break

            if not turn.tool_calls:
                break

            tool_calls += len(turn.tool_calls)
            self.messages.append({"role": "user", "content": self._run_tools(turn)})
        else:
            stopped_early = True
            self.ui.on_warning(
                f"Stopped after {self.config.max_steps} steps without finishing. "
                "Raise max_steps, or break the task into smaller requests."
            )

        if not (refused or stopped_early):
            final_text = self._verify(user_input, final_text) or final_text

        self._record("assistant", {"text": final_text, "steps": steps, "tool_calls": tool_calls})
        return TurnResult(
            text=final_text, steps=steps, tool_calls=tool_calls,
            stopped_early=stopped_early, refused=refused,
        )

    def _model_turn(self) -> Turn:
        return self.engine.send(
            system=self.system,
            messages=self.messages,
            tools=self.toolbox.definitions(),
            on_text=self.ui.on_text,
            on_thinking=self.ui.on_thinking if self.config.show_thinking else None,
        )

    # ── Acting ────────────────────────────────────────────────────────────────

    def _run_tools(self, turn: Turn) -> list[dict]:
        """Execute every requested tool and return all results as one message.

        All of them, in a single user message: splitting results across several
        messages teaches the model that its parallel calls were not wanted, and
        it stops making them.
        """
        results: list[dict] = []
        for call in turn.tool_calls:
            args = call.input if isinstance(call.input, dict) else {}
            self.ui.on_tool(call.name, args)

            output, is_error = self.toolbox.run(self.ctx, call.name, args)

            self.ui.on_tool_result(call.name, output, is_error)
            self._record("tool", {"name": call.name, "args": args, "error": is_error})
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": call.id,
                    "content": output or "(no output)",
                    "is_error": is_error,
                }
            )
        return results

    # ── Checking its own work ─────────────────────────────────────────────────

    def _verify(self, user_input: str, answer: str) -> str | None:
        """Optional fresh-context review pass. Off by default.

        A separate model that never saw the working conversation catches dropped
        steps and claimed-but-not-done work better than self-critique does. It is
        disabled by default (`max_verify_rounds = 0`) because Claude Opus 5
        already verifies its own work, and stacking a second pass on top mostly
        buys latency. Turn it on when running a smaller model as the engine —
        that is where it earns its cost.
        """
        rounds = self.config.max_verify_rounds
        if rounds <= 0 or not answer:
            return None

        for _ in range(rounds):
            transcript = self._transcript_for_review(user_input, answer)
            try:
                verdict = self.engine.review(VERIFIER_PROMPT, transcript)
            except EngineError as exc:
                self.ui.on_warning(f"Review pass skipped: {exc}")
                return None

            if verdict.strip().upper().startswith("PASS") or not verdict.strip():
                return None

            self.ui.on_notice("review found gaps — continuing")
            # Framed explicitly as machine-generated. It rides in a user message
            # because the API requires a system message to follow a user turn,
            # and at this point the conversation ends with the assistant.
            self.messages.append(
                {
                    "role": "user",
                    "content": (
                        "[automatic review — generated by the harness, not the user]\n"
                        f"{verdict}\n\n"
                        "Close any gap that is real. If a point is mistaken, say so in one "
                        "line and do not change the work."
                    ),
                }
            )
            turn = self._model_turn()
            self.messages.append(
                {"role": "assistant", "content": self.engine.replayable(turn.message.content)}
            )
            if turn.tool_calls:
                self.messages.append({"role": "user", "content": self._run_tools(turn)})
                turn = self._model_turn()
                self.messages.append(
                    {"role": "assistant", "content": self.engine.replayable(turn.message.content)}
                )
            answer = turn.text or answer
        return answer

    def _transcript_for_review(self, user_input: str, answer: str) -> str:
        actions = [
            f"- {e['data']['name']}({json.dumps(e['data']['args'], ensure_ascii=False)[:200]})"
            f"{'  [FAILED]' if e['data']['error'] else ''}"
            for e in self.session.events
            if e["kind"] == "tool"
        ]
        return (
            f"# The user asked\n{user_input}\n\n"
            f"# Tools the agent ran\n{chr(10).join(actions) or '(none)'}\n\n"
            f"# What the agent replied\n{answer}\n"
        )

    # ── Refusals ──────────────────────────────────────────────────────────────

    @staticmethod
    def _refusal_text(turn: Turn) -> str:
        category = f" (category: {turn.refusal_category})" if turn.refusal_category else ""
        return (
            f"The request was declined by the model's safety classifiers{category}. "
            "Nothing was run. If this is legitimate work on your own systems, rephrasing "
            "around the concrete task — what to inspect and what decision it feeds — "
            "usually gets through."
        )

    # ── Session log ───────────────────────────────────────────────────────────

    def _record(self, kind: str, data: dict) -> None:
        self.session.events.append(
            {
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "kind": kind,
                "data": data,
            }
        )

    def save_session(self) -> Path | None:
        """Write the transcript to <home>/sessions. Never fatal."""
        if not self.session.events:
            return None
        self.config.sessions_dir.mkdir(parents=True, exist_ok=True)
        stamp = self.session.started_at.replace(":", "").replace("-", "")
        path = self.config.sessions_dir / f"session-{stamp}.json"
        try:
            path.write_text(
                json.dumps(
                    {
                        "started_at": self.session.started_at,
                        "model": self.session.model,
                        "workspace": self.session.workspace,
                        "events": self.session.events,
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            return path
        except OSError:
            return None

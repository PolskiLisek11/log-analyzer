"""The engine — the model, and everything about talking to it.

This is the layer the reel calls "an AI model": the part that turns a
conversation plus a set of tool declarations into the next message. It knows
nothing about what the tools do or why the loop is running; the harness owns
that. Keeping the split clean is what makes the model swappable.

Two optional beta features are enabled by default and degrade gracefully:

* **server-side fallback** — Opus 5 runs safety classifiers that can decline a
  request outright (a normal HTTP 200 with ``stop_reason == "refusal"``).
  Benign security work occasionally trips them, which for a log-analysis agent
  is not hypothetical. With fallbacks on, the API re-runs the declined request
  on a suitable other model inside the same call instead of returning nothing.
* **compaction** — a long agent session will eventually outgrow even a 1M-token
  window. Compaction summarises the older history server-side as it approaches
  the limit, so a session can keep going instead of dying at the ceiling.

If the API rejects either one, `_send` turns both off, warns, and retries once —
a beta that is unavailable should cost a warning, not the session.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import anthropic

# Blocks the API rejects when replayed after a mid-output fallback: they belong
# to the model that declined, not the one that answered.
_UNREPLAYABLE = {"thinking", "redacted_thinking"}


class EngineError(Exception):
    """A request failed in a way the harness cannot paper over."""


@dataclass
class Turn:
    """One assistant response, plus what the harness needs to decide next."""

    message: object                  # anthropic Message
    stop_reason: str
    text: str
    tool_calls: list                 # list of tool_use content blocks
    refused: bool = False
    refusal_category: str | None = None
    fell_back_to: str | None = None


class Engine:
    def __init__(self, config, api_key: str | None = None, on_warning: Callable[[str], None] = print):
        self.config = config
        self.on_warning = on_warning
        self._betas_enabled = config.server_side_fallback or config.compaction
        try:
            self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        except Exception as exc:  # noqa: BLE001 — surfaced as a clean startup error
            raise EngineError(f"could not create the Anthropic client: {exc}") from exc

    # ── Request construction ──────────────────────────────────────────────────

    def _betas(self) -> list[str]:
        betas: list[str] = []
        if self.config.server_side_fallback:
            betas.append("server-side-fallback-2026-07-01")
        if self.config.compaction:
            betas.append("compact-2026-01-12")
        return betas

    def _kwargs(self, system, messages, tools) -> dict:
        kwargs: dict = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": messages,
            "thinking": {
                "type": "adaptive",
                "display": "summarized" if self.config.show_thinking else "omitted",
            },
            "output_config": {"effort": self.config.effort},
        }
        if tools:
            kwargs["tools"] = tools

        if self._betas_enabled:
            betas = self._betas()
            if betas:
                kwargs["betas"] = betas
            if self.config.server_side_fallback:
                # "default" lets the API pick the substitute by refusal category
                # rather than pinning a model that will eventually be retired.
                kwargs["fallbacks"] = "default"
            if self.config.compaction:
                kwargs["context_management"] = {"edits": [{"type": "compact_20260112"}]}
        return kwargs

    # ── Sending ───────────────────────────────────────────────────────────────

    def send(
        self,
        *,
        system,
        messages: list,
        tools: list | None = None,
        on_text: Callable[[str], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
    ) -> Turn:
        """One model turn, streamed.

        Streaming is not optional here: `max_tokens` is large enough that a
        non-streaming request would risk an HTTP timeout on a long answer, and
        the user gets text as it arrives instead of after a two-minute pause.
        """
        message = self._send(
            self._kwargs(system, messages, tools), on_text=on_text, on_thinking=on_thinking
        )
        return self._to_turn(message)

    def _send(self, kwargs: dict, *, on_text, on_thinking):
        """Send, giving up one optional request feature per rejection.

        `--model` takes any model id, and models differ in what they accept:
        `effort: "max"` is rejected by Haiku 4.5, and thinking configuration is
        not universal either. Rather than carry a capability table that goes
        stale every release, the engine reads the rejection, drops the feature
        the API named, warns once, and retries. Anything it cannot attribute to
        an optional feature is a real error and is raised.
        """
        dropped: set[str] = set()

        while True:
            try:
                return self._stream_once(kwargs, on_text, on_thinking)
            except TypeError as exc:
                # The SDK raises a bare TypeError when it cannot resolve any
                # credential. It surfaces at request time rather than at client
                # construction, so it cannot be caught earlier — and it is the
                # very first thing a new user hits, so it gets a real message.
                if "authentication" not in str(exc).lower():
                    raise
                raise EngineError(
                    "No API credentials found. Either export ANTHROPIC_API_KEY, or run "
                    "`ant auth login` and leave it unset."
                ) from exc
            except anthropic.BadRequestError as exc:
                giving_up = self._next_degradation(exc, kwargs, dropped)
                if giving_up is None:
                    raise EngineError(self._explain(exc)) from exc

                name, keys, note = giving_up
                dropped.add(name)
                for key in keys:
                    kwargs.pop(key, None)
                if name == "betas":
                    self._betas_enabled = False
                self.on_warning(f"{note} Reason: {getattr(exc, 'message', exc)}")
            except anthropic.APIError as exc:
                raise EngineError(self._explain(exc)) from exc

    # Optional request features, and what to drop when the API rejects one.
    # Ordered most specific first: a message naming "effort" should cost the
    # effort setting, not the betas.
    _DEGRADATIONS: tuple[tuple[str, tuple[str, ...], tuple[str, ...], str], ...] = (
        (
            "output_config", ("effort",), ("output_config",),
            "This model rejected the effort setting — continuing without it.",
        ),
        (
            "thinking", ("thinking",), ("thinking",),
            "This model rejected the thinking configuration — continuing without it.",
        ),
        (
            "betas", (), ("betas", "fallbacks", "context_management"),
            "Optional API features (server-side fallback / compaction) were rejected — "
            "continuing without them.",
        ),
    )

    @classmethod
    def _next_degradation(cls, exc: Exception, kwargs: dict, dropped: set[str]):
        """Pick the feature to give up for this rejection, or None to raise."""
        message = str(getattr(exc, "message", "") or exc).lower()

        for name, keywords, keys, note in cls._DEGRADATIONS:
            if name in dropped or not any(key in kwargs for key in keys):
                continue
            # The betas entry has no keywords: rejection wording for an
            # unavailable beta varies, so it stays the last-resort attempt.
            if keywords and not any(word in message for word in keywords):
                continue
            return name, keys, note
        return None

    def _stream_once(self, kwargs: dict, on_text, on_thinking):
        resource = self.client.beta.messages if "betas" in kwargs else self.client.messages
        with resource.stream(**kwargs) as stream:
            for event in stream:
                if event.type != "content_block_delta":
                    continue
                delta = event.delta
                if delta.type == "text_delta" and on_text:
                    on_text(delta.text)
                elif delta.type == "thinking_delta" and on_thinking:
                    on_thinking(delta.thinking)
            return stream.get_final_message()

    # ── Response shaping ──────────────────────────────────────────────────────

    @staticmethod
    def _to_turn(message) -> Turn:
        text_parts, tool_calls, fell_back_to = [], [], None
        for block in message.content:
            kind = getattr(block, "type", None)
            if kind == "text":
                text_parts.append(block.text)
            elif kind == "tool_use":
                tool_calls.append(block)
            elif kind == "fallback":
                # Emitted at the point the API switched models mid-request.
                target = getattr(block, "to", None)
                fell_back_to = getattr(target, "model", None)

        stop_reason = getattr(message, "stop_reason", "") or ""
        details = getattr(message, "stop_details", None)
        return Turn(
            message=message,
            stop_reason=stop_reason,
            text="".join(text_parts).strip(),
            tool_calls=tool_calls,
            refused=stop_reason == "refusal",
            refusal_category=getattr(details, "category", None) if details else None,
            fell_back_to=fell_back_to,
        )

    @staticmethod
    def replayable(content: list) -> list:
        """Assistant content, filtered for sending back in the next request.

        Thinking blocks replay fine on the same model, but after a mid-output
        fallback the surviving message mixes blocks from two models and the
        API rejects the model-internal ones. Dropping them costs nothing —
        they are unbilled on replay either way.
        """
        if not any(getattr(b, "type", None) == "fallback" for b in content):
            return content
        return [b for b in content if getattr(b, "type", None) not in _UNREPLAYABLE]

    # ── Verifier ──────────────────────────────────────────────────────────────

    def review(self, system: str, transcript: str) -> str:
        """A short, non-streaming call on a separate model. Used by the verifier."""
        response = self.client.messages.create(
            model=self.config.verify_model,
            max_tokens=2000,
            system=system,
            messages=[{"role": "user", "content": transcript}],
            output_config={"effort": "medium"},
        )
        if getattr(response, "stop_reason", "") == "refusal":
            return "PASS"
        return "".join(
            b.text for b in response.content if getattr(b, "type", None) == "text"
        ).strip()

    # ── Errors ────────────────────────────────────────────────────────────────

    @staticmethod
    def _explain(exc: Exception) -> str:
        if isinstance(exc, anthropic.AuthenticationError):
            return (
                "Authentication failed. Set ANTHROPIC_API_KEY, or run `ant auth login` "
                "and leave it unset."
            )
        if isinstance(exc, anthropic.PermissionDeniedError):
            return "That API key does not have access to this model."
        if isinstance(exc, anthropic.NotFoundError):
            return f"Model not found: {getattr(exc, 'message', exc)}"
        if isinstance(exc, anthropic.RateLimitError):
            retry_after = "unknown"
            response = getattr(exc, "response", None)
            if response is not None:
                retry_after = response.headers.get("retry-after", "unknown")
            return f"Rate limited. Retry after {retry_after}s."
        if isinstance(exc, anthropic.APIConnectionError):
            return "Could not reach the API — check the network connection."
        if isinstance(exc, anthropic.APIStatusError):
            return f"API error {exc.status_code}: {getattr(exc, 'message', exc)}"
        return f"{type(exc).__name__}: {exc}"

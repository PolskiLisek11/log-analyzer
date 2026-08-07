"""The toolbox — what turns a model that talks into an agent that acts.

A tool is a JSON-schema declaration the model sees plus a Python function the
harness runs. `Toolbox` owns the registry and is the single place where a call
from the model becomes a side effect: approval, execution, error shaping and
output truncation all happen in `Toolbox.run`, so no individual tool has to
remember them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from ..config import Config
from ..memory import Memory


class ToolError(Exception):
    """A tool failed in a way the model should see and can react to.

    Raising this returns an error tool_result rather than crashing the loop —
    the model usually recovers by fixing its arguments or trying another route.
    """


class ApprovalFn(Protocol):
    def __call__(self, tool: str, args: dict, reason: str) -> bool: ...


@dataclass
class ToolContext:
    """Everything a tool handler is allowed to reach."""

    config: Config
    workspace: Path
    memory: Memory
    plan: "Plan"
    notify: Callable[[str], None] = lambda msg: None


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[ToolContext, dict], str]
    mutating: bool = False       # gated by approval_mode
    approval_hint: str = ""      # shown to the user when asking


@dataclass
class Plan:
    """The agent's visible task list.

    The model maintains it through the `plan` tool; the harness renders it. It
    exists so a long task has a shape the user can watch, and so the agent has
    somewhere to put intermediate structure other than the conversation.
    """

    steps: list[dict] = field(default_factory=list)

    def set(self, steps: list[dict]) -> None:
        cleaned: list[dict] = []
        for raw in steps:
            title = str(raw.get("title", "")).strip()
            if not title:
                continue
            status = str(raw.get("status", "todo")).strip().lower()
            if status not in ("todo", "doing", "done"):
                status = "todo"
            cleaned.append({"title": title, "status": status})
        self.steps = cleaned

    def render(self) -> str:
        if not self.steps:
            return "(no plan)"
        marks = {"todo": "[ ]", "doing": "[~]", "done": "[x]"}
        return "\n".join(f"  {marks[s['status']]} {s['title']}" for s in self.steps)

    @property
    def is_empty(self) -> bool:
        return not self.steps


class Toolbox:
    """Registry plus the one code path that executes a model-requested call."""

    def __init__(self, approve: ApprovalFn | None = None):
        self._tools: dict[str, ToolSpec] = {}
        self._approve = approve

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec

    def register_all(self, specs: list[ToolSpec]) -> None:
        for spec in specs:
            self.register(spec)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def definitions(self) -> list[dict]:
        """Tool declarations for the API, in a stable order.

        Sorted by name so the serialised tool block is byte-identical between
        requests — the tools section renders first in the prompt, so any
        reordering would invalidate the whole prompt cache.
        """
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.input_schema,
            }
            for spec in sorted(self._tools.values(), key=lambda s: s.name)
        ]

    def run(self, ctx: ToolContext, name: str, args: dict) -> tuple[str, bool]:
        """Execute one call. Returns (result_text, is_error).

        Never raises: an exception here would kill the agent loop mid-task, and
        the model can almost always do something useful with the error text.
        """
        spec = self._tools.get(name)
        if spec is None:
            return (
                f"Unknown tool {name!r}. Available: {', '.join(self.names())}",
                True,
            )

        if spec.mutating:
            mode = ctx.config.approval_mode
            if mode == "readonly":
                return (
                    f"Denied: {name} changes state and Jarvis is running in read-only mode.",
                    True,
                )
            if mode == "ask" and self._approve is not None:
                if not self._approve(name, args, spec.approval_hint):
                    return ("Denied by the user. Ask what they would prefer instead.", True)

        try:
            result = spec.handler(ctx, args or {})
        except ToolError as exc:
            return (str(exc), True)
        except Exception as exc:  # noqa: BLE001 — a tool bug must not end the session
            return (f"{type(exc).__name__}: {exc}", True)

        return (_truncate(result, ctx.config.max_output_chars), False)


def _truncate(text: str, limit: int) -> str:
    text = text if isinstance(text, str) else str(text)
    if len(text) <= limit:
        return text
    head = text[: limit - 2000]
    tail = text[-1500:]
    dropped = len(text) - len(head) - len(tail)
    return (
        f"{head}\n\n… [{dropped} characters truncated — narrow the request "
        f"(a filter, a line range, a more specific path) to see the rest] …\n\n{tail}"
    )

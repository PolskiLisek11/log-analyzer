"""Memory tools — how the agent reads and writes its own long-term notes.

The descriptions here are prescriptive about *when* to call each tool, not just
what it does. Recent Claude models reach for memory conservatively unless the
trigger condition is spelled out, and memory that is never written is the same
as no memory at all.
"""

from __future__ import annotations

from ..memory import MemoryError_
from . import ToolContext, ToolError, ToolSpec


def _wrap(fn):
    """Translate MemoryError_ into the harness's ToolError."""

    def inner(ctx: ToolContext, args: dict) -> str:
        try:
            return fn(ctx, args)
        except MemoryError_ as exc:
            raise ToolError(str(exc)) from exc

    return inner


@_wrap
def memory_write(ctx: ToolContext, args: dict) -> str:
    path = ctx.memory.write(str(args.get("path", "")), str(args.get("content", "")))
    ctx.notify(f"memory ← {path}")
    return f"Saved to memory as {path}."


@_wrap
def memory_read(ctx: ToolContext, args: dict) -> str:
    return ctx.memory.read(str(args.get("path", "")))


@_wrap
def memory_search(ctx: ToolContext, args: dict) -> str:
    hits = ctx.memory.search(str(args.get("query", "")))
    if not hits:
        return "No memory notes match that query."
    return "\n".join(f"{path}: {line}" for path, line in hits)


@_wrap
def memory_list(ctx: ToolContext, args: dict) -> str:
    notes = ctx.memory.index()
    if not notes:
        return "Memory is empty."
    return "\n".join(f"{n.path}  ({n.size} B, {n.modified})\n    {n.summary}" for n in notes)


@_wrap
def memory_delete(ctx: ToolContext, args: dict) -> str:
    path = ctx.memory.delete(str(args.get("path", "")))
    ctx.notify(f"memory ✕ {path}")
    return f"Deleted {path}."


def build() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="memory_write",
            description=(
                "Save a note to long-term memory so it is available in future sessions. "
                "Write one whenever you learn something that will still matter next time: a "
                "stated preference, a fact about the user's projects or environment, a "
                "correction they made, or an approach that turned out to work. One idea per "
                "note. The content must open with '# ' and a one-line summary, because that "
                "line is what you will see in the memory index next session. Update an "
                "existing note instead of creating a near-duplicate. Never record credentials, "
                "API keys or tokens."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative note path, e.g. 'preferences/tone.md' or 'projects/log-analyzer.md'.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Markdown. First line '# <one-line summary>', then the detail and why it matters.",
                    },
                },
                "required": ["path", "content"],
            },
            handler=memory_write,
            mutating=True,
            approval_hint="writes a note to long-term memory",
        ),
        ToolSpec(
            name="memory_read",
            description=(
                "Read one memory note in full. The system prompt lists only summaries — call "
                "this when a summary looks relevant to the task at hand."
            ),
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Note path from the memory index."}},
                "required": ["path"],
            },
            handler=memory_read,
        ),
        ToolSpec(
            name="memory_search",
            description=(
                "Search memory note contents for a phrase. Use it when you suspect something "
                "was recorded but no summary in the index makes it obvious which note."
            ),
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Text to look for, case-insensitive."}},
                "required": ["query"],
            },
            handler=memory_search,
        ),
        ToolSpec(
            name="memory_list",
            description="List every memory note with its summary, size and last-modified time.",
            input_schema={"type": "object", "properties": {}, "required": []},
            handler=memory_list,
        ),
        ToolSpec(
            name="memory_delete",
            description=(
                "Delete a memory note. Use it when a note turns out to be wrong or has been "
                "superseded — stale memory is worse than none, because it is recalled with "
                "the same confidence as accurate memory."
            ),
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Note path to delete."}},
                "required": ["path"],
            },
            handler=memory_delete,
            mutating=True,
            approval_hint="deletes a note from long-term memory",
        ),
    ]

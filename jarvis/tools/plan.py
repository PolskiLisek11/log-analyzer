"""The plan tool — the agent's task list, made visible.

A plan the model keeps only in its own reasoning is invisible: on a task that
runs for two minutes and twenty tool calls, the user sees a cursor and has no
idea whether anything is going right. Writing the plan through a tool puts it on
screen and gives the model a stable place to track what is left, rather than
re-deriving it from the conversation on every turn.
"""

from __future__ import annotations

from . import ToolContext, ToolError, ToolSpec


def plan(ctx: ToolContext, args: dict) -> str:
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ToolError("steps must be a non-empty list of {title, status} objects")
    if len(steps) > 25:
        raise ToolError("keep the plan under 25 steps — group the small ones together")

    ctx.plan.set(steps)
    if ctx.plan.is_empty:
        raise ToolError("every step needs a non-empty title")

    ctx.notify("plan\n" + ctx.plan.render())
    done = sum(1 for s in ctx.plan.steps if s["status"] == "done")
    return f"Plan updated: {done}/{len(ctx.plan.steps)} steps done."


def build() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="plan",
            description=(
                "Record or update the task list for the current request, and show it to the "
                "user. Call it once at the start of any task needing several steps or tools, "
                "then again as steps complete — always passing the whole list, since it "
                "replaces the previous one. Exactly one step should be 'doing' at a time. "
                "Skip it for single-step requests, where it is pure overhead."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "steps": {
                        "type": "array",
                        "description": "The complete plan, in order.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "description": "Short imperative description, e.g. 'Scan auth.log for brute force'.",
                                },
                                "status": {
                                    "type": "string",
                                    "enum": ["todo", "doing", "done"],
                                    "description": "Progress for this step.",
                                },
                            },
                            "required": ["title", "status"],
                        },
                    },
                },
                "required": ["steps"],
            },
            handler=plan,
        ),
    ]

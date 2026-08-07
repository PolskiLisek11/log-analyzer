"""The shell tool.

Three properties make this safe enough to hand to a model:

1. **No shell.** The command is split with `shlex` and handed to `subprocess`
   with ``shell=False``. Nothing interprets ``;``, ``|``, ``$(…)`` or ``>`` —
   they arrive as ordinary argv strings, so command injection has nowhere to
   land. The cost is that pipes and redirects genuinely do not work.
2. **Allowlist.** Only the executables in ``Config.shell_allow`` may run, matched
   on basename so ``/bin/rm`` cannot slip past as ``rm``. Interpreters are not
   on the default list: allowing one is allowing arbitrary code.
3. **Confinement and a clock.** Commands run with the workspace as the working
   directory and are killed after ``Config.shell_timeout`` seconds.

A blocklist would be the wrong shape here — it fails open on everything nobody
thought of. This one fails closed.
"""

from __future__ import annotations

import shlex
import subprocess

from . import ToolContext, ToolError, ToolSpec

# Operators that only appear as standalone tokens when they were unquoted, i.e.
# when the model expected a shell to interpret them. Detected to give a clear
# message rather than silently passing "|" to grep as a search argument.
SHELL_OPERATORS = {"|", "||", "&", "&&", ";", ">", ">>", "<", "<<", "2>", "&>"}

# Sub-commands allowed for tools that are themselves a suite of commands. Git
# is on the default allowlist because reading history is genuinely useful; the
# half of git that rewrites or publishes history is not.
SUBCOMMAND_ALLOW: dict[str, set[str]] = {
    "git": {
        "status", "log", "diff", "show", "branch", "ls-files", "rev-parse",
        "blame", "remote", "describe", "shortlog", "config",
    },
}


def run_shell(ctx: ToolContext, args: dict) -> str:
    raw = str(args.get("command", "")).strip()
    if not raw:
        raise ToolError("command is required")

    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        raise ToolError(f"could not parse command (unbalanced quotes?): {exc}") from exc
    if not argv:
        raise ToolError("command is empty after parsing")

    operators = [token for token in argv if token in SHELL_OPERATORS]
    if operators:
        raise ToolError(
            f"shell operators ({', '.join(sorted(set(operators)))}) are not supported — "
            "commands run without a shell, so there is nothing to interpret them. "
            "Run one command per call, or use grep_files / read_file instead of a pipeline."
        )

    program = argv[0].rsplit("/", 1)[-1]
    allowed = ctx.config.shell_allow
    if program not in allowed:
        raise ToolError(
            f"{program!r} is not on the allowlist. Permitted: {', '.join(sorted(allowed))}. "
            "Use the file tools for anything involving file contents."
        )

    permitted_subs = SUBCOMMAND_ALLOW.get(program)
    if permitted_subs is not None:
        sub = next((a for a in argv[1:] if not a.startswith("-")), None)
        if sub is None or sub not in permitted_subs:
            raise ToolError(
                f"only read-only {program} sub-commands are allowed: "
                f"{', '.join(sorted(permitted_subs))}"
            )

    timeout = ctx.config.shell_timeout
    try:
        proc = subprocess.run(  # noqa: S603 — shell=False with an allowlisted argv[0]
            argv,
            cwd=str(ctx.workspace),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        raise ToolError(f"{program!r} is allowlisted but not installed on this machine") from None
    except subprocess.TimeoutExpired:
        raise ToolError(f"command exceeded the {timeout}s timeout and was killed") from None

    parts = [f"$ {raw}", f"exit code: {proc.returncode}"]
    if proc.stdout.strip():
        parts.append(f"--- stdout ---\n{proc.stdout.rstrip()}")
    if proc.stderr.strip():
        parts.append(f"--- stderr ---\n{proc.stderr.rstrip()}")
    if not proc.stdout.strip() and not proc.stderr.strip():
        parts.append("(no output)")
    return "\n".join(parts)


def build() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="run_shell",
            description=(
                "Run one allowlisted command in the workspace and return its exit code, "
                "stdout and stderr. There is no shell: pipes, redirects and $(…) are not "
                "interpreted, and only read-mostly inspection tools are permitted. "
                "For reading, searching or editing files, the dedicated file tools are "
                "faster and are not subject to the allowlist."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "A single command with its arguments, e.g. 'wc -l access.log'.",
                    },
                },
                "required": ["command"],
            },
            handler=run_shell,
            mutating=True,
            approval_hint="runs a command on this machine",
        ),
    ]

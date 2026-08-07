"""The interface — a terminal REPL, and a one-shot mode for scripts.

Everything the user sees is decided here, and nothing else in the package prints.
The harness reports through callbacks (`UI`), so the same agent drives an
interactive session, a piped command, or some future front end without any of
them knowing about the others.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import APPROVAL_MODES, Config
from .engine import Engine, EngineError
from .harness import UI, Harness
from .memory import Memory
from .tools import Toolbox
from .tools import files as files_tools
from .tools import memory_tools, plan as plan_tools, security, shell
from .voice import make_voice

BANNER = "jarvis  ·  personal agent"


class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"

    @classmethod
    def disable(cls) -> None:
        for name in ("RESET", "DIM", "BOLD", "CYAN", "GREEN", "YELLOW", "RED", "BLUE"):
            setattr(cls, name, "")


HELP = f"""\
{C.BOLD}Commands{C.RESET}
  /help              this message
  /memory            list long-term memory notes
  /plan              show the current plan
  /tools             list available tools
  /workspace         show the workspace path
  /save              write the session transcript to disk
  /clear             forget this conversation (memory notes are kept)
  /exit              quit

Anything else is sent to the agent.
"""


# ── Rendering ─────────────────────────────────────────────────────────────────

class Renderer:
    """Terminal output, and the only place that tracks cursor state."""

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._mid_line = False

    def stream_text(self, chunk: str) -> None:
        if not self._mid_line:
            sys.stdout.write(f"\n{C.BOLD}jarvis{C.RESET}  ")
            self._mid_line = True
        sys.stdout.write(chunk)
        sys.stdout.flush()

    def stream_thinking(self, chunk: str) -> None:
        if self.quiet:
            return
        sys.stdout.write(f"{C.DIM}{chunk}{C.RESET}")
        sys.stdout.flush()

    def end_stream(self) -> None:
        if self._mid_line:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._mid_line = False

    def tool(self, name: str, args: dict) -> None:
        self.end_stream()
        if self.quiet:
            return
        detail = ", ".join(
            f"{k}={_short(v)}" for k, v in list(args.items())[:3] if v not in (None, "")
        )
        print(f"  {C.CYAN}▸ {name}{C.RESET}{C.DIM}({detail}){C.RESET}")

    def tool_result(self, name: str, output: str, is_error: bool) -> None:
        if self.quiet:
            return
        if is_error:
            print(f"    {C.RED}✕ {output.splitlines()[0][:160]}{C.RESET}")
        else:
            lines = output.count("\n") + 1
            print(f"    {C.DIM}✓ {lines} line(s){C.RESET}")

    def notice(self, message: str) -> None:
        self.end_stream()
        if self.quiet:
            return
        head, _, rest = message.partition("\n")
        print(f"  {C.BLUE}{head}{C.RESET}")
        if rest:
            print(f"{C.DIM}{rest}{C.RESET}")

    def warning(self, message: str) -> None:
        self.end_stream()
        print(f"  {C.YELLOW}! {message}{C.RESET}")

    def error(self, message: str) -> None:
        self.end_stream()
        print(f"  {C.RED}✕ {message}{C.RESET}")


def _short(value, limit: int = 60) -> str:
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    text = text.replace("\n", "⏎")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ── Approval ──────────────────────────────────────────────────────────────────

def make_approver(renderer: Renderer, interactive: bool):
    def approve(tool: str, args: dict, reason: str) -> bool:
        renderer.end_stream()
        if not interactive:
            renderer.warning(f"{tool} needs approval but there is no terminal to ask — denied.")
            return False

        detail = ", ".join(f"{k}={_short(v, 100)}" for k, v in args.items())
        print(f"\n  {C.YELLOW}approve{C.RESET} {C.BOLD}{tool}{C.RESET} — {reason}")
        print(f"    {C.DIM}{detail}{C.RESET}")
        try:
            answer = input(f"  {C.YELLOW}[y/N]{C.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        return answer in ("y", "yes")

    return approve


# ── Assembly ──────────────────────────────────────────────────────────────────

def build_toolbox(config: Config, approve) -> Toolbox:
    toolbox = Toolbox(approve=approve)
    toolbox.register_all(plan_tools.build())
    toolbox.register_all(files_tools.build())
    toolbox.register_all(memory_tools.build())
    toolbox.register_all(shell.build())
    toolbox.register_all(security.build())
    return toolbox


def build_agent(config: Config, renderer: Renderer, interactive: bool) -> Harness:
    config.ensure_home()
    memory = Memory(config.memory_dir)
    toolbox = build_toolbox(config, make_approver(renderer, interactive))
    engine = Engine(config, on_warning=renderer.warning)
    ui = UI(
        on_text=renderer.stream_text,
        on_thinking=renderer.stream_thinking,
        on_tool=renderer.tool,
        on_tool_result=renderer.tool_result,
        on_notice=renderer.notice,
        on_warning=renderer.warning,
    )
    return Harness(config, engine, toolbox, memory, ui)


# ── Argument parsing ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jarvis",
        description="A personal agent: a Claude model, a tool loop, and memory that persists.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  jarvis                                    interactive session
  jarvis -p "scan examples/ and summarise"  one-shot, prints and exits
  jarvis --workspace /var/log --approve readonly
  jarvis --voice system --thinking
""",
    )
    parser.add_argument("-p", "--prompt", help="run a single request and exit")
    parser.add_argument("-w", "--workspace", help="directory the file tools may touch")
    parser.add_argument("--home", help="agent home directory (default: ~/.jarvis)")
    parser.add_argument("--model", help="model id (default: claude-opus-5)")
    parser.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        help="how hard the model works per turn (default: xhigh)",
    )
    parser.add_argument(
        "--approve", choices=list(APPROVAL_MODES), dest="approval_mode",
        help="ask before state changes (default), auto-approve, or refuse them",
    )
    parser.add_argument("--voice", choices=["off", "system"], help="speak the final answer")
    parser.add_argument("--thinking", action="store_true", default=None,
                        help="stream the model's reasoning summary")
    parser.add_argument("--max-steps", type=int, dest="max_steps",
                        help="tool iterations allowed per request (default: 40)")
    parser.add_argument("--verify", type=int, dest="max_verify_rounds",
                        help="fresh-context review passes after each answer (default: 0)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--quiet", action="store_true", help="answers only, no tool trace")
    return parser


def config_from_args(args: argparse.Namespace) -> Config:
    return Config.load(
        home=Path(args.home).expanduser() if args.home else None,
        workspace=Path(args.workspace).expanduser().resolve() if args.workspace else None,
        model=args.model,
        effort=args.effort,
        approval_mode=args.approval_mode,
        voice=args.voice,
        show_thinking=args.thinking,
        max_steps=args.max_steps,
        max_verify_rounds=args.max_verify_rounds,
    )


# ── REPL ──────────────────────────────────────────────────────────────────────

def handle_command(command: str, agent: Harness, renderer: Renderer) -> bool:
    """Handle a /command. Returns False when the session should end."""
    cmd = command.strip().lower()

    if cmd in ("/exit", "/quit", "/q"):
        return False

    if cmd == "/help":
        print(HELP)
    elif cmd == "/memory":
        notes = agent.memory.index()
        if not notes:
            print(f"  {C.DIM}memory is empty{C.RESET}")
        for note in notes:
            print(f"  {C.BOLD}{note.path}{C.RESET}\n    {C.DIM}{note.summary}{C.RESET}")
    elif cmd == "/plan":
        print(agent.plan.render())
    elif cmd == "/tools":
        for name in agent.toolbox.names():
            print(f"  {name}")
        for server in agent.config.mcp_servers:
            # Named, not listed: their tools are resolved by the API at request
            # time, so this process never sees the individual names.
            print(f"  {C.DIM}+ tools from MCP server {server['name']}{C.RESET}")
    elif cmd == "/workspace":
        print(f"  {agent.config.workspace}")
    elif cmd == "/save":
        path = agent.save_session()
        print(f"  {C.DIM}{path or 'nothing to save'}{C.RESET}")
    elif cmd == "/clear":
        agent.messages.clear()
        agent.plan.set([])
        print(f"  {C.DIM}conversation cleared (memory kept){C.RESET}")
    else:
        renderer.warning(f"unknown command {command!r} — try /help")
    return True


def repl(agent: Harness, renderer: Renderer, voice) -> int:
    print(f"\n{C.BOLD}{BANNER}{C.RESET}")
    print(f"{C.DIM}model {agent.config.model} · effort {agent.config.effort} · "
          f"approve {agent.config.approval_mode} · {len(agent.toolbox)} tools{C.RESET}")
    print(f"{C.DIM}workspace {agent.config.workspace}{C.RESET}")
    if agent.config.mcp_servers:
        names = ", ".join(s["name"] for s in agent.config.mcp_servers)
        print(f"{C.DIM}mcp {names}{C.RESET}")
    print(f"{C.DIM}/help for commands, /exit to quit{C.RESET}")

    while True:
        try:
            line = input(f"\n{C.GREEN}you{C.RESET}  ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        if line.startswith("/"):
            if not handle_command(line, agent, renderer):
                break
            continue

        try:
            result = agent.run_turn(line)
        except EngineError as exc:
            renderer.error(str(exc))
            continue
        except KeyboardInterrupt:
            renderer.end_stream()
            renderer.warning("interrupted")
            continue

        renderer.end_stream()
        if result.tool_calls and not renderer.quiet:
            print(f"{C.DIM}  ({result.steps} steps, {result.tool_calls} tool calls){C.RESET}")
        if voice.enabled and result.text:
            voice.speak(result.text)

    path = agent.save_session()
    if path:
        print(f"{C.DIM}session saved to {path}{C.RESET}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        C.disable()

    interactive = sys.stdin.isatty() and not args.prompt
    config = config_from_args(args)

    # Asking for approval requires somebody to ask. Without a terminal the safe
    # reading of "ask" is "do not change anything", not "assume yes".
    if config.approval_mode == "ask" and not sys.stdin.isatty():
        config.approval_mode = "readonly"

    renderer = Renderer(quiet=args.quiet)

    try:
        agent = build_agent(config, renderer, interactive)
    except EngineError as exc:
        renderer.error(str(exc))
        return 1

    voice = make_voice(config.voice)
    if config.voice == "system" and not voice.enabled:
        renderer.warning("no system speech binary found (say / espeak-ng / spd-say) — voice off")

    if args.prompt:
        try:
            result = agent.run_turn(args.prompt)
        except EngineError as exc:
            renderer.error(str(exc))
            return 1
        renderer.end_stream()
        if voice.enabled and result.text:
            voice.speak(result.text)
        agent.save_session()
        return 2 if result.refused or result.stopped_early else 0

    return repl(agent, renderer, voice)

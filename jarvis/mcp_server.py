"""Jarvis as an MCP server — the log analyzer, plugged into any agent.

`python -m jarvis` is one agent. This exposes the same tools over the Model
Context Protocol, so the analyzer becomes available to Claude Desktop, Claude
Code, Hermes Agent, a LiveKit voice agent, or anything else that speaks MCP.

The point is that it makes the choice of agent reversible. The detection logic
lives in `analyzer.py`, the declarations live in `jarvis/tools/`, and both this
server and the in-process agent read from the same registry — so there is one
source of truth for what a tool is called and what it accepts, and no drift
between the two surfaces.

    python -m jarvis.mcp_server --workspace /var/log

Claude Desktop config (`claude_desktop_config.json`):

    {
      "mcpServers": {
        "log-analyzer": {
          "command": "python",
          "args": ["-m", "jarvis.mcp_server", "--workspace", "/var/log"],
          "cwd": "/path/to/log-analyzer"
        }
      }
    }

**Read-only by default.** An MCP server hands its tools to whatever connects,
and there is no human in this process to approve anything — the connecting
client owns that conversation. So the default tool set is the analyzer plus
read-only file access. `--allow-writes` adds the mutating tools and makes the
client solely responsible for gating them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import anyio
    import mcp.types as types
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
except ImportError as exc:  # pragma: no cover — exercised by hand, not in CI
    raise SystemExit(
        "The MCP server needs the 'mcp' package, which the agent itself does not:\n"
        "    pip install mcp\n"
        f"(import failed: {exc})"
    ) from exc

from . import __version__
from .config import Config
from .memory import Memory
from .tools import Plan, ToolContext, Toolbox
from .tools import files as files_tools
from .tools import security, shell

# Exposed by default: the domain tools this repository exists for, plus enough
# read-only file access for a client to find the logs in the first place.
READ_ONLY_TOOLS = ("scan_logs", "scan_logs_json", "read_file", "list_dir", "glob_files", "grep_files")

INSTRUCTIONS = """\
Security log analysis for SSH (auth.log/syslog) and web server (Apache/Nginx) logs.

Use scan_logs when asked what is happening in a log, whether a host is under
attack, or to review security events — it detects brute force, directory
scanning, scanner user agents, path traversal and off-hours access, and returns
findings with severity and a recommended action. Prefer it over reading raw log
files line by line. Use scan_logs_json when you need to sort or correlate
findings rather than report them.
"""


def build_toolbox(allow_writes: bool) -> Toolbox:
    """The tool set this server exposes, drawn from the agent's own registry."""
    toolbox = Toolbox()
    toolbox.register_all(security.build())
    toolbox.register_all(files_tools.build())
    if allow_writes:
        toolbox.register_all(shell.build())

    if allow_writes:
        return toolbox

    # Rebuild with only the read-only subset rather than filtering at call time:
    # a tool the client can see but never run is a worse experience than one
    # that was never advertised.
    filtered = Toolbox()
    for name in READ_ONLY_TOOLS:
        spec = toolbox.get(name)
        if spec is not None:
            filtered.register(spec)
    return filtered


def build_server(config: Config, toolbox: Toolbox) -> Server:
    context = ToolContext(
        config=config,
        workspace=config.workspace,
        memory=Memory(config.memory_dir),
        plan=Plan(),
    )

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=definition["name"],
                    description=definition["description"],
                    input_schema=definition["input_schema"],
                )
                for definition in toolbox.definitions()
            ]
        )

    async def on_call_tool(ctx, params) -> types.CallToolResult:
        # Toolbox.run is synchronous and does real I/O — reading files, walking
        # directories, parsing a log that may be large. Running it inline would
        # block the event loop and stall the connection for the duration.
        output, is_error = await anyio.to_thread.run_sync(
            toolbox.run, context, params.name, params.arguments or {}
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=output or "(no output)")],
            is_error=is_error,
        )

    return Server(
        name="log-analyzer",
        version=__version__,
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


async def serve(server: Server) -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jarvis.mcp_server",
        description="Expose the log analyzer to any MCP client over stdio.",
    )
    parser.add_argument(
        "-w", "--workspace", default=".",
        help="directory the tools may read; paths outside it are refused (default: .)",
    )
    parser.add_argument(
        "--allow-writes", action="store_true",
        help="also expose editing and shell tools — the connecting client becomes "
             "solely responsible for approving them",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"workspace is not a directory: {workspace}", file=sys.stderr)
        return 1

    config = Config(
        workspace=workspace,
        # With writes enabled the gate moves to the client: there is no terminal
        # here to prompt on, so "ask" would deadlock and "readonly" would refuse
        # the very tools the flag was passed to enable.
        approval_mode="auto" if args.allow_writes else "readonly",
    )
    config.ensure_home()

    toolbox = build_toolbox(args.allow_writes)
    # stdout is the MCP transport — anything printed there corrupts the protocol.
    print(
        f"log-analyzer MCP server · workspace {workspace} · {len(toolbox)} tools"
        f"{' · writes enabled' if args.allow_writes else ''}",
        file=sys.stderr,
    )

    try:
        anyio.run(serve, build_server(config, toolbox))
    except (KeyboardInterrupt, BrokenPipeError):
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Configuration and the agent's home directory.

The "home" is a single directory that holds everything the agent owns across
runs: its memory, its workspace, its session transcripts and its config file.
Nothing about the agent is stored outside it, so backing up or wiping the agent
is a matter of copying or deleting one folder.

Layout::

    ~/.jarvis/
    ├── config.json      # persisted settings (optional — defaults work)
    ├── memory/          # markdown notes the agent writes to itself
    ├── workspace/       # the only directory file tools may touch
    └── sessions/        # one JSON transcript per conversation
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

# Executables the shell tool may run by default. Deliberately read-mostly:
# nothing here can install packages, open a network connection or execute an
# arbitrary script. Interpreters (python3, node, perl…) are excluded on purpose
# because allowing one is equivalent to allowing arbitrary code — add them via
# `shell_allow_extra` only when the agent runs inside a container.
DEFAULT_SHELL_ALLOW: tuple[str, ...] = (
    "ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "stat", "file",
    "du", "sort", "uniq", "cut", "tr", "diff", "basename", "dirname", "echo",
    "pwd", "date", "git", "tree", "md5sum", "sha256sum",
)

# Approval policies for tools that change state (write_file, edit_file,
# run_shell, memory_delete).
APPROVAL_MODES = ("ask", "auto", "readonly")


_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _default_home() -> Path:
    return Path(os.environ.get("JARVIS_HOME") or (Path.home() / ".jarvis"))


def _expand_env(value, field: str):
    """Substitute ${VAR} references in a config string.

    Config files get committed by accident and copied into backups, so an API
    token belongs in the environment and only its name belongs here. An
    undefined variable is an error rather than a silent pass-through: sending
    the literal "${GMAIL_TOKEN}" as a bearer token fails far from its cause.
    """
    if not isinstance(value, str):
        return value

    def replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        resolved = os.environ.get(name)
        if resolved is None:
            raise ValueError(
                f"config field {field!r} references ${{{name}}}, which is not set "
                "in the environment"
            )
        return resolved

    return _ENV_REF.sub(replace, value)


@dataclass
class Config:
    """Everything tunable about a Jarvis run."""

    # ── Engine ────────────────────────────────────────────────────────────────
    model: str = "claude-opus-5"
    effort: str = "xhigh"            # low | medium | high | xhigh | max
    max_tokens: int = 32000
    show_thinking: bool = False

    # Optional beta features. Both degrade gracefully: if the API rejects them
    # the engine retries once with them off (see engine.Engine._send).
    server_side_fallback: bool = True   # retry policy refusals on another model
    compaction: bool = True             # summarise history server-side when long

    # ── Harness ───────────────────────────────────────────────────────────────
    max_steps: int = 40              # tool-calling iterations per user turn
    max_verify_rounds: int = 0       # 0 = off; see docs/JARVIS.md ("Verify")
    verify_model: str = "claude-sonnet-5"

    # ── Home / workspace ──────────────────────────────────────────────────────
    home: Path = field(default_factory=_default_home)
    workspace: Path | None = None    # defaults to <home>/workspace

    # ── Tools ─────────────────────────────────────────────────────────────────
    approval_mode: str = "ask"       # ask | auto | readonly

    # Remote MCP servers, connected by the API rather than by this process:
    # [{"name": "gmail", "url": "https://…/sse", "authorization_token": "…"}].
    # Each one contributes its tools without a line of integration code here.
    mcp_servers: tuple[dict, ...] = ()

    shell_allow_extra: tuple[str, ...] = ()
    shell_timeout: int = 30
    max_output_chars: int = 30_000   # per tool result, before truncation

    # ── Interface ─────────────────────────────────────────────────────────────
    voice: str = "off"               # off | system

    def __post_init__(self) -> None:
        self.home = Path(self.home).expanduser()
        self.workspace = (
            Path(self.workspace).expanduser() if self.workspace else self.home / "workspace"
        )
        if self.approval_mode not in APPROVAL_MODES:
            raise ValueError(
                f"approval_mode must be one of {APPROVAL_MODES}, got {self.approval_mode!r}"
            )

        # Validated here rather than at request time: a typo in config.json
        # should fail on startup with the offending entry, not as an opaque 400
        # in the middle of a task.
        servers = []
        for entry in self.mcp_servers or ():
            if not isinstance(entry, dict) or not entry.get("name") or not entry.get("url"):
                raise ValueError(
                    f"each mcp_servers entry needs 'name' and 'url', got {entry!r}"
                )
            servers.append({k: _expand_env(v, k) for k, v in entry.items()})
        names = [s["name"] for s in servers]
        if len(names) != len(set(names)):
            raise ValueError(f"mcp_servers names must be unique, got {names}")
        self.mcp_servers = tuple(servers)

    # ── Derived paths ─────────────────────────────────────────────────────────

    @property
    def memory_dir(self) -> Path:
        return self.home / "memory"

    @property
    def sessions_dir(self) -> Path:
        return self.home / "sessions"

    @property
    def config_file(self) -> Path:
        return self.home / "config.json"

    @property
    def shell_allow(self) -> tuple[str, ...]:
        return tuple(DEFAULT_SHELL_ALLOW) + tuple(self.shell_allow_extra)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def ensure_home(self) -> None:
        """Create the home directory tree. Safe to call repeatedly."""
        for path in (self.home, self.memory_dir, self.sessions_dir, self.workspace):
            path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def load(cls, home: Path | None = None, **overrides) -> "Config":
        """Read <home>/config.json if present, then apply keyword overrides.

        Unknown keys in the file are ignored rather than fatal, so a config
        written by a newer version still boots.
        """
        base = cls(home=home) if home else cls()
        data: dict = {}
        if base.config_file.is_file():
            try:
                data = json.loads(base.config_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}

        known = set(cls.__dataclass_fields__)
        merged = {k: v for k, v in data.items() if k in known}
        merged.update({k: v for k, v in overrides.items() if k in known and v is not None})
        merged.pop("home", None)

        if "shell_allow_extra" in merged:
            merged["shell_allow_extra"] = tuple(merged["shell_allow_extra"])

        return replace(base, **merged)

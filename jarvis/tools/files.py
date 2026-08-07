"""File tools, confined to the workspace.

Every path in this module arrives as model output, so none of it is passed to
`open()` directly. `_safe_path` resolves each one — following symlinks — and
rejects anything that lands outside the workspace root, which is the only
boundary standing between a bad path argument and the rest of the filesystem.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from . import ToolContext, ToolError, ToolSpec

MAX_READ_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache"}


def _safe_path(ctx: ToolContext, raw: str, *, must_exist: bool = False) -> Path:
    if not raw or not str(raw).strip():
        raise ToolError("path must not be empty")

    root = ctx.workspace.resolve()
    candidate = Path(str(raw).strip()).expanduser()
    target = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

    if target != root and root not in target.parents:
        raise ToolError(
            f"path {raw!r} resolves outside the workspace ({root}). "
            "File tools may only touch the workspace."
        )
    if must_exist and not target.exists():
        raise ToolError(f"no such file or directory: {raw}")
    return target


def _rel(ctx: ToolContext, path: Path) -> str:
    try:
        return path.resolve().relative_to(ctx.workspace.resolve()).as_posix() or "."
    except ValueError:
        return str(path)


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


# ── Handlers ──────────────────────────────────────────────────────────────────

def read_file(ctx: ToolContext, args: dict) -> str:
    path = _safe_path(ctx, args.get("path", ""), must_exist=True)
    if path.is_dir():
        raise ToolError(f"{_rel(ctx, path)} is a directory — use list_dir")
    if path.stat().st_size > MAX_READ_BYTES:
        raise ToolError(
            f"{_rel(ctx, path)} is larger than {MAX_READ_BYTES // 1024} KB — "
            "read it with start_line/max_lines, or grep it instead"
        )

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(args.get("start_line", 1) or 1))
    limit = int(args.get("max_lines", 800) or 800)
    window = lines[start - 1 : start - 1 + limit]

    if not window:
        return f"{_rel(ctx, path)} has {len(lines)} lines; nothing at line {start}."

    body = "\n".join(f"{start + i:>6}  {line}" for i, line in enumerate(window))
    shown_to = start + len(window) - 1
    footer = ""
    if shown_to < len(lines):
        footer = f"\n\n[showing {start}-{shown_to} of {len(lines)} lines]"
    return body + footer


def write_file(ctx: ToolContext, args: dict) -> str:
    path = _safe_path(ctx, args.get("path", ""))
    content = args.get("content")
    if content is None:
        raise ToolError("content is required")
    if path.is_dir():
        raise ToolError(f"{_rel(ctx, path)} is a directory")

    existed = path.is_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(content), encoding="utf-8")
    verb = "Overwrote" if existed else "Created"
    return f"{verb} {_rel(ctx, path)} ({len(str(content))} characters)."


def edit_file(ctx: ToolContext, args: dict) -> str:
    path = _safe_path(ctx, args.get("path", ""), must_exist=True)
    old = args.get("old_text")
    new = args.get("new_text")
    if not old:
        raise ToolError("old_text is required and must not be empty")
    if new is None:
        raise ToolError("new_text is required (use an empty string to delete)")

    text = path.read_text(encoding="utf-8", errors="replace")
    hits = text.count(old)
    if hits == 0:
        raise ToolError(
            f"old_text does not appear in {_rel(ctx, path)}. "
            "Read the file first and copy the exact text, including indentation."
        )
    if hits > 1:
        raise ToolError(
            f"old_text appears {hits} times in {_rel(ctx, path)}. "
            "Include enough surrounding context to make it unique."
        )

    path.write_text(text.replace(old, str(new), 1), encoding="utf-8")
    return f"Edited {_rel(ctx, path)}."


def list_dir(ctx: ToolContext, args: dict) -> str:
    path = _safe_path(ctx, args.get("path", ".") or ".", must_exist=True)
    if not path.is_dir():
        raise ToolError(f"{_rel(ctx, path)} is not a directory")

    entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    if not entries:
        return f"{_rel(ctx, path)} is empty."

    rows = []
    for entry in entries[:400]:
        if entry.is_dir():
            rows.append(f"  {entry.name}/")
        else:
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            rows.append(f"  {entry.name}  ({size} B)")
    header = f"{_rel(ctx, path)}  —  {len(entries)} entries"
    return header + "\n" + "\n".join(rows)


def glob_files(ctx: ToolContext, args: dict) -> str:
    pattern = str(args.get("pattern", "")).strip()
    if not pattern:
        raise ToolError("pattern is required, e.g. '**/*.py'")

    root = _safe_path(ctx, args.get("path", ".") or ".", must_exist=True)
    matches = [
        _rel(ctx, p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
        and not any(part in SKIP_DIRS for part in p.parts)
        and fnmatch.fnmatch(p.name, pattern.rsplit("/", 1)[-1])
        and fnmatch.fnmatch(_rel(ctx, p), pattern.lstrip("./"))
    ]
    if not matches:
        # Fall back to matching the basename only — '*.py' is the common shape
        # and users rarely mean it to be anchored at the root.
        matches = [
            _rel(ctx, p)
            for p in sorted(root.rglob("*"))
            if p.is_file()
            and not any(part in SKIP_DIRS for part in p.parts)
            and fnmatch.fnmatch(p.name, pattern.rsplit("/", 1)[-1])
        ]
    if not matches:
        return f"No files match {pattern!r} under {_rel(ctx, root)}."
    return "\n".join(matches[:300])


def grep_files(ctx: ToolContext, args: dict) -> str:
    pattern = str(args.get("pattern", "")).strip()
    if not pattern:
        raise ToolError("pattern is required")
    try:
        regex = re.compile(pattern, re.IGNORECASE if args.get("ignore_case") else 0)
    except re.error as exc:
        raise ToolError(f"invalid regular expression: {exc}") from exc

    root = _safe_path(ctx, args.get("path", ".") or ".", must_exist=True)
    glob = str(args.get("glob", "") or "").strip()
    limit = int(args.get("max_results", 100) or 100)

    files = [root] if root.is_file() else list(_iter_files(root))
    hits: list[str] = []
    for file in sorted(files):
        if glob and not fnmatch.fnmatch(file.name, glob):
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                hits.append(f"{_rel(ctx, file)}:{lineno}: {line.strip()[:300]}")
                if len(hits) >= limit:
                    return "\n".join(hits) + f"\n\n[stopped at {limit} matches]"
    return "\n".join(hits) if hits else f"No matches for {pattern!r}."


# ── Declarations ──────────────────────────────────────────────────────────────

def build() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="read_file",
            description=(
                "Read a text file from the workspace, with line numbers. Call this before "
                "editing anything so edit_file can be given exact text. Large files should "
                "be read in windows via start_line/max_lines, or searched with grep_files."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the workspace root."},
                    "start_line": {"type": "integer", "description": "First line to show (1-based). Default 1."},
                    "max_lines": {"type": "integer", "description": "How many lines to show. Default 800."},
                },
                "required": ["path"],
            },
            handler=read_file,
        ),
        ToolSpec(
            name="write_file",
            description=(
                "Create a file or replace its entire contents. Parent directories are created "
                "automatically. For a change to part of an existing file, prefer edit_file — "
                "this overwrites everything."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the workspace root."},
                    "content": {"type": "string", "description": "The full new contents of the file."},
                },
                "required": ["path", "content"],
            },
            handler=write_file,
            mutating=True,
            approval_hint="writes a file in the workspace",
        ),
        ToolSpec(
            name="edit_file",
            description=(
                "Replace one exact snippet in a file. old_text must appear exactly once — "
                "include surrounding lines to make it unique. Fails without changing anything "
                "if the snippet is missing or ambiguous."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the workspace root."},
                    "old_text": {"type": "string", "description": "Exact text to replace, including indentation."},
                    "new_text": {"type": "string", "description": "Replacement text. Empty string deletes."},
                },
                "required": ["path", "old_text", "new_text"],
            },
            handler=edit_file,
            mutating=True,
            approval_hint="modifies an existing file",
        ),
        ToolSpec(
            name="list_dir",
            description="List the entries of a workspace directory with file sizes.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory relative to the workspace root. Default '.'."},
                },
                "required": [],
            },
            handler=list_dir,
        ),
        ToolSpec(
            name="glob_files",
            description=(
                "Find files by name pattern, e.g. '*.log' or '**/*.py'. Use this to locate "
                "files when the exact path is unknown; use grep_files to search their contents."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern, e.g. '*.log'."},
                    "path": {"type": "string", "description": "Directory to search under. Default '.'."},
                },
                "required": ["pattern"],
            },
            handler=glob_files,
        ),
        ToolSpec(
            name="grep_files",
            description=(
                "Search file contents with a regular expression and return matching lines as "
                "path:line: text. Faster and far cheaper than reading whole files when looking "
                "for where something is defined or mentioned."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Python regular expression."},
                    "path": {"type": "string", "description": "File or directory to search. Default '.'."},
                    "glob": {"type": "string", "description": "Only search files whose name matches this glob."},
                    "ignore_case": {"type": "boolean", "description": "Case-insensitive match."},
                    "max_results": {"type": "integer", "description": "Cap on matches returned. Default 100."},
                },
                "required": ["pattern"],
            },
            handler=grep_files,
        ),
    ]

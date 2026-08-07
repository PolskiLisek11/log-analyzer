"""Persistent memory — the part that survives when the process exits.

Memory is a directory of small markdown notes. Each note's first line is a
one-line summary; the rest is the body. That split is what makes memory cheap:
the system prompt carries only the summaries (an index), and the agent spends
tokens on a full note only when it decides to read one.

    memory/
    ├── projects/log-analyzer.md
    │       # Repo the user maintains: a stdlib-only SSH/web log threat scanner.
    │       Entry point is analyzer.py …
    └── preferences/tone.md
            # User wants short answers, Polish, no emoji.
            …

One idea per file. A note that has to describe two unrelated things is two
notes — the index stays readable and a single recall pulls in less noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAX_NOTE_BYTES = 64 * 1024
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


class MemoryError_(Exception):
    """Raised for invalid paths or oversized notes."""


@dataclass(frozen=True)
class Note:
    path: str          # relative to the memory root, e.g. "projects/repo.md"
    summary: str       # first line, stripped of leading '#'
    size: int
    modified: str      # ISO-8601 UTC


class Memory:
    """A directory of markdown notes, addressed by relative path."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ── Path handling ─────────────────────────────────────────────────────────

    def _resolve(self, rel: str) -> Path:
        """Map a caller-supplied relative path to a file inside the root.

        The path comes from model output, so it is validated segment by segment
        rather than trusted: no absolute paths, no '..', no separators beyond
        '/', and no characters outside a conservative allowlist.
        """
        rel = (rel or "").strip().replace("\\", "/")
        if not rel:
            raise MemoryError_("memory path must not be empty")
        # Rejected rather than silently reinterpreted: quietly turning
        # "/etc/passwd" into a note inside the root would still be confined, but
        # it would hide the mistake instead of correcting it.
        if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
            raise MemoryError_(
                f"{rel!r} is an absolute path — memory paths are relative to the memory root"
            )
        if not rel.endswith(".md"):
            rel += ".md"

        segments = [s for s in rel.split("/") if s]
        for segment in segments:
            if segment in (".", "..") or not _SAFE_SEGMENT.match(segment):
                raise MemoryError_(
                    f"invalid path segment {segment!r} — use letters, digits, '.', '_', '-'"
                )

        target = (self.root / "/".join(segments)).resolve()
        root = self.root.resolve()
        if target != root and root not in target.parents:
            raise MemoryError_("memory path escapes the memory root")
        return target

    # ── Reads ─────────────────────────────────────────────────────────────────

    def index(self) -> list[Note]:
        """Every note, newest first, with its one-line summary."""
        notes: list[Note] = []
        for path in sorted(self.root.rglob("*.md")):
            if not path.is_file():
                continue
            try:
                first = path.read_text(encoding="utf-8", errors="replace").lstrip().split("\n", 1)[0]
                stat = path.stat()
            except OSError:
                continue
            notes.append(
                Note(
                    path=path.relative_to(self.root).as_posix(),
                    summary=first.lstrip("# ").strip() or "(no summary)",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                    .isoformat(timespec="seconds"),
                )
            )
        notes.sort(key=lambda n: n.modified, reverse=True)
        return notes

    def digest(self, limit: int = 60) -> str:
        """The index rendered for the system prompt.

        Built once per session and held constant for its lifetime, so it sits
        inside the cached prompt prefix instead of invalidating it every turn.
        """
        notes = self.index()
        if not notes:
            return "(memory is empty — nothing has been recorded yet)"

        lines = [f"- {n.path} — {n.summary}" for n in notes[:limit]]
        if len(notes) > limit:
            lines.append(f"- … and {len(notes) - limit} more (use memory_list)")
        return "\n".join(lines)

    def read(self, rel: str) -> str:
        path = self._resolve(rel)
        if not path.is_file():
            raise MemoryError_(f"no note at {rel!r} — use memory_list to see what exists")
        return path.read_text(encoding="utf-8", errors="replace")

    def search(self, query: str, limit: int = 20) -> list[tuple[str, str]]:
        """Case-insensitive substring search. Returns (path, matching line)."""
        needle = (query or "").strip().lower()
        if not needle:
            return []

        hits: list[tuple[str, str]] = []
        for path in sorted(self.root.rglob("*.md")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(self.root).as_posix()
            for line in text.splitlines():
                if needle in line.lower():
                    hits.append((rel, line.strip()))
                    if len(hits) >= limit:
                        return hits
        return hits

    # ── Writes ────────────────────────────────────────────────────────────────

    def write(self, rel: str, content: str) -> str:
        """Create or replace a note. Returns the relative path written."""
        data = (content or "").strip()
        if not data:
            raise MemoryError_("refusing to write an empty note")
        if len(data.encode("utf-8")) > MAX_NOTE_BYTES:
            raise MemoryError_(
                f"note exceeds {MAX_NOTE_BYTES} bytes — split it into several notes"
            )
        if not data.lstrip().startswith("#"):
            raise MemoryError_(
                "a note must open with '# <one-line summary>' so it shows up usefully in the index"
            )

        path = self._resolve(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + "\n", encoding="utf-8")
        return path.relative_to(self.root).as_posix()

    def delete(self, rel: str) -> str:
        path = self._resolve(rel)
        if not path.is_file():
            raise MemoryError_(f"no note at {rel!r}")
        relative = path.relative_to(self.root).as_posix()
        path.unlink()
        return relative

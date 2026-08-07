"""The domain tool: this repository's log analyzer, exposed to the agent.

`analyzer.py` already knows how to turn SSH and web logs into a list of threats.
Wrapping it as a tool is what lets the agent reason *about* the findings —
correlate an IP across files, check it against what it wrote to memory last
week, draft the firewall rule — instead of the user reading the report and doing
that themselves.

The analyzer is imported, not shelled out to, so results arrive as `Threat`
objects rather than as text that would have to be parsed back out of a terminal
rendering.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from . import ToolContext, ToolError, ToolSpec
from .files import _rel, _safe_path

REPO_ROOT = Path(__file__).resolve().parents[2]
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _load_analyzer():
    """Import analyzer.py from the repository root.

    Deferred to call time so importing the jarvis package never depends on the
    analyzer being present — the agent is useful without it, just with one tool
    fewer.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        import analyzer  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ToolError(
            f"could not import analyzer.py from {REPO_ROOT}: {exc}"
        ) from exc
    return analyzer


def scan_logs(ctx: ToolContext, args: dict) -> str:
    analyzer = _load_analyzer()

    target = _safe_path(ctx, args.get("path", ".") or ".", must_exist=True)
    threshold = int(args.get("threshold", 10) or 10)
    if threshold < 1:
        raise ToolError("threshold must be at least 1")

    min_severity = str(args.get("min_severity", "LOW") or "LOW").upper()
    if min_severity not in SEVERITY_ORDER:
        raise ToolError(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")

    if target.is_dir():
        files = sorted(p for p in target.glob("*.log") if p.is_file())
        if not files:
            return f"No .log files found in {_rel(ctx, target)}."
    else:
        files = [target]

    # analyzer prints warnings for unrecognised formats; keep them out of the
    # tool result so the model sees findings rather than terminal chrome.
    analyzer.disable_colors()
    engine = analyzer.LogAnalyzer(threshold=threshold)
    for file in files:
        engine.analyze_file(file)

    threats = [
        t for t in engine.threats
        if SEVERITY_ORDER.get(t.severity, 0) >= SEVERITY_ORDER[min_severity]
    ]
    threats.sort(key=lambda t: (-SEVERITY_ORDER.get(t.severity, 0), t.source_ip))

    scanned = ", ".join(_rel(ctx, f) for f in files)
    if not threats:
        return (
            f"Scanned {len(files)} file(s): {scanned}\n"
            f"threshold={threshold}, min_severity={min_severity}\n\n"
            "No threats detected."
        )

    counts = Counter(t.severity for t in threats)
    summary = ", ".join(
        f"{sev}={counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[sev]
    )

    blocks = [
        f"Scanned {len(files)} file(s): {scanned}",
        f"threshold={threshold}, min_severity={min_severity}",
        f"{len(threats)} threat(s) — {summary}",
        "",
    ]
    for threat in threats[: int(args.get("max_threats", 40) or 40)]:
        detail = "; ".join(threat.details) if threat.details else "—"
        blocks.append(
            f"[{threat.severity}] {threat.threat_type}\n"
            f"  source_ip:   {threat.source_ip}\n"
            f"  count:       {threat.count} events\n"
            f"  window:      {threat.first_seen} → {threat.last_seen}\n"
            f"  file:        {threat.source_file}\n"
            f"  details:     {detail}\n"
            f"  recommended: {threat.recommendation}"
        )

    if len(threats) > 40:
        blocks.append(f"… {len(threats) - 40} further threats omitted; raise min_severity to narrow.")

    return "\n\n".join(blocks)


def scan_logs_json(ctx: ToolContext, args: dict) -> str:
    """Same scan, returned as JSON — for when the agent wants to compute on it."""
    import json

    analyzer = _load_analyzer()
    target = _safe_path(ctx, args.get("path", ".") or ".", must_exist=True)
    threshold = int(args.get("threshold", 10) or 10)

    files = (
        sorted(p for p in target.glob("*.log") if p.is_file())
        if target.is_dir()
        else [target]
    )
    if not files:
        raise ToolError(f"no .log files found in {_rel(ctx, target)}")

    analyzer.disable_colors()
    engine = analyzer.LogAnalyzer(threshold=threshold)
    for file in files:
        engine.analyze_file(file)

    payload = {
        "files_scanned": [_rel(ctx, f) for f in files],
        "threshold": threshold,
        "total_threats": len(engine.threats),
        "summary": dict(Counter(t.severity for t in engine.threats)),
        "threats": [asdict(t) for t in engine.threats],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="scan_logs",
            description=(
                "Run this repository's threat detection over a log file or a directory of "
                ".log files and return the findings as readable text. Detects SSH brute force, "
                "web directory scanning, scanner user agents, path traversal and off-hours "
                "access; the log format is auto-detected. Call this whenever the user asks "
                "what is happening in a log, whether a host is under attack, or to review "
                "security events — do not try to read raw logs line by line instead."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Log file, or a directory scanned for *.log. Relative to the workspace.",
                    },
                    "threshold": {
                        "type": "integer",
                        "description": "Events from one IP before it is reported. Default 10; lower it for quiet hosts.",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Drop findings below this severity. Default LOW.",
                    },
                },
                "required": ["path"],
            },
            handler=scan_logs,
        ),
        ToolSpec(
            name="scan_logs_json",
            description=(
                "The same scan as scan_logs, returned as JSON. Use it when you need to sort, "
                "count or cross-reference findings — for example correlating one source IP "
                "across several files — rather than just report them."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Log file or directory, relative to the workspace."},
                    "threshold": {"type": "integer", "description": "Events from one IP before it is reported. Default 10."},
                },
                "required": ["path"],
            },
            handler=scan_logs_json,
        ),
    ]

#!/usr/bin/env python3
"""
log-analyzer — Security Log Analyzer
=====================================
A SOC-grade command-line tool for detecting threats in common log formats.

Detects:
  - SSH brute-force attacks
  - Web directory/path scanning
  - Suspicious user agents (scanners, exploit frameworks)
  - Off-hours access (01:00–05:00 local time)
  - Repeated authentication failures
  - Path traversal attempts

Supports: auth.log / syslog (SSH), Apache / Nginx access logs (Combined Log Format)

Usage:
  python analyzer.py --file examples/ssh_bruteforce.log
  python analyzer.py --batch examples/ --output report.json
  python analyzer.py --file access.log --threshold 5 --no-color
"""

import argparse
import io
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Force UTF-8 on Windows terminals ─────────────────────────────────────────

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ── ANSI colour codes ─────────────────────────────────────────────────────────

class C:
    RED      = "\033[91m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    MAGENTA  = "\033[95m"
    WHITE    = "\033[97m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RESET    = "\033[0m"

def disable_colors() -> None:
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")

SEVERITY_COLOR = {
    "LOW":      C.GREEN,
    "MEDIUM":   C.YELLOW,
    "HIGH":     C.YELLOW,
    "CRITICAL": C.RED,
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Threat:
    threat_type:    str
    severity:       str          # LOW | MEDIUM | HIGH | CRITICAL
    source_ip:      str
    count:          int
    first_seen:     str
    last_seen:      str
    details:        list[str] = field(default_factory=list)
    recommendation: str = ""
    source_file:    str = ""

    def severity_score(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(self.severity, 0)


# ── Known malicious / scanner user agents ─────────────────────────────────────

MALICIOUS_UA_PATTERNS: list[tuple[str, str]] = [
    (r"sqlmap",                "SQLMap — automated SQL injection scanner"),
    (r"nikto",                 "Nikto — web vulnerability scanner"),
    (r"nmap",                  "Nmap — port/service scanner"),
    (r"masscan",               "Masscan — mass port scanner"),
    (r"zgrab",                 "ZGrab — banner-grabbing scanner"),
    (r"gobuster",              "Gobuster — directory/DNS brute-forcer"),
    (r"dirbuster",             "DirBuster — directory brute-forcer"),
    (r"wfuzz",                 "WFuzz — web fuzzer"),
    (r"hydra",                 "Hydra — login brute-forcer"),
    (r"metasploit",            "Metasploit Framework — exploit framework"),
    (r"python-requests",       "python-requests — often used in recon scripts"),
    (r"curl/",                 "curl — scripted/automated request"),
    (r"wget/",                 "wget — scripted/automated request"),
    (r"go-http-client",        "Go HTTP client — automated tool"),
    (r"java/",                 "Java HTTP client — automated tool"),
    (r"scrapy",                "Scrapy — web scraper"),
    (r"zgrab2",                "ZGrab2 — internet-wide scanner"),
    (r"masscan-ng",            "Masscan-NG — mass scanner"),
    (r"nuclei",                "Nuclei — vulnerability scanner"),
    (r"whatweb",               "WhatWeb — web fingerprinter"),
]

# Paths that indicate active exploitation / enumeration attempts
SENSITIVE_PATHS: list[str] = [
    r"\.env", r"\.git/", r"\.htaccess", r"\.htpasswd",
    r"wp-admin", r"wp-login\.php", r"xmlrpc\.php",
    r"phpmyadmin", r"pma/",
    r"etc/passwd", r"etc/shadow",
    r"\.\.\/", r"%2e%2e",          # path traversal
    r"shell\.php", r"c99\.php", r"r57\.php", r"b374k",
    r"config\.php", r"db\.php", r"database\.php",
    r"backup\.(zip|tar|gz|sql)",
    r"web\.config", r"app\.config",
    r"/cgi-bin/",
]

SENSITIVE_RE = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATHS]


# ── Log format parsers ────────────────────────────────────────────────────────

# auth.log / syslog — SSH entries
# Example: Apr 28 01:03:12 srv sshd[1201]: Failed password for root from 185.220.101.42 port 54321 ssh2
SSH_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<event>Failed password|Accepted password|Accepted publickey|Invalid user)\s+"
    r"(?:for\s+(?P<user>\S+)\s+)?from\s+(?P<ip>[\d.]+)"
)

# Apache / Nginx Combined Log Format
# Example: 192.168.1.1 - - [28/Apr/2026:09:00:01 +0000] "GET /path HTTP/1.1" 200 1234 "-" "UA"
APACHE_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+|-)\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)

# Datetime formats for parsing
SSH_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5,  "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10,"Nov": 11, "Dec": 12,
}


def parse_ssh_datetime(month: str, day: str, time_str: str) -> Optional[datetime]:
    try:
        now = datetime.now()
        return datetime(now.year, SSH_MONTHS[month], int(day),
                        *map(int, time_str.split(":")))
    except (KeyError, ValueError):
        return None


def parse_apache_datetime(dt_str: str) -> Optional[datetime]:
    # "28/Apr/2026:09:00:01 +0000"
    try:
        return datetime.strptime(dt_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def detect_format(lines: list[str]) -> str:
    """
    Sniff the first non-empty lines to determine log format.
    Returns 'ssh', 'apache', or 'unknown'.
    """
    sample = [l for l in lines[:20] if l.strip()]
    for line in sample:
        if SSH_RE.match(line):
            return "ssh"
        if APACHE_RE.match(line):
            return "apache"
    return "unknown"


# ── Analysis engine ───────────────────────────────────────────────────────────

class LogAnalyzer:
    """
    Core analysis engine. Parses log entries and applies detection rules.

    Detection rules:
      SSH  → brute_force, off_hours_ssh
      Web  → dir_scan, suspicious_ua, path_traversal, off_hours_web
    """

    def __init__(self, threshold: int = 10):
        self.threshold = threshold      # min events before alerting
        self.threats:  list[Threat] = []

    # ── SSH analysis ──────────────────────────────────────────────────────────

    def analyze_ssh(self, lines: list[str], source_file: str) -> None:
        """Parse auth.log / syslog and run SSH detection rules."""

        # ip -> list of (datetime, event, user)
        failures:    defaultdict[str, list] = defaultdict(list)
        off_hours:   defaultdict[str, list] = defaultdict(list)

        for line in lines:
            m = SSH_RE.match(line.strip())
            if not m:
                continue

            ip    = m.group("ip")
            event = m.group("event")
            user  = m.group("user") or "unknown"
            dt    = parse_ssh_datetime(m.group("month"), m.group("day"), m.group("time"))

            if dt is None:
                continue

            if event in ("Failed password", "Invalid user"):
                failures[ip].append((dt, user))

            # Off-hours: any SSH activity between 01:00–05:00
            if 1 <= dt.hour < 5:
                off_hours[ip].append((dt, event, user))

        # Rule 1 — SSH brute force
        for ip, events in failures.items():
            if len(events) >= self.threshold:
                times    = sorted(e[0] for e in events)
                users    = list({e[1] for e in events})
                severity = "CRITICAL" if len(events) >= 20 else "HIGH" if len(events) >= 10 else "MEDIUM"
                self.threats.append(Threat(
                    threat_type    = "SSH Brute Force",
                    severity       = severity,
                    source_ip      = ip,
                    count          = len(events),
                    first_seen     = times[0].strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen      = times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                    details        = [f"Targeted users: {', '.join(users[:8])}{'...' if len(users)>8 else ''}"],
                    recommendation = "Block IP with firewall (iptables/ufw). Enable fail2ban. Disable password auth — use SSH keys only.",
                    source_file    = source_file,
                ))

        # Rule 2 — Off-hours SSH access (any source, any event)
        for ip, events in off_hours.items():
            if len(events) >= 3:
                times = sorted(e[0] for e in events)
                self.threats.append(Threat(
                    threat_type    = "Off-Hours SSH Access",
                    severity       = "MEDIUM",
                    source_ip      = ip,
                    count          = len(events),
                    first_seen     = times[0].strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen      = times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                    details        = [f"Activity detected between 01:00-05:00 ({len(events)} events)"],
                    recommendation = "Investigate whether access was authorized. Consider time-based access controls.",
                    source_file    = source_file,
                ))

    # ── Web / Apache analysis ─────────────────────────────────────────────────

    def analyze_apache(self, lines: list[str], source_file: str) -> None:
        """Parse Apache/Nginx Combined Log Format and run web detection rules."""

        # ip -> list of (datetime, status, path, ua)
        ip_requests:  defaultdict[str, list] = defaultdict(list)
        ua_hits:      defaultdict[str, list] = defaultdict(list)   # ua_label -> [(dt, ip, path)]
        traversal:    defaultdict[str, list] = defaultdict(list)
        off_hours_web: defaultdict[str, list] = defaultdict(list)

        for line in lines:
            m = APACHE_RE.match(line.strip())
            if not m:
                continue

            ip     = m.group("ip")
            dt     = parse_apache_datetime(m.group("datetime"))
            method = m.group("method")
            path   = m.group("path")
            status = int(m.group("status"))
            ua     = m.group("ua")

            if dt is None:
                continue

            ip_requests[ip].append((dt, status, path, ua))

            # Off-hours web (01:00–05:00)
            if 1 <= dt.hour < 5:
                off_hours_web[ip].append((dt, path))

            # Suspicious UA detection
            for pattern, label in MALICIOUS_UA_PATTERNS:
                if re.search(pattern, ua, re.IGNORECASE):
                    ua_hits[label].append((dt, ip, path))
                    break

            # Path traversal / sensitive file access
            for srx in SENSITIVE_RE:
                if srx.search(path):
                    traversal[ip].append((dt, path))
                    break

        # Rule 3 — Directory / path scanning (high 404 rate from single IP)
        for ip, reqs in ip_requests.items():
            total     = len(reqs)
            not_found = [r for r in reqs if r[1] == 404]
            if total < self.threshold:
                continue
            ratio = len(not_found) / total
            if ratio >= 0.5:
                times    = sorted(r[0] for r in reqs)
                paths    = [r[2] for r in not_found[:5]]
                severity = "CRITICAL" if len(not_found) >= 30 else "HIGH" if len(not_found) >= 15 else "MEDIUM"
                self.threats.append(Threat(
                    threat_type    = "Web Directory Scanning",
                    severity       = severity,
                    source_ip      = ip,
                    count          = len(not_found),
                    first_seen     = times[0].strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen      = times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                    details        = [
                        f"{len(not_found)}/{total} requests returned 404 ({ratio*100:.0f}%)",
                        f"Sample paths: {', '.join(paths)}",
                    ],
                    recommendation = "Block IP. Review WAF rules. Enable rate limiting. Consider CrowdSec or ModSecurity.",
                    source_file    = source_file,
                ))

        # Rule 4 — Suspicious / malicious user agents
        for label, hits in ua_hits.items():
            times    = sorted(h[0] for h in hits)
            ips      = list({h[1] for h in hits})
            severity = "HIGH" if any(kw in label.lower() for kw in ("sqlmap","metasploit","nikto","nuclei")) else "MEDIUM"
            # Group by IP for separate alerts
            by_ip: defaultdict[str, list] = defaultdict(list)
            for dt, ip, path in hits:
                by_ip[ip].append((dt, path))
            for ip, ip_hits in by_ip.items():
                ip_times = sorted(h[0] for h in ip_hits)
                self.threats.append(Threat(
                    threat_type    = "Suspicious User Agent",
                    severity       = severity,
                    source_ip      = ip,
                    count          = len(ip_hits),
                    first_seen     = ip_times[0].strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen      = ip_times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                    details        = [f"Tool identified: {label}"],
                    recommendation = "Block IP immediately. Check server for signs of compromise. Review WAF logs.",
                    source_file    = source_file,
                ))

        # Rule 5 — Path traversal / sensitive file probing
        for ip, hits in traversal.items():
            if len(hits) < 3:
                continue
            times = sorted(h[0] for h in hits)
            paths = list({h[1] for h in hits})[:5]
            self.threats.append(Threat(
                threat_type    = "Path Traversal / Sensitive File Probe",
                severity       = "HIGH",
                source_ip      = ip,
                count          = len(hits),
                first_seen     = times[0].strftime("%Y-%m-%d %H:%M:%S"),
                last_seen      = times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                details        = [f"Targeted paths: {', '.join(paths)}"],
                recommendation = "Block IP. Audit web root for exposed sensitive files. Harden .htaccess / server config.",
                source_file    = source_file,
            ))

        # Rule 6 — Off-hours web access
        for ip, hits in off_hours_web.items():
            if len(hits) < 5:
                continue
            times = sorted(h[0] for h in hits)
            self.threats.append(Threat(
                threat_type    = "Off-Hours Web Activity",
                severity       = "LOW",
                source_ip      = ip,
                count          = len(hits),
                first_seen     = times[0].strftime("%Y-%m-%d %H:%M:%S"),
                last_seen      = times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                details        = [f"{len(hits)} requests between 01:00-05:00"],
                recommendation = "Review requests for reconnaissance patterns. Correlate with other alerts.",
                source_file    = source_file,
            ))

    # ── Entry point ───────────────────────────────────────────────────────────

    def analyze_file(self, path: Path) -> None:
        """Auto-detect log format and run appropriate analysis."""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            print(f"{C.RED}Error reading {path}: {exc}{C.RESET}", file=sys.stderr)
            return

        fmt = detect_format(lines)
        if fmt == "ssh":
            self.analyze_ssh(lines, str(path))
        elif fmt == "apache":
            self.analyze_apache(lines, str(path))
        else:
            print(f"{C.YELLOW}[WARN] Could not detect log format in {path.name} — skipping{C.RESET}",
                  file=sys.stderr)


# ── Terminal output ───────────────────────────────────────────────────────────

def _wrap(text: str, width: int = 58, indent: str = "         ") -> str:
    words, line, lines = text.split(), "", []
    for w in words:
        candidate = f"{line} {w}".strip()
        if len(candidate) > width:
            if line:
                lines.append(line)
            line = w
        else:
            line = candidate
    if line:
        lines.append(line)
    return ("\n" + indent).join(lines)


def print_threat(t: Threat) -> None:
    scol = SEVERITY_COLOR.get(t.severity, C.WHITE)
    div  = f"{C.BOLD}{C.CYAN}{'─' * 64}{C.RESET}"

    print(f"\n{div}")
    print(f"{C.BOLD}  {t.threat_type.upper()}{C.RESET}")
    print(f"{C.DIM}  Source: {t.source_file}{C.RESET}")
    print(div)
    print(f"  {C.BOLD}SEVERITY  {C.RESET}{scol}{C.BOLD}{t.severity}{C.RESET}")
    print(f"  {C.BOLD}SOURCE IP {C.RESET}{C.WHITE}{t.source_ip}{C.RESET}")
    print(f"  {C.BOLD}COUNT     {C.RESET}{t.count} events")
    print(f"  {C.BOLD}FIRST     {C.RESET}{t.first_seen}")
    print(f"  {C.BOLD}LAST      {C.RESET}{t.last_seen}")

    if t.details:
        print(f"\n  {C.BOLD}DETAILS{C.RESET}")
        for d in t.details:
            print(f"    {C.DIM}>{C.RESET} {_wrap(d)}")

    print(f"\n  {C.BOLD}RECOMMENDATION{C.RESET}")
    print(f"    {C.CYAN}{_wrap(t.recommendation)}{C.RESET}")
    print(f"{div}")


def print_summary(threats: list[Threat], files_scanned: int) -> None:
    counts = {s: sum(1 for t in threats if t.severity == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    total  = sum(counts.values())

    div = f"{C.BOLD}{C.CYAN}{'=' * 64}{C.RESET}"
    print(f"\n{div}")
    print(f"{C.BOLD}  SCAN SUMMARY{C.RESET}")
    print(div)
    print(f"  Files scanned : {files_scanned}")
    print(f"  Threats found : {total}")
    print()

    if total == 0:
        print(f"  {C.GREEN}{C.BOLD}  No threats detected — logs look clean.{C.RESET}")
    else:
        col = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.YELLOW, "LOW": C.GREEN}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = counts[sev]
            bar = col[sev] + ("█" * n).ljust(20) + C.RESET
            print(f"  {col[sev]}{C.BOLD}{sev:<10}{C.RESET}  {bar}  {n}")

    print()

    if threats:
        # Top offenders table
        ip_count: defaultdict[str, int] = defaultdict(int)
        for t in threats:
            ip_count[t.source_ip] += t.severity_score()
        top = sorted(ip_count.items(), key=lambda x: -x[1])[:5]

        print(f"  {C.BOLD}TOP OFFENDERS{C.RESET}")
        print(f"  {'IP Address':<20} {'Threat Score':>12}")
        print(f"  {'-'*20} {'-'*12}")
        for ip, score in top:
            print(f"  {C.RED}{ip:<20}{C.RESET} {score:>12}")

    print(div)


# ── JSON report ───────────────────────────────────────────────────────────────

def save_report(threats: list[Threat], out: Path, files: list[str]) -> None:
    counts = {s: sum(1 for t in threats if t.severity == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    report = {
        "generated_at":  datetime.now().isoformat(),
        "files_scanned": files,
        "summary":       counts,
        "total_threats": len(threats),
        "threats":       [asdict(t) for t in threats],
    }
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n{C.CYAN}Report saved -> {out}{C.RESET}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Security Log Analyzer — detect threats in auth and web logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
log formats supported (auto-detected):
  ssh     auth.log / syslog  (SSH brute force, off-hours access)
  apache  Apache / Nginx access log in Combined Log Format

examples:
  python analyzer.py --file examples/ssh_bruteforce.log
  python analyzer.py --file examples/web_scanning.log --threshold 5
  python analyzer.py --batch examples/ --output report.json
  python analyzer.py --batch /var/log/ --no-color | tee scan.log
        """,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",  "-f", type=Path, metavar="FILE",
                     help="analyze a single log file")
    src.add_argument("--batch", "-b", type=Path, metavar="DIR",
                     help="analyze all .log files in a directory")

    parser.add_argument("--output",    "-o", type=Path, metavar="JSON",
                        help="write JSON report to file")
    parser.add_argument("--threshold", "-t", type=int, default=10, metavar="N",
                        help="minimum event count to trigger an alert (default: 10)")
    parser.add_argument("--no-color",  action="store_true",
                        help="disable ANSI color output")
    parser.add_argument("--min-severity", choices=["LOW","MEDIUM","HIGH","CRITICAL"],
                        default="LOW", metavar="LEVEL",
                        help="only show threats at or above this severity (default: LOW)")
    return parser


def severity_gte(threat_sev: str, min_sev: str) -> bool:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(threat_sev, 0) >= order.get(min_sev, 0)


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    analyzer     = LogAnalyzer(threshold=args.threshold)
    files_scanned: list[str] = []

    print(f"\n{C.BOLD}{C.CYAN}  log-analyzer  |  Security Log Analyzer{C.RESET}")
    print(f"{C.DIM}  threshold={args.threshold}  min-severity={args.min_severity}{C.RESET}\n")

    if args.file:
        if not args.file.exists():
            print(f"{C.RED}Error: file not found — {args.file}{C.RESET}", file=sys.stderr)
            return 1
        print(f"{C.DIM}[*] Scanning {args.file.name} ...{C.RESET}")
        analyzer.analyze_file(args.file)
        files_scanned.append(str(args.file))

    else:  # --batch
        if not args.batch.is_dir():
            print(f"{C.RED}Error: not a directory — {args.batch}{C.RESET}", file=sys.stderr)
            return 1
        log_files = sorted(args.batch.glob("*.log"))
        if not log_files:
            print(f"{C.YELLOW}No .log files found in {args.batch}{C.RESET}", file=sys.stderr)
            return 0
        print(f"{C.BOLD}[*] Batch scan — {len(log_files)} file(s){C.RESET}")
        for i, lf in enumerate(log_files, 1):
            print(f"{C.DIM}    [{i}/{len(log_files)}] {lf.name}{C.RESET}")
            analyzer.analyze_file(lf)
            files_scanned.append(str(lf))

    # Filter by minimum severity and sort (critical first)
    visible = [t for t in analyzer.threats if severity_gte(t.severity, args.min_severity)]
    visible.sort(key=lambda t: (-t.severity_score(), t.source_ip))

    if visible:
        print(f"\n{C.BOLD}{'─'*64}")
        print(f"  THREATS DETECTED ({len(visible)})")
        print(f"{'─'*64}{C.RESET}")
        for threat in visible:
            print_threat(threat)
    else:
        print(f"\n{C.GREEN}{C.BOLD}  [OK] No threats detected above threshold.{C.RESET}")

    print_summary(analyzer.threats, len(files_scanned))

    if args.output:
        save_report(analyzer.threats, args.output, files_scanned)

    # Exit code 2 = threats found (useful in CI / SIEM pipelines)
    return 2 if visible else 0


if __name__ == "__main__":
    sys.exit(main())

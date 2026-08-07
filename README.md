# log-analyzer

A SOC-grade command-line tool for detecting threats in SSH and web server logs. Pure Python stdlib — no external dependencies.

```
  log-analyzer  |  Security Log Analyzer
  threshold=10  min-severity=LOW

[*] Batch scan — 3 file(s)
    [1/3] normal_traffic.log
    [2/3] ssh_bruteforce.log
    [3/3] web_scanning.log

────────────────────────────────────────────────────────────────
  THREATS DETECTED (13)
────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────
  SSH BRUTE FORCE
  Source: ssh_bruteforce.log
────────────────────────────────────────────────────────────────
  SEVERITY  CRITICAL
  SOURCE IP 185.220.101.42
  COUNT     20 events
  FIRST     2026-04-28 01:03:12
  LAST      2026-04-28 01:03:50

  DETAILS
    > Targeted users: postgres, admin, test, deploy, git, pi, oracle, root...

  RECOMMENDATION
    Block IP with firewall (iptables/ufw). Enable fail2ban.
    Disable password auth — use SSH keys only.
────────────────────────────────────────────────────────────────
```

## What It Detects

| Threat | Log Format | Severity |
|--------|-----------|----------|
| SSH Brute Force | auth.log / syslog | MEDIUM → CRITICAL |
| Web Directory Scanning | Apache / Nginx | MEDIUM → CRITICAL |
| Suspicious User Agents | Apache / Nginx | MEDIUM → HIGH |
| Path Traversal / Sensitive File Probing | Apache / Nginx | HIGH |
| Off-Hours SSH Access (01:00–05:00) | auth.log / syslog | MEDIUM |
| Off-Hours Web Activity | Apache / Nginx | LOW |

Suspicious UA signatures include: `sqlmap`, `nikto`, `nmap`, `masscan`, `gobuster`, `dirbuster`, `nuclei`, `hydra`, `metasploit`, `wfuzz`, and more.

## Quick Start

```bash
git clone https://github.com/PolskiLisek11/log-analyzer
cd log-analyzer
python analyzer.py --file examples/ssh_bruteforce.log
```

No `pip install` required — stdlib only.

## Usage

```
usage: analyzer [-h] (--file FILE | --batch DIR)
                [--output JSON] [--threshold N]
                [--min-severity LEVEL] [--no-color]

options:
  --file FILE            analyze a single log file
  --batch DIR            analyze all .log files in a directory
  --output JSON          write JSON report to file
  --threshold N          minimum event count to trigger alert (default: 10)
  --min-severity LEVEL   LOW | MEDIUM | HIGH | CRITICAL  (default: LOW)
  --no-color             disable ANSI color output
```

### Examples

```bash
# Single file
python analyzer.py --file examples/ssh_bruteforce.log

# Web log with lower threshold
python analyzer.py --file examples/web_scanning.log --threshold 5

# Full batch scan with JSON report
python analyzer.py --batch examples/ --output report.json

# Only show high+ severity, pipe to file
python analyzer.py --batch /var/log/ --min-severity HIGH --no-color | tee scan.log

# CI/CD pipeline — exits 2 if threats found
python analyzer.py --file /var/log/auth.log || echo "Threats detected!"
```

## Supported Log Formats

Format is **auto-detected** — no flags needed.

| Format | Example line |
|--------|-------------|
| `auth.log` / `syslog` | `Apr 28 01:03:12 srv sshd[1201]: Failed password for root from 1.2.3.4 port 54321 ssh2` |
| Apache / Nginx CLF | `1.2.3.4 - - [28/Apr/2026:09:00:01 +0000] "GET /admin HTTP/1.1" 404 512 "-" "sqlmap/1.7"` |

## JSON Report

```bash
python analyzer.py --batch examples/ --output report.json
```

```json
{
  "generated_at": "2026-04-28T14:30:00.123456",
  "files_scanned": ["examples/ssh_bruteforce.log", "examples/web_scanning.log"],
  "summary": { "CRITICAL": 1, "HIGH": 6, "MEDIUM": 5, "LOW": 1 },
  "total_threats": 13,
  "threats": [
    {
      "threat_type": "SSH Brute Force",
      "severity": "CRITICAL",
      "source_ip": "185.220.101.42",
      "count": 20,
      "first_seen": "2026-04-28 01:03:12",
      "last_seen": "2026-04-28 01:03:50",
      "details": ["Targeted users: postgres, admin, test, root..."],
      "recommendation": "Block IP with firewall...",
      "source_file": "examples/ssh_bruteforce.log"
    }
  ]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No threats detected |
| `1` | Startup error (file not found, etc.) |
| `2` | Threats found — useful for CI/SIEM pipelines |

## Jarvis — the analyzer as an agent

`analyzer.py` tells you *what* is in a log. Jarvis is a personal agent that can
act on it: correlate an IP across files, remember what you decided about it last
week, and draft the firewall rule. The analyzer becomes one of its tools.

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

python -m jarvis                                     # interactive session
python -m jarvis -p "scan examples/ and summarise"   # one-shot
python -m jarvis --workspace /var/log --approve readonly
```

It is assembled from five parts — a model, a loop, memory, tools and an
interface — with a home at `~/.jarvis`:

| Part | Where | What it does |
|------|-------|--------------|
| Engine | `jarvis/engine.py` | Talks to Claude. Streaming, adaptive thinking, effort. |
| Harness | `jarvis/harness.py` | The loop: plan → act → feed results back → repeat. |
| Memory | `jarvis/memory.py` | Markdown notes that survive between sessions. |
| Tools | `jarvis/tools/` | Files, shell, memory, and `scan_logs` — this analyzer. |
| Interface | `jarvis/cli.py`, `jarvis/voice.py` | Terminal REPL, optional speech. |

State-changing actions ask before they run (`--approve auto` to skip, `readonly`
to refuse). File tools cannot leave the workspace, and the shell tool runs one
allowlisted command with no shell interpretation — so pipes and redirects do not
work, and neither does command injection.

Architecture and the reasoning behind each boundary: **[docs/JARVIS.md](docs/JARVIS.md)**.

```bash
python -m unittest discover -s tests -t .   # 97 tests, all offline
```

`analyzer.py` itself stays stdlib-only — `anthropic` is needed only for the agent.

## Project Structure

```
log-analyzer/
├── analyzer.py          # main script — parser, detection engine, output
├── requirements.txt     # stdlib only for the analyzer; anthropic for the agent
├── examples/
│   ├── ssh_bruteforce.log       # simulated SSH brute force (3 IPs)
│   ├── web_scanning.log         # simulated dir scan + sqlmap + nikto
│   └── normal_traffic.log       # clean baseline traffic
├── jarvis/              # the agent
│   ├── engine.py                # the model
│   ├── harness.py               # the agent loop
│   ├── memory.py                # long-term notes
│   ├── prompts.py               # system prompt
│   ├── voice.py                 # speech output
│   ├── cli.py                   # REPL + one-shot mode
│   └── tools/                   # files, shell, memory, plan, scan_logs
├── docs/JARVIS.md       # agent architecture
└── tests/test_jarvis.py # offline test suite
```

## Detection Thresholds

Default `--threshold 10` means an IP must trigger ≥10 suspicious events to generate an alert. Lower it for noisier environments:

```bash
python analyzer.py --file auth.log --threshold 5   # more sensitive
python analyzer.py --file auth.log --threshold 20  # less sensitive
```

Severity is determined by event count:

| Count | SSH Brute Force | Dir Scan |
|-------|----------------|----------|
| < threshold | — | — |
| threshold+ | MEDIUM | MEDIUM |
| 10+ | HIGH | HIGH |
| 20+ | CRITICAL | — |
| 30+ | — | CRITICAL |

## License

MIT

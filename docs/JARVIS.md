# Jarvis — architecture

A personal agent built from five parts. The claim worth taking seriously is the
one about the harness: **a model on its own is a chatbot; the loop around it is
what makes it an agent.** Everything below is organised around that.

```
                         ┌───────────────────────────────┐
   you ──── cli.py ────► │  harness.py — the loop        │
        (interface)      │                               │
                         │   ask the model ──────────────┼──► engine.py ──► Claude
                         │        ▲            │         │
                         │        │            ▼         │
                         │        │      run the tools ──┼──► tools/
                         │        └──── results ─────────┤      files, shell,
                         │                               │      memory, scan_logs
                         └───────────────┬───────────────┘
                                         │
                          memory.py ◄────┘  notes that outlive the process
                                                    │
                            ~/.jarvis/  ◄───────────┘  the home
```

| Piece | Where | What it is |
|---|---|---|
| The engine | `jarvis/engine.py` | An AI model. Turns a conversation plus tool declarations into the next message. Knows nothing about the tools. |
| The harness | `jarvis/harness.py` | The loop. Plans, acts, feeds results back, decides when the task is done. **This is the part that makes it agentic.** |
| Memory | `jarvis/memory.py` | Markdown notes the agent writes to itself and reads back next session. |
| Tools | `jarvis/tools/` | The ability to do work: read and write files, run commands, scan logs. |
| Voice / interface | `jarvis/voice.py`, `jarvis/cli.py` | A terminal REPL, and optional speech for the final answer. |
| A home | `~/.jarvis/` | One directory holding memory, workspace, config and transcripts. |

---

## The loop

Stripped of error handling, `Harness.run_turn` is this:

```
append the user's message
repeat, up to max_steps:
    ask the model
    append its reply verbatim
    if it asked for no tools:  stop
    run every requested tool
    append all results as ONE message
```

Four details in there are load-bearing, and each one is a bug if you get it
wrong:

**The assistant's `content` goes back verbatim.** It is tempting to pull the
text out and append that. Doing so drops the `tool_use` blocks, and the next
turn's `tool_result` blocks then reference something that is not in the
conversation — the API rejects the request.

**All tool results go back in a single message.** When a model requests three
tools at once and gets three separate messages back, it learns that parallel
calls are not wanted and stops making them. One message, every result.

**A failing tool returns an error, it does not raise.** `Toolbox.run` catches
everything and returns `(text, is_error=True)`. The model reads the error and
usually fixes its own arguments. An exception escaping here would kill the
session over a typo in a path.

**The step budget is not optional.** A model that gets stuck retrying the same
failing call will do it until something stops it. `max_steps` (default 40) is
that something.

### Everything else in the loop

| Situation | What happens |
|---|---|
| `stop_reason == "pause_turn"` | A server-side tool hit its iteration cap. Re-send unchanged — it resumes. Adding a "continue" message only confuses whose turn it is. |
| `stop_reason == "refusal"` | Safety classifiers declined. `content` is empty or partial, so anything reading `content[0]` blindly crashes here. Reported to the user; nothing ran. |
| `stop_reason == "max_tokens"` | The answer was cut off. Warn rather than pretend it is complete. |
| Step budget exhausted | Stop and say so. `TurnResult.stopped_early` is set, and one-shot mode exits `2`. |

---

## The engine

Wraps the Messages API and nothing else. Model, effort, thinking and streaming
live here so the rest of the package never imports `anthropic`.

- **Streaming is mandatory, not a preference.** `max_tokens` is 32000 by
  default; a non-streaming request that large risks an HTTP timeout on a long
  answer, and the user would stare at a cursor for two minutes either way.
- **Adaptive thinking**, with `display` set to `"omitted"` unless `--thinking`
  is passed. Thinking happens and is billed identically either way — `display`
  only controls whether you get to read a summary of it.
- **Effort** defaults to `xhigh`, the sweet spot for agentic and coding work.
  `--effort medium` is a real cost lever and is worth trying on routine tasks.
- **Server-side fallback** is on by default. Opus 5 runs safety classifiers that
  can decline a request outright, and for a log-analysis agent a false positive
  on legitimate security work is not hypothetical. With fallbacks on, the API
  re-runs the declined request on another model inside the same call.
- **Compaction** is on by default, so a long session summarises its own history
  server-side instead of dying at the context ceiling.

The last two are betas. If the API rejects either, the engine turns both off,
prints a warning and retries once — an unavailable beta should cost a warning,
not the session.

---

## Memory

A directory of markdown notes. The first line of each note is a one-line
summary; the rest is the body.

That split is the whole design. The system prompt carries **only the
summaries** — an index — and the agent spends tokens on a full note only when a
summary looks relevant and it calls `memory_read`. Memory can therefore grow
without the prompt growing with it.

```
~/.jarvis/memory/
├── preferences/tone.md      # User wants short answers in Polish, no emoji.
└── projects/log-analyzer.md # Stdlib-only SSH/web log threat scanner they maintain.
```

The index is built once at session start and held constant for the session's
lifetime. Rebuilding it mid-session would change the front of the prompt and
invalidate the cached prefix for the entire conversation on the next request.

One idea per note. A note describing two unrelated things is two notes: the
index stays readable, and a recall pulls in less noise.

---

## Tools

| Tool | Does |
|---|---|
| `plan` | Records the task list and puts it on screen. |
| `read_file`, `write_file`, `edit_file` | Workspace file access. `edit_file` refuses ambiguous matches rather than guessing. |
| `list_dir`, `glob_files`, `grep_files` | Finding things without reading whole files. |
| `memory_write`, `memory_read`, `memory_search`, `memory_list`, `memory_delete` | Long-term notes. |
| `run_shell` | One allowlisted command, no shell. |
| `scan_logs`, `scan_logs_json` | **This repository's threat detection**, as a tool. |

`scan_logs` is the point of building this here rather than in an empty
directory. `analyzer.py` already turns logs into a list of threats; wrapping it
as a tool is what lets the agent reason *about* the findings — correlate an IP
across files, check it against what it noted last week, draft the firewall rule
— instead of the user reading a report and doing that part themselves. It is
imported rather than shelled out to, so findings arrive as objects instead of
text that would have to be parsed back out of a terminal rendering.

### Security boundaries

The agent runs on your machine with your permissions, and its arguments are
model output. Three boundaries hold:

**Path confinement.** Every path is resolved — following symlinks — and rejected
if it lands outside the workspace. A symlink inside the workspace pointing at
`/etc/passwd` does not work; there is a test for exactly that.

**A shell allowlist, and no shell.** Commands are split with `shlex` and run with
`shell=False`, so `;`, `|`, `$(…)` and `>` are never interpreted — they arrive
as ordinary arguments and command injection has nowhere to land. The cost is
real: pipes and redirects genuinely do not work. Only the executables in
`Config.shell_allow` may run, matched on basename so `/bin/rm` cannot slip past
as `rm`. `git` is further restricted to read-only sub-commands.

**Interpreters are not on the default allowlist.** Allowing `python3` is
allowing arbitrary code, which would make the other two boundaries decorative.
Add it through `shell_allow_extra` when the agent runs in a container, and
understand what you are turning off.

On top of those, the approval gate:

| `--approve` | Behaviour |
|---|---|
| `ask` (default) | Every state-changing tool is shown with its arguments and waits for `y`. |
| `auto` | No prompts. For headless runs where you already trust the task. |
| `readonly` | State-changing tools are refused. Investigation only. |

Without a terminal, `ask` degrades to `readonly` rather than to `auto` — the
safe reading of "ask the user" when there is no user is "change nothing".

---

## Checking its own work

The reel describes the harness as something that "plans, acts, and checks its
own work". Two of those are unconditional here. The third is a switch that is
**off by default**, and the reason is worth stating.

`--verify N` runs a fresh-context review pass after each answer: a separate
model, which never saw the working conversation, is given the original request
and a list of what actually ran, and reports `PASS` or concrete gaps. Gaps are
fed back and the agent continues.

That is a genuinely good pattern — a reviewer with fresh context catches
claimed-but-not-done work far better than self-critique does. It is off by
default because Claude Opus 5 already verifies its own work without being asked,
and stacking a second pass on top mostly buys latency. It earns its cost when
you run a smaller model as the engine:

```bash
jarvis --model claude-haiku-4-5 --effort medium --verify 1
```

For the same reason there is no "double-check your work" line in the system
prompt. On a current model that instruction produces over-verification, not
accuracy.

---

## Prompt caching

The system prompt is built once in `Harness.__init__` and never mutated. It
carries a `cache_control` breakpoint, and tool declarations are emitted in
sorted order so the serialised tool block is byte-identical between requests.

Both matter because caching is a **prefix match**: tools render first, then the
system prompt, then messages. One changed byte anywhere in that prefix
invalidates everything after it. A timestamp in the system prompt, or a tool
list built from an unordered `dict`, would silently cost full price on every
turn of a long session.

---

## Running it

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

python -m jarvis                                  # interactive
python -m jarvis -p "scan examples/ and summarise" # one-shot
python -m jarvis --workspace /var/log --approve readonly
python -m jarvis --voice system --thinking
```

Exit codes in one-shot mode: `0` finished, `1` startup or API error, `2` refused
or stopped at the step budget.

### Tests

```bash
python -m unittest discover -s tests -t .
```

97 tests, all offline — no API key, no network. They cover path confinement, the
shell allowlist, the approval gate, memory, response shaping, and the loop
itself driven by a stub engine.

---

## What is deliberately not here

- **No RAG or vector store.** Memory is a searchable directory of notes. For a
  single user's notes, an index would be machinery without a payoff.
- **No speech input.** Output speech uses whatever TTS the OS already has;
  transcription would mean a real dependency and a microphone permission
  prompt. `Voice` is a protocol, so a Whisper implementation drops in.
- **No sub-agents.** One loop, one model. Delegation is worth adding when a task
  fans out across genuinely independent tracks, and adds cost and re-briefing
  overhead when it does not.
- **No sandbox of its own.** The boundaries above are real but they are not a
  container. For untrusted work, run the whole thing in one.

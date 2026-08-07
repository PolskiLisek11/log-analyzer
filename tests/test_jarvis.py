"""Tests for the Jarvis agent.

Everything here runs offline — no API key, no network. The parts worth testing
are the ones that hold when the model misbehaves: path confinement, the shell
allowlist, the approval gate, and the response shaping the loop depends on.

    python -m unittest discover -s tests -t .
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

from jarvis.config import Config
from jarvis.engine import Engine
from jarvis.memory import Memory, MemoryError_
from jarvis.tools import Plan, ToolContext, ToolError, ToolSpec, Toolbox
from jarvis.tools import files as files_tools
from jarvis.tools import memory_tools, plan as plan_tools, security, shell
from jarvis.voice import NullVoice, make_voice, strip_markup

REPO_ROOT = Path(__file__).resolve().parents[1]


class AgentTestCase(unittest.TestCase):
    """Builds a real config, memory and tool context over a temp directory."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="jarvis-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.config = Config(home=self.tmp / "home", workspace=self.tmp / "ws")
        self.config.ensure_home()
        self.memory = Memory(self.config.memory_dir)
        self.ctx = ToolContext(
            config=self.config,
            workspace=self.config.workspace,
            memory=self.memory,
            plan=Plan(),
        )

    def write(self, relative: str, content: str) -> Path:
        path = self.config.workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


# ── Config ────────────────────────────────────────────────────────────────────

class TestConfig(AgentTestCase):
    def test_derived_paths_live_under_home(self):
        self.assertEqual(self.config.memory_dir.parent, self.config.home)
        self.assertEqual(self.config.sessions_dir.parent, self.config.home)

    def test_ensure_home_is_idempotent(self):
        self.config.ensure_home()
        self.config.ensure_home()
        self.assertTrue(self.config.memory_dir.is_dir())

    def test_invalid_approval_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            Config(home=self.tmp, approval_mode="whenever")

    def test_extra_shell_binaries_extend_the_allowlist(self):
        config = Config(home=self.tmp, shell_allow_extra=("python3",))
        self.assertIn("python3", config.shell_allow)
        self.assertIn("ls", config.shell_allow)

    def test_python_is_not_allowlisted_by_default(self):
        self.assertNotIn("python3", Config(home=self.tmp).shell_allow)

    def test_load_applies_overrides_and_ignores_unknown_keys(self):
        config = Config.load(home=self.tmp, model="claude-sonnet-5", nonsense="x")
        self.assertEqual(config.model, "claude-sonnet-5")
        self.assertFalse(hasattr(config, "nonsense"))

    def test_load_leaves_defaults_for_none_overrides(self):
        config = Config.load(home=self.tmp, model=None)
        self.assertEqual(config.model, "claude-opus-5")


# ── Memory ────────────────────────────────────────────────────────────────────

class TestMemory(AgentTestCase):
    def test_write_then_read_round_trips(self):
        self.memory.write("prefs/tone.md", "# Short answers\nUser prefers brevity.")
        self.assertIn("User prefers brevity", self.memory.read("prefs/tone.md"))

    def test_extension_is_added_when_missing(self):
        path = self.memory.write("prefs/tone", "# Short answers\nbody")
        self.assertEqual(path, "prefs/tone.md")

    def test_index_exposes_the_summary_line(self):
        self.memory.write("a.md", "# The one-line summary\nbody text")
        notes = self.memory.index()
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].summary, "The one-line summary")

    def test_digest_lists_notes_and_reports_emptiness(self):
        self.assertIn("empty", self.memory.digest())
        self.memory.write("b.md", "# Second note\nbody")
        self.assertIn("b.md — Second note", self.memory.digest())

    def test_note_without_summary_heading_is_rejected(self):
        with self.assertRaises(MemoryError_):
            self.memory.write("c.md", "no heading here")

    def test_empty_note_is_rejected(self):
        with self.assertRaises(MemoryError_):
            self.memory.write("d.md", "   ")

    def test_oversized_note_is_rejected(self):
        with self.assertRaises(MemoryError_):
            self.memory.write("e.md", "# big\n" + "x" * (64 * 1024 + 1))

    def test_traversal_paths_are_rejected(self):
        for bad in ("../escape.md", "/etc/passwd", "a/../../b.md", "..%2Fx.md"):
            with self.subTest(path=bad), self.assertRaises(MemoryError_):
                self.memory.write(bad, "# x\nbody")

    def test_absolute_path_does_not_escape_the_root(self):
        with self.assertRaises(MemoryError_):
            self.memory.read("/etc/hostname")

    def test_search_finds_content_and_misses_are_empty(self):
        self.memory.write("f.md", "# Note\nthe firewall rule is documented here")
        self.assertTrue(self.memory.search("FIREWALL"))
        self.assertEqual(self.memory.search("nonexistent-token"), [])

    def test_delete_removes_the_note(self):
        self.memory.write("g.md", "# Note\nbody")
        self.memory.delete("g.md")
        self.assertEqual(self.memory.index(), [])
        with self.assertRaises(MemoryError_):
            self.memory.delete("g.md")


# ── File tools ────────────────────────────────────────────────────────────────

class TestFileTools(AgentTestCase):
    def test_read_returns_numbered_lines(self):
        self.write("notes.txt", "alpha\nbeta\ngamma\n")
        out = files_tools.read_file(self.ctx, {"path": "notes.txt"})
        self.assertIn("1  alpha", out)
        self.assertIn("3  gamma", out)

    def test_read_window_reports_the_range(self):
        self.write("many.txt", "\n".join(str(i) for i in range(1, 101)))
        out = files_tools.read_file(self.ctx, {"path": "many.txt", "start_line": 10, "max_lines": 5})
        self.assertIn("10  10", out)
        self.assertIn("showing 10-14 of 100 lines", out)

    def test_write_creates_parent_directories(self):
        files_tools.write_file(self.ctx, {"path": "deep/nested/f.txt", "content": "hi"})
        self.assertEqual((self.config.workspace / "deep/nested/f.txt").read_text(), "hi")

    def test_edit_replaces_a_unique_snippet(self):
        self.write("code.py", "def a():\n    return 1\n")
        files_tools.edit_file(self.ctx, {"path": "code.py", "old_text": "return 1", "new_text": "return 2"})
        self.assertIn("return 2", (self.config.workspace / "code.py").read_text())

    def test_edit_refuses_ambiguous_snippets_without_writing(self):
        self.write("dup.txt", "same\nsame\n")
        with self.assertRaises(ToolError) as caught:
            files_tools.edit_file(self.ctx, {"path": "dup.txt", "old_text": "same", "new_text": "x"})
        self.assertIn("appears 2 times", str(caught.exception))
        self.assertEqual((self.config.workspace / "dup.txt").read_text(), "same\nsame\n")

    def test_edit_refuses_a_missing_snippet(self):
        self.write("plain.txt", "hello")
        with self.assertRaises(ToolError):
            files_tools.edit_file(self.ctx, {"path": "plain.txt", "old_text": "absent", "new_text": "x"})

    def test_paths_outside_the_workspace_are_refused(self):
        for bad in ("../outside.txt", "/etc/passwd", "../../etc/hostname"):
            with self.subTest(path=bad), self.assertRaises(ToolError) as caught:
                files_tools.read_file(self.ctx, {"path": bad})
            self.assertIn("outside the workspace", str(caught.exception))

    def test_symlink_out_of_the_workspace_is_refused(self):
        secret = self.tmp / "secret.txt"
        secret.write_text("classified")
        link = self.config.workspace / "link.txt"
        try:
            link.symlink_to(secret)
        except OSError:
            self.skipTest("symlinks unavailable on this platform")
        with self.assertRaises(ToolError):
            files_tools.read_file(self.ctx, {"path": "link.txt"})

    def test_writing_outside_the_workspace_is_refused(self):
        with self.assertRaises(ToolError):
            files_tools.write_file(self.ctx, {"path": "../evil.txt", "content": "x"})
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_grep_reports_path_and_line_number(self):
        self.write("src/app.py", "import os\ndef handler():\n    pass\n")
        out = files_tools.grep_files(self.ctx, {"pattern": r"def \w+"})
        self.assertIn("src/app.py:2:", out)

    def test_grep_rejects_an_invalid_regex(self):
        with self.assertRaises(ToolError):
            files_tools.grep_files(self.ctx, {"pattern": "(unclosed"})

    def test_glob_matches_by_extension(self):
        self.write("a.log", "x")
        self.write("sub/b.log", "y")
        self.write("c.txt", "z")
        out = files_tools.glob_files(self.ctx, {"pattern": "*.log"})
        self.assertIn("a.log", out)
        self.assertIn("sub/b.log", out)
        self.assertNotIn("c.txt", out)

    def test_list_dir_marks_directories(self):
        self.write("sub/x.txt", "1")
        out = files_tools.list_dir(self.ctx, {"path": "."})
        self.assertIn("sub/", out)


# ── Shell tool ────────────────────────────────────────────────────────────────

class TestShellTool(AgentTestCase):
    def test_allowlisted_command_runs_in_the_workspace(self):
        self.write("hello.txt", "content")
        out = shell.run_shell(self.ctx, {"command": "ls"})
        self.assertIn("hello.txt", out)
        self.assertIn("exit code: 0", out)

    def test_non_allowlisted_binary_is_refused(self):
        with self.assertRaises(ToolError) as caught:
            shell.run_shell(self.ctx, {"command": "rm -rf /"})
        self.assertIn("not on the allowlist", str(caught.exception))

    def test_absolute_path_cannot_smuggle_a_denied_binary(self):
        with self.assertRaises(ToolError):
            shell.run_shell(self.ctx, {"command": "/bin/rm file"})

    def test_interpreters_are_denied_by_default(self):
        with self.assertRaises(ToolError):
            shell.run_shell(self.ctx, {"command": "python3 -c 'print(1)'"})

    def test_shell_operators_are_reported_clearly(self):
        for command in ("ls | grep x", "ls > out.txt", "ls ; rm f", "ls && cat f"):
            with self.subTest(command=command), self.assertRaises(ToolError) as caught:
                shell.run_shell(self.ctx, {"command": command})
            self.assertIn("shell operators", str(caught.exception))

    def test_quoted_metacharacters_are_still_usable_as_arguments(self):
        self.write("data.txt", "alpha\nbeta\n")
        out = shell.run_shell(self.ctx, {"command": "grep -E 'alpha|beta' data.txt"})
        self.assertIn("alpha", out)

    def test_git_write_subcommands_are_refused(self):
        with self.assertRaises(ToolError) as caught:
            shell.run_shell(self.ctx, {"command": "git push origin main"})
        self.assertIn("read-only", str(caught.exception))

    def test_unbalanced_quotes_produce_a_clear_error(self):
        with self.assertRaises(ToolError):
            shell.run_shell(self.ctx, {"command": "ls 'unterminated"})

    def test_empty_command_is_refused(self):
        with self.assertRaises(ToolError):
            shell.run_shell(self.ctx, {"command": "   "})


# ── Toolbox ───────────────────────────────────────────────────────────────────

class TestToolbox(AgentTestCase):
    def make_box(self, approve=None) -> Toolbox:
        box = Toolbox(approve=approve)
        box.register(ToolSpec(
            name="ok", description="d", input_schema={"type": "object", "properties": {}},
            handler=lambda ctx, args: "fine",
        ))
        box.register(ToolSpec(
            name="boom", description="d", input_schema={"type": "object", "properties": {}},
            handler=lambda ctx, args: (_ for _ in ()).throw(RuntimeError("kaboom")),
        ))
        box.register(ToolSpec(
            name="mutate", description="d", input_schema={"type": "object", "properties": {}},
            handler=lambda ctx, args: "changed", mutating=True,
        ))
        return box

    def test_successful_call_returns_output(self):
        self.assertEqual(self.make_box().run(self.ctx, "ok", {}), ("fine", False))

    def test_unknown_tool_is_an_error_not_a_crash(self):
        output, is_error = self.make_box().run(self.ctx, "nope", {})
        self.assertTrue(is_error)
        self.assertIn("Unknown tool", output)

    def test_handler_exception_is_converted_to_an_error_result(self):
        output, is_error = self.make_box().run(self.ctx, "boom", {})
        self.assertTrue(is_error)
        self.assertIn("kaboom", output)

    def test_readonly_mode_blocks_mutating_tools(self):
        self.config.approval_mode = "readonly"
        output, is_error = self.make_box().run(self.ctx, "mutate", {})
        self.assertTrue(is_error)
        self.assertIn("read-only", output)

    def test_readonly_mode_still_allows_reads(self):
        self.config.approval_mode = "readonly"
        self.assertEqual(self.make_box().run(self.ctx, "ok", {}), ("fine", False))

    def test_ask_mode_denial_stops_the_call(self):
        self.config.approval_mode = "ask"
        box = self.make_box(approve=lambda tool, args, reason: False)
        output, is_error = box.run(self.ctx, "mutate", {})
        self.assertTrue(is_error)
        self.assertIn("Denied", output)

    def test_ask_mode_approval_lets_the_call_through(self):
        self.config.approval_mode = "ask"
        box = self.make_box(approve=lambda tool, args, reason: True)
        self.assertEqual(box.run(self.ctx, "mutate", {}), ("changed", False))

    def test_auto_mode_never_consults_the_approver(self):
        self.config.approval_mode = "auto"
        calls = []
        box = self.make_box(approve=lambda *a: calls.append(a) or False)
        self.assertEqual(box.run(self.ctx, "mutate", {}), ("changed", False))
        self.assertEqual(calls, [])

    def test_long_output_is_truncated_with_an_explanation(self):
        box = Toolbox()
        box.register(ToolSpec(
            name="flood", description="d", input_schema={"type": "object", "properties": {}},
            handler=lambda ctx, args: "x" * 100_000,
        ))
        self.config.max_output_chars = 5_000
        output, is_error = box.run(self.ctx, "flood", {})
        self.assertFalse(is_error)
        self.assertLess(len(output), 10_000)
        self.assertIn("truncated", output)

    def test_definitions_are_sorted_for_a_stable_prompt_prefix(self):
        box = self.make_box()
        names = [d["name"] for d in box.definitions()]
        self.assertEqual(names, sorted(names))

    def test_duplicate_registration_is_rejected(self):
        box = self.make_box()
        with self.assertRaises(ValueError):
            box.register(ToolSpec(
                name="ok", description="d", input_schema={"type": "object", "properties": {}},
                handler=lambda ctx, args: "",
            ))

    def test_every_declaration_is_well_formed(self):
        box = Toolbox()
        for module in (plan_tools, files_tools, memory_tools, shell, security):
            box.register_all(module.build())
        for definition in box.definitions():
            with self.subTest(tool=definition["name"]):
                self.assertGreater(len(definition["description"]), 40)
                self.assertEqual(definition["input_schema"]["type"], "object")
                self.assertIn("properties", definition["input_schema"])
                for prop in definition["input_schema"]["properties"].values():
                    self.assertIn("description", prop)


# ── Plan ──────────────────────────────────────────────────────────────────────

class TestPlan(AgentTestCase):
    def test_render_marks_each_status(self):
        self.ctx.plan.set([
            {"title": "one", "status": "done"},
            {"title": "two", "status": "doing"},
            {"title": "three", "status": "todo"},
        ])
        rendered = self.ctx.plan.render()
        self.assertIn("[x] one", rendered)
        self.assertIn("[~] two", rendered)
        self.assertIn("[ ] three", rendered)

    def test_unknown_status_falls_back_to_todo(self):
        self.ctx.plan.set([{"title": "x", "status": "banana"}])
        self.assertEqual(self.ctx.plan.steps[0]["status"], "todo")

    def test_untitled_steps_are_dropped(self):
        self.ctx.plan.set([{"title": "  ", "status": "todo"}, {"title": "real", "status": "todo"}])
        self.assertEqual(len(self.ctx.plan.steps), 1)

    def test_tool_reports_progress(self):
        out = plan_tools.plan(self.ctx, {"steps": [
            {"title": "a", "status": "done"}, {"title": "b", "status": "todo"},
        ]})
        self.assertIn("1/2", out)

    def test_tool_rejects_an_empty_plan(self):
        with self.assertRaises(ToolError):
            plan_tools.plan(self.ctx, {"steps": []})

    def test_tool_rejects_an_oversized_plan(self):
        with self.assertRaises(ToolError):
            plan_tools.plan(self.ctx, {"steps": [{"title": f"s{i}", "status": "todo"} for i in range(30)]})


# ── Security tool (wraps analyzer.py) ─────────────────────────────────────────

class TestSecurityTool(AgentTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.ctx.workspace = REPO_ROOT
        self.config.workspace = REPO_ROOT

    def test_scan_detects_the_ssh_brute_force_sample(self):
        out = security.scan_logs(self.ctx, {"path": "examples/ssh_bruteforce.log"})
        self.assertIn("SSH Brute Force", out)
        self.assertIn("CRITICAL", out)

    def test_min_severity_filters_findings_out(self):
        everything = security.scan_logs(self.ctx, {"path": "examples/", "min_severity": "LOW"})
        critical = security.scan_logs(self.ctx, {"path": "examples/", "min_severity": "CRITICAL"})
        self.assertLess(critical.count("["), everything.count("["))

    def test_clean_log_reports_no_threats(self):
        out = security.scan_logs(self.ctx, {"path": "examples/normal_traffic.log"})
        self.assertIn("No threats detected", out)

    def test_json_scan_is_machine_readable(self):
        import json

        payload = json.loads(security.scan_logs_json(self.ctx, {"path": "examples/"}))
        self.assertIn("threats", payload)
        self.assertGreater(payload["total_threats"], 0)
        self.assertIn("severity", payload["threats"][0])

    def test_invalid_severity_is_refused(self):
        with self.assertRaises(ToolError):
            security.scan_logs(self.ctx, {"path": "examples/", "min_severity": "URGENT"})

    def test_scanning_outside_the_workspace_is_refused(self):
        self.ctx.workspace = self.tmp / "ws"
        self.config.workspace = self.tmp / "ws"
        with self.assertRaises(ToolError):
            security.scan_logs(self.ctx, {"path": "/var/log"})


# ── Engine response shaping ───────────────────────────────────────────────────

def _block(**fields):
    return types.SimpleNamespace(**fields)


class TestEngineShaping(unittest.TestCase):
    def test_turn_separates_text_from_tool_calls(self):
        message = _block(
            content=[
                _block(type="text", text="Working on it."),
                _block(type="tool_use", name="read_file", id="tu_1", input={"path": "a"}),
            ],
            stop_reason="tool_use",
            stop_details=None,
        )
        turn = Engine._to_turn(message)
        self.assertEqual(turn.text, "Working on it.")
        self.assertEqual(len(turn.tool_calls), 1)
        self.assertEqual(turn.tool_calls[0].name, "read_file")
        self.assertFalse(turn.refused)

    def test_refusal_is_flagged_with_its_category(self):
        message = _block(
            content=[], stop_reason="refusal",
            stop_details=_block(category="cyber", explanation="…"),
        )
        turn = Engine._to_turn(message)
        self.assertTrue(turn.refused)
        self.assertEqual(turn.refusal_category, "cyber")

    def test_missing_stop_details_does_not_crash(self):
        turn = Engine._to_turn(_block(content=[], stop_reason="end_turn", stop_details=None))
        self.assertIsNone(turn.refusal_category)

    def test_fallback_block_records_the_answering_model(self):
        message = _block(
            content=[
                _block(type="fallback", to=_block(model="claude-opus-4-8")),
                _block(type="text", text="answer"),
            ],
            stop_reason="end_turn", stop_details=None,
        )
        self.assertEqual(Engine._to_turn(message).fell_back_to, "claude-opus-4-8")

    def test_replayable_keeps_content_untouched_without_a_fallback(self):
        content = [_block(type="thinking", thinking="…"), _block(type="text", text="hi")]
        self.assertIs(Engine.replayable(content), content)

    def test_replayable_drops_thinking_after_a_fallback(self):
        content = [
            _block(type="thinking", thinking="…"),
            _block(type="fallback", to=_block(model="claude-opus-4-8")),
            _block(type="text", text="hi"),
        ]
        kinds = [b.type for b in Engine.replayable(content)]
        self.assertNotIn("thinking", kinds)
        self.assertIn("text", kinds)


# ── Voice ─────────────────────────────────────────────────────────────────────

class TestEngineDegradation(unittest.TestCase):
    """Which optional feature the engine gives up for a given rejection.

    `--model` accepts any model id and models differ in what they accept —
    `effort: "max"` is rejected by Haiku 4.5, for one. The engine reads the
    rejection rather than carrying a capability table that goes stale.
    """

    def full_kwargs(self) -> dict:
        return {
            "model": "claude-haiku-4-5",
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": "max"},
            "betas": ["compact-2026-01-12"],
            "fallbacks": "default",
            "context_management": {"edits": []},
        }

    @staticmethod
    def error(message: str):
        return types.SimpleNamespace(message=message)

    def test_an_effort_rejection_drops_only_effort(self):
        name, keys, _ = Engine._next_degradation(
            self.error("effort: max is not supported by this model"), self.full_kwargs(), set()
        )
        self.assertEqual(name, "output_config")
        self.assertEqual(keys, ("output_config",))

    def test_a_thinking_rejection_drops_only_thinking(self):
        name, keys, _ = Engine._next_degradation(
            self.error("thinking is not supported"), self.full_kwargs(), set()
        )
        self.assertEqual(name, "thinking")
        self.assertEqual(keys, ("thinking",))

    def test_an_unattributable_rejection_falls_back_to_the_betas(self):
        name, keys, _ = Engine._next_degradation(
            self.error("something entirely unexpected"), self.full_kwargs(), set()
        )
        self.assertEqual(name, "betas")
        self.assertIn("context_management", keys)

    def test_a_feature_is_only_given_up_once(self):
        kwargs = self.full_kwargs()
        self.assertIsNone(
            Engine._next_degradation(
                self.error("effort rejected"), kwargs, {"output_config", "thinking", "betas"}
            )
        )

    def test_nothing_left_to_drop_means_raise(self):
        self.assertIsNone(
            Engine._next_degradation(
                self.error("messages: at least one message is required"),
                {"model": "claude-opus-5", "messages": []},
                set(),
            )
        )

    def test_absent_features_are_not_offered_up(self):
        # No effort in the request, so an unrelated failure must not claim it.
        name, _, _ = Engine._next_degradation(
            self.error("unexpected"),
            {"model": "claude-opus-5", "betas": ["x"], "thinking": {"type": "adaptive"}},
            set(),
        )
        self.assertEqual(name, "betas")

    def test_degradations_cover_every_optional_kwarg(self):
        # Every optional request parameter must have a way to be given up, or a
        # model that rejects it takes the whole session down with it.
        optional = {
            "thinking", "output_config", "betas", "fallbacks",
            "context_management", "mcp_servers",
        }
        covered = {key for _, _, keys, _ in Engine._DEGRADATIONS for key in keys}
        self.assertEqual(covered, optional)


class TestVoice(unittest.TestCase):
    def test_markdown_syntax_is_stripped(self):
        spoken = strip_markup("## Heading\n- **bold** and `code`\n[link](http://x)")
        for symbol in ("#", "*", "`", "[", "]", "("):
            self.assertNotIn(symbol, spoken)
        self.assertIn("bold", spoken)
        self.assertIn("link", spoken)

    def test_code_blocks_are_summarised_away(self):
        spoken = strip_markup("Here:\n```python\nprint('x')\n```\ndone")
        self.assertNotIn("print", spoken)
        self.assertIn("code omitted", spoken)

    def test_long_text_is_cut_at_a_sentence_boundary(self):
        spoken = strip_markup(("This is a sentence. " * 200))
        self.assertLessEqual(len(spoken), 720)
        self.assertTrue(spoken.endswith("…"))

    def test_off_mode_yields_a_silent_voice(self):
        voice = make_voice("off")
        self.assertIsInstance(voice, NullVoice)
        self.assertFalse(voice.enabled)
        voice.speak("nothing happens")


# ── Memory tools ──────────────────────────────────────────────────────────────

class TestMemoryTools(AgentTestCase):
    def test_write_and_read_through_the_tool_layer(self):
        memory_tools.memory_write(self.ctx, {"path": "n.md", "content": "# Summary\ndetail"})
        self.assertIn("detail", memory_tools.memory_read(self.ctx, {"path": "n.md"}))

    def test_memory_errors_surface_as_tool_errors(self):
        with self.assertRaises(ToolError):
            memory_tools.memory_write(self.ctx, {"path": "../x.md", "content": "# a\nb"})

    def test_listing_empty_memory_is_not_an_error(self):
        self.assertIn("empty", memory_tools.memory_list(self.ctx, {}))

    def test_search_reports_no_matches_plainly(self):
        self.assertIn("No memory notes", memory_tools.memory_search(self.ctx, {"query": "zzz"}))


# ── The loop itself ───────────────────────────────────────────────────────────

class StubEngine:
    """An engine that replays scripted turns, so the loop can be tested offline.

    It records the `messages` list it was handed on each call, which is how the
    tests below assert on conversation shape — the thing that actually breaks
    the API when the harness gets it wrong.
    """

    def __init__(self, turns: list):
        self.turns = list(turns)
        self.calls: list[list[dict]] = []
        self.reviews: list[str] = []
        self.review_replies: list[str] = []

    def send(self, *, system, messages, tools=None, on_text=None, on_thinking=None):
        self.calls.append([dict(m) for m in messages])
        if not self.turns:
            raise AssertionError("the harness asked for more turns than were scripted")
        turn = self.turns.pop(0)
        if turn.text and on_text:
            on_text(turn.text)
        return turn

    def review(self, system, transcript):
        self.reviews.append(transcript)
        return self.review_replies.pop(0) if self.review_replies else "PASS"

    @staticmethod
    def replayable(content):
        return content


def _turn(*, text="", tools=(), stop_reason=None, refused=False, category=None):
    blocks = []
    if text:
        blocks.append(_block(type="text", text=text))
    blocks.extend(tools)
    if stop_reason is None:
        stop_reason = "tool_use" if tools else "end_turn"
    from jarvis.engine import Turn

    return Turn(
        message=_block(content=blocks),
        stop_reason=stop_reason,
        text=text,
        tool_calls=list(tools),
        refused=refused,
        refusal_category=category,
    )


def _call(name, args, call_id="tu_1"):
    return _block(type="tool_use", name=name, id=call_id, input=args)


class TestHarnessLoop(AgentTestCase):
    def build(self, turns: list) -> tuple:
        from jarvis.harness import UI, Harness

        engine = StubEngine(turns)
        toolbox = Toolbox(approve=lambda *a: True)
        toolbox.register_all(files_tools.build())
        toolbox.register_all(plan_tools.build())
        self.config.approval_mode = "auto"
        harness = Harness(self.config, engine, toolbox, self.memory, UI())
        return harness, engine

    def test_a_plain_answer_runs_no_tools(self):
        harness, engine = self.build([_turn(text="Nothing to do.")])
        result = harness.run_turn("hi")
        self.assertEqual(result.text, "Nothing to do.")
        self.assertEqual(result.tool_calls, 0)
        self.assertEqual(result.steps, 1)

    def test_a_tool_call_is_executed_and_the_loop_continues(self):
        self.write("data.txt", "hello world")
        harness, engine = self.build([
            _turn(tools=[_call("read_file", {"path": "data.txt"})]),
            _turn(text="The file says hello world."),
        ])
        result = harness.run_turn("what is in data.txt?")

        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(result.text, "The file says hello world.")
        # The tool actually ran: its output reached the second request.
        second_request = engine.calls[1]
        tool_results = second_request[-1]["content"]
        self.assertEqual(tool_results[0]["type"], "tool_result")
        self.assertIn("hello world", tool_results[0]["content"])
        self.assertFalse(tool_results[0]["is_error"])

    def test_a_tool_actually_changes_the_workspace(self):
        harness, _ = self.build([
            _turn(tools=[_call("write_file", {"path": "out.txt", "content": "written"})]),
            _turn(text="Done."),
        ])
        harness.run_turn("write a file")
        self.assertEqual((self.config.workspace / "out.txt").read_text(), "written")

    def test_parallel_calls_come_back_in_one_message(self):
        self.write("a.txt", "A")
        self.write("b.txt", "B")
        harness, engine = self.build([
            _turn(tools=[
                _call("read_file", {"path": "a.txt"}, "tu_1"),
                _call("read_file", {"path": "b.txt"}, "tu_2"),
            ]),
            _turn(text="Both read."),
        ])
        result = harness.run_turn("read both")

        self.assertEqual(result.tool_calls, 2)
        results_message = engine.calls[1][-1]
        self.assertEqual(results_message["role"], "user")
        self.assertEqual(len(results_message["content"]), 2)
        self.assertEqual(
            [r["tool_use_id"] for r in results_message["content"]], ["tu_1", "tu_2"]
        )

    def test_tool_use_blocks_are_preserved_in_history(self):
        self.write("x.txt", "x")
        harness, engine = self.build([
            _turn(text="Looking.", tools=[_call("read_file", {"path": "x.txt"})]),
            _turn(text="Done."),
        ])
        harness.run_turn("go")
        assistant = engine.calls[1][1]
        self.assertEqual(assistant["role"], "assistant")
        # The whole content list goes back — dropping the tool_use block would
        # make the following tool_result reference a message that does not exist.
        self.assertIn("tool_use", [getattr(b, "type", None) for b in assistant["content"]])

    def test_a_failing_tool_is_reported_and_the_loop_recovers(self):
        harness, engine = self.build([
            _turn(tools=[_call("read_file", {"path": "../escape.txt"})]),
            _turn(text="I cannot reach that path."),
        ])
        result = harness.run_turn("read outside")

        tool_result = engine.calls[1][-1]["content"][0]
        self.assertTrue(tool_result["is_error"])
        self.assertIn("outside the workspace", tool_result["content"])
        self.assertEqual(result.text, "I cannot reach that path.")

    def test_denied_approval_stops_the_side_effect(self):
        from jarvis.harness import UI, Harness

        engine = StubEngine([
            _turn(tools=[_call("write_file", {"path": "nope.txt", "content": "x"})]),
            _turn(text="Understood, I left it alone."),
        ])
        toolbox = Toolbox(approve=lambda tool, args, reason: False)
        toolbox.register_all(files_tools.build())
        self.config.approval_mode = "ask"
        harness = Harness(self.config, engine, toolbox, self.memory, UI())

        harness.run_turn("write it")
        self.assertFalse((self.config.workspace / "nope.txt").exists())
        self.assertTrue(engine.calls[1][-1]["content"][0]["is_error"])

    def test_the_step_budget_ends_a_runaway_loop(self):
        self.write("loop.txt", "x")
        self.config.max_steps = 3
        harness, engine = self.build([
            _turn(tools=[_call("read_file", {"path": "loop.txt"})]) for _ in range(3)
        ])
        result = harness.run_turn("spin forever")
        self.assertTrue(result.stopped_early)
        self.assertEqual(result.steps, 3)

    def test_a_refusal_ends_the_turn_without_running_tools(self):
        harness, engine = self.build([_turn(refused=True, stop_reason="refusal", category="cyber")])
        result = harness.run_turn("something disallowed")
        self.assertTrue(result.refused)
        self.assertIn("cyber", result.text)
        self.assertEqual(result.tool_calls, 0)

    def test_pause_turn_resumes_without_injecting_a_message(self):
        harness, engine = self.build([
            _turn(stop_reason="pause_turn"),
            _turn(text="Resumed and finished."),
        ])
        result = harness.run_turn("long server-side task")
        self.assertEqual(result.text, "Resumed and finished.")
        # Only the original user turn plus the paused assistant turn — nothing
        # was fabricated to nudge the model along.
        self.assertEqual([m["role"] for m in engine.calls[1]], ["user", "assistant"])

    def test_max_tokens_stops_the_loop_with_a_warning(self):
        from jarvis.harness import UI, Harness

        warnings: list[str] = []
        engine = StubEngine([_turn(text="Partial answer", stop_reason="max_tokens")])
        toolbox = Toolbox(approve=lambda *a: True)
        harness = Harness(
            self.config, engine, toolbox, self.memory, UI(on_warning=warnings.append)
        )
        result = harness.run_turn("write something enormous")
        self.assertEqual(result.text, "Partial answer")
        self.assertTrue(any("output token limit" in w for w in warnings))

    def test_the_plan_tool_updates_visible_state(self):
        harness, _ = self.build([
            _turn(tools=[_call("plan", {"steps": [
                {"title": "read the log", "status": "doing"},
                {"title": "summarise", "status": "todo"},
            ]})]),
            _turn(text="Planned."),
        ])
        harness.run_turn("make a plan")
        self.assertEqual(len(harness.plan.steps), 2)
        self.assertIn("[~] read the log", harness.plan.render())

    def test_the_system_prompt_is_built_once_and_stays_byte_identical(self):
        harness, engine = self.build([
            _turn(tools=[_call("plan", {"steps": [{"title": "a", "status": "todo"}]})]),
            _turn(text="ok"),
        ])
        before = harness.system[0]["text"]
        harness.run_turn("go")
        # A system prompt edited mid-session would invalidate the cached prefix
        # for the whole conversation on the next request.
        self.assertEqual(harness.system[0]["text"], before)
        self.assertEqual(harness.system[0]["cache_control"], {"type": "ephemeral"})

    def test_memory_digest_is_embedded_in_the_system_prompt(self):
        self.memory.write("projects/thing.md", "# A project the user maintains\nbody")
        harness, _ = self.build([_turn(text="hi")])
        self.assertIn("A project the user maintains", harness.system[0]["text"])

    def test_conversation_accumulates_across_turns(self):
        harness, engine = self.build([_turn(text="first"), _turn(text="second")])
        harness.run_turn("one")
        harness.run_turn("two")
        roles = [m["role"] for m in engine.calls[1]]
        self.assertEqual(roles, ["user", "assistant", "user"])

    def test_session_transcript_is_written(self):
        harness, _ = self.build([_turn(text="done")])
        harness.run_turn("hello")
        path = harness.save_session()
        self.assertIsNotNone(path)
        self.assertIn("hello", path.read_text(encoding="utf-8"))

    def test_verifier_is_off_by_default(self):
        harness, engine = self.build([_turn(text="done")])
        harness.run_turn("task")
        self.assertEqual(engine.reviews, [])

    def test_verifier_pass_leaves_the_answer_alone(self):
        self.config.max_verify_rounds = 1
        harness, engine = self.build([_turn(text="all done")])
        engine.review_replies = ["PASS"]
        result = harness.run_turn("task")
        self.assertEqual(result.text, "all done")
        self.assertEqual(len(engine.reviews), 1)

    def test_verifier_gaps_trigger_another_round(self):
        self.config.max_verify_rounds = 1
        harness, engine = self.build([
            _turn(text="half done"),
            _turn(text="now actually done"),
        ])
        engine.review_replies = ["GAPS\n- the second file was never written"]
        result = harness.run_turn("do two things")
        self.assertEqual(result.text, "now actually done")
        follow_up = engine.calls[-1][-1]
        self.assertEqual(follow_up["role"], "user")
        self.assertIn("automatic review", follow_up["content"])
        self.assertIn("the second file was never written", follow_up["content"])


# ── MCP: consuming remote servers ─────────────────────────────────────────────

class TestMcpClient(AgentTestCase):
    """Jarvis as an MCP client — remote servers' tools, no integration code."""

    def engine(self, **overrides):
        config = Config(home=self.tmp / "h", workspace=self.tmp / "w", **overrides)
        return Engine(config)

    def test_no_servers_configured_means_no_mcp_in_the_request(self):
        kwargs = self.engine()._kwargs("sys", [], [{"name": "read_file"}])
        self.assertNotIn("mcp_servers", kwargs)
        self.assertNotIn("mcp-client-2025-11-20", kwargs.get("betas", []))

    def test_configured_servers_produce_servers_toolsets_and_the_beta(self):
        engine = self.engine(mcp_servers=({"name": "gmail", "url": "https://x/sse"},))
        kwargs = engine._kwargs("sys", [], [{"name": "read_file"}])

        self.assertEqual(kwargs["mcp_servers"], [{"name": "gmail", "url": "https://x/sse"}])
        self.assertIn("mcp-client-2025-11-20", kwargs["betas"])
        # Every server must be referenced by exactly one toolset or the API
        # rejects the request outright.
        toolsets = [t for t in kwargs["tools"] if t.get("type") == "mcp_toolset"]
        self.assertEqual(toolsets, [{"type": "mcp_toolset", "mcp_server_name": "gmail"}])

    def test_local_tools_survive_alongside_mcp_toolsets(self):
        engine = self.engine(mcp_servers=({"name": "gmail", "url": "https://x/sse"},))
        kwargs = engine._kwargs("sys", [], [{"name": "scan_logs"}])
        self.assertIn({"name": "scan_logs"}, kwargs["tools"])

    def test_toolsets_are_emitted_in_a_stable_order(self):
        engine = self.engine(mcp_servers=(
            {"name": "zulip", "url": "https://z/sse"},
            {"name": "gmail", "url": "https://g/sse"},
        ))
        kwargs = engine._kwargs("sys", [], [])
        names = [t["mcp_server_name"] for t in kwargs["tools"] if t.get("type") == "mcp_toolset"]
        self.assertEqual(names, sorted(names))

    def test_an_mcp_rejection_drops_servers_and_toolsets_together(self):
        engine = self.engine(mcp_servers=({"name": "gmail", "url": "https://x/sse"},))
        kwargs = engine._kwargs("sys", [], [{"name": "read_file"}])

        chosen = Engine._next_degradation(
            types.SimpleNamespace(message="mcp_servers: beta not enabled"), kwargs, set()
        )
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen[0], "mcp_servers")

    def test_config_rejects_a_server_without_a_url(self):
        with self.assertRaises(ValueError):
            Config(home=self.tmp, mcp_servers=({"name": "gmail"},))

    def test_config_rejects_duplicate_server_names(self):
        with self.assertRaises(ValueError):
            Config(home=self.tmp, mcp_servers=(
                {"name": "gmail", "url": "https://a"}, {"name": "gmail", "url": "https://b"},
            ))

    def test_tokens_are_read_from_the_environment(self):
        os.environ["JARVIS_TEST_TOKEN"] = "s3cret"
        self.addCleanup(os.environ.pop, "JARVIS_TEST_TOKEN", None)

        config = Config(home=self.tmp, mcp_servers=({
            "name": "gmail", "url": "https://x", "authorization_token": "${JARVIS_TEST_TOKEN}",
        },))
        self.assertEqual(config.mcp_servers[0]["authorization_token"], "s3cret")

    def test_an_undefined_variable_fails_at_startup(self):
        # Better here than as a 401 from a server three steps into a task.
        with self.assertRaises(ValueError) as caught:
            Config(home=self.tmp, mcp_servers=({
                "name": "gmail", "url": "https://x", "authorization_token": "${NOT_SET_ANYWHERE}",
            },))
        self.assertIn("NOT_SET_ANYWHERE", str(caught.exception))


# ── MCP: serving our own tools ────────────────────────────────────────────────

class TestMcpServerToolset(unittest.TestCase):
    """What the MCP server advertises. An MCP server hands its tools to
    whatever connects, so the default set is the security-relevant decision."""

    def test_writes_are_excluded_by_default(self):
        from jarvis.mcp_server import build_toolbox

        names = build_toolbox(allow_writes=False).names()
        for mutating in ("write_file", "edit_file", "run_shell"):
            self.assertNotIn(mutating, names)

    def test_the_domain_tools_are_present(self):
        from jarvis.mcp_server import build_toolbox

        names = build_toolbox(allow_writes=False).names()
        self.assertIn("scan_logs", names)
        self.assertIn("scan_logs_json", names)

    def test_allow_writes_adds_the_mutating_tools(self):
        from jarvis.mcp_server import build_toolbox

        names = build_toolbox(allow_writes=True).names()
        self.assertIn("write_file", names)
        self.assertIn("run_shell", names)

    def test_declarations_match_the_agent_registry_exactly(self):
        # One source of truth: the MCP surface and the in-process agent must not
        # drift, or a tool means two different things depending on the door.
        from jarvis.cli import build_toolbox as agent_toolbox
        from jarvis.mcp_server import build_toolbox as mcp_toolbox

        agent = {d["name"]: d for d in agent_toolbox(Config(), lambda *a: True).definitions()}
        for definition in mcp_toolbox(allow_writes=False).definitions():
            with self.subTest(tool=definition["name"]):
                self.assertEqual(definition, agent[definition["name"]])


class TestMcpServerEndToEnd(unittest.TestCase):
    """Spawns the real server and speaks MCP to it over stdio."""

    def run_session(self, coro_body):
        try:
            import anyio
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError:  # pragma: no cover
            self.skipTest("mcp SDK not installed")

        async def main():
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "jarvis.mcp_server", "--workspace", "."],
                cwd=str(REPO_ROOT),
            )
            with anyio.fail_after(60):
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        return await coro_body(session)

        return anyio.run(main)

    def test_the_server_advertises_its_tools_over_the_protocol(self):
        result = self.run_session(lambda s: s.list_tools())
        names = sorted(t.name for t in result.tools)
        self.assertIn("scan_logs", names)
        self.assertNotIn("write_file", names)
        for tool in result.tools:
            self.assertTrue(tool.description)
            self.assertEqual(tool.input_schema["type"], "object")

    def test_a_scan_runs_through_the_protocol(self):
        result = self.run_session(
            lambda s: s.call_tool("scan_logs", {"path": "examples/ssh_bruteforce.log"})
        )
        self.assertFalse(result.is_error)
        self.assertIn("SSH Brute Force", result.content[0].text)

    def test_workspace_confinement_survives_the_mcp_layer(self):
        result = self.run_session(lambda s: s.call_tool("read_file", {"path": "/etc/passwd"}))
        self.assertTrue(result.is_error)
        self.assertIn("outside the workspace", result.content[0].text)

    def test_an_unknown_tool_is_an_error_not_a_crash(self):
        result = self.run_session(lambda s: s.call_tool("no_such_tool", {}))
        self.assertTrue(result.is_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)

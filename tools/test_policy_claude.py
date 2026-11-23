#!/usr/bin/env python3
"""Tests for the shared .claude/ rules in tools/policy_check.py (#169).

The pure rules are tested directly. What needs real git objects (symbolic links,
gitlinks, a CRLF-only or mode-only rewrite, the exit status under --enforce before
and after an approval) runs the checker as a child process in a throwaway repository,
the way `policy` and the corpus runner do. The corpus cannot hold those cases: its
runner copies trees without keeping links, and `spec_links` rejects links under
ci/corpus/.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc

ROOT = Path(__file__).resolve().parent.parent
OWNER, LANES = pc.load_lanes((ROOT / "ci/lanes.toml").read_text(encoding="utf-8"))
BLOB = "0" * 40


def entries(*paths, mode="100644"):
    return {p: (mode, BLOB) for p in paths}


class LaneRuleTests(unittest.TestCase):
    def test_claude_dir_is_lane_c_by_its_own_rule(self):
        # On main before #169 these were lane C only as "unclassified path".
        for path in (".claude/settings.json", ".claude/hooks/x.py", ".claude/handover/HANDOVER-x.md",
                     ".claude/skills/s/SKILL.md", ".claude/agents/a.md"):
            self.assertEqual(pc.lane_of(path, LANES), ("C", ".claude/**"), path)

    def test_codeowners_names_claude_dir(self):
        self.assertIn("/.claude/ ", pc.codeowners_text(OWNER, LANES))


class AgentConfigEscalationTests(unittest.TestCase):
    def test_nested_and_case_variant_config_escalates(self):
        for path in ("docs/CLAUDE.md", "web/.claude/skills/x/SKILL.md", "crates/x/AGENTS.md",
                     ".mcp.json", "examples/.mcp.json", "docs/claude.local.md", "CLAUDE.local.md",
                     ".Claude/settings.json", ".CLAUDE/hooks/x", "Agents.md", "claude.md",
                     "ci/corpus/invariants/x/tree/.claude/ship-state.md", "docs/ＣＬＡＵＤＥ.md"):
            found = pc.agent_config_escalations([path])
            self.assertEqual(len(found), 1, path)
            self.assertIn(path, found[0])

    def test_sanctioned_and_unrelated_paths_do_not(self):
        self.assertEqual(pc.agent_config_escalations(
            ["AGENTS.md", "CLAUDE.md", ".claude/settings.json", ".claude/handover/H.md",
             "docs/claude-notes.md", "web/agents.html", "tools/claims_check.py"]), [])

    def test_classify_raises_lane_and_says_why(self):
        empty = lambda path: None
        result = pc.classify(["docs/CLAUDE.md"], empty, empty, LANES)
        self.assertEqual(result["lane"], "C")
        self.assertTrue(any("agent config docs/CLAUDE.md" in e for e in result["escalations"]))


class ClaudePathTests(unittest.TestCase):
    def errors(self, tree, settings=None):
        return pc.claude_path_errors(tree, lambda path: settings)

    def test_allowed_regular_files_pass(self):
        tree = entries(".claude/hooks/guard.py", ".claude/skills/s/SKILL.md", ".claude/agents/a.md",
                       ".claude/handover/HANDOVER-2026-01-01-0000.md", "README.md", "docs/x.md")
        tree[".claude/hooks/run.sh"] = ("100755", BLOB)
        self.assertEqual(self.errors(tree, "---\nname: s\n---\n"), [])

    def test_off_the_list_fails(self):
        for path in (".claude/ship-state.md", ".claude/settings.local.json", ".claude/commands/x.md",
                     ".claude/output-styles/x.md", ".claude/tmp/x", ".claude/review-1-draft.md",
                     ".claude/hooks", ".claude/settings.json.bak"):
            found = self.errors(entries(path))
            self.assertEqual(len(found), 1, path)
            self.assertIn("allow-list", found[0])

    def test_case_variant_top_fails(self):
        for path in (".CLAUDE/x.md", ".Claude/settings.json", ".ｃｌａｕｄｅ/x"):
            found = self.errors(entries(path))
            self.assertEqual(len(found), 1, path)
            self.assertIn("case-insensitive", found[0])

    def test_links_fail_even_at_allowed_paths(self):
        for mode, word in (("120000", "symbolic link"), ("160000", "gitlink")):
            self.assertIn(word, self.errors(entries(".claude/hooks/x.py", mode=mode))[0])
            self.assertIn(word, self.errors(entries(".claude", mode=mode))[0])

    def test_nested_claude_is_left_to_classify(self):
        self.assertEqual(self.errors(entries("docs/.claude/ship-state.md", "web/.CLAUDE/x")), [])

    def test_settings_keys_are_allow_listed(self):
        tree = entries(".claude/settings.json")
        self.assertEqual(self.errors(tree, "{}"), [])
        for key in ("hooks", "env", "apiKeyHelper", "statusLine", "mcpServers", "enableAllProjectMcpServers",
                    "permissions", "awsAuthRefresh", "otelHeadersHelper"):
            found = self.errors(tree, json.dumps({key: {}}))
            self.assertEqual(len(found), 1, key)
            self.assertIn(repr(key), found[0])

    def test_settings_must_be_one_json_object(self):
        tree = entries(".claude/settings.json")
        for text in ("", "[]", "not json", '{"a": 1} trailing', '{"x": 1, "x": 2}'):
            found = self.errors(tree, text)
            self.assertEqual(len(found), 1, text)
            self.assertIn("is not a JSON object", found[0], text)


class HandoverRuleTests(unittest.TestCase):
    """Every departure from written-once handovers escalates with its own reason. The
    maintainer chose a flag for approval over a hard failure (#169)."""
    H = ".claude/handover/HANDOVER-1.md"
    A, B, C = "a" * 40, "b" * 40, "c" * 40

    def rules(self, paths, base, head, earlier=frozenset()):
        return pc.handover_escalations(paths, base, head, earlier)

    def test_unchanged_and_added_alone_raise_nothing(self):
        base = {self.H: ("100644", self.A)}
        head = dict(base, **{".claude/handover/HANDOVER-2.md": ("100644", self.B)})
        self.assertEqual(self.rules([".claude/handover/HANDOVER-2.md"], base, head), [])

    def test_bytes_or_mode_changed(self):
        base = {self.H: ("100644", self.A)}
        for head in ({self.H: ("100644", self.C)}, {self.H: ("100755", self.A)}):
            self.assertEqual(self.rules([self.H], base, head),
                             [f"handover {self.H} was changed: handovers are written once"])

    def test_rename_and_replace(self):
        base = {self.H: ("100644", self.A)}
        other = ".claude/handover/HANDOVER-1b.md"
        renamed = self.rules([self.H, other], base, {other: ("100644", self.A)})
        self.assertTrue(any("was renamed to " + other in v for v in renamed), renamed)
        # A rename with a one-byte edit is a removal plus an add: still flagged as a replacement.
        replaced = self.rules([self.H, other], base, {other: ("100644", self.B)})
        self.assertTrue(any("is not replaced" in v for v in replaced), replaced)

    def test_removal_alone(self):
        base = {self.H: ("100644", self.A)}
        self.assertEqual(self.rules([self.H], base, {}), [f"handover {self.H} was removed"])

    def test_identical_twin_removed_is_not_a_rename(self):
        twin = ".claude/handover/HANDOVER-2.md"
        base = {self.H: ("100644", self.A), twin: ("100644", self.A)}
        self.assertEqual(self.rules([self.H], base, {twin: ("100644", self.A)}), [f"handover {self.H} was removed"])

    def test_a_path_used_before(self):
        found = self.rules([self.H], {}, {self.H: ("100644", self.B)}, frozenset({pc._folded(self.H)}))
        self.assertEqual(found, [f"handover {self.H} existed before: a removed handover is not written again"])

    def test_handover_with_other_paths(self):
        head = {".claude/handover/H2.md": ("100644", self.B)}
        found = self.rules([".claude/handover/H2.md", "docs/x.md"], {}, head)
        self.assertEqual(found, ["a change that adds a handover also touches other paths: docs/x.md"])

    def test_classify_reports_them_as_escalations(self):
        empty = lambda path: None
        base = {self.H: ("100644", self.A)}
        result = pc.classify([self.H], empty, empty, LANES, handovers=(base, {self.H: ("100644", self.C)}))
        self.assertEqual(result["lane"], "C")
        self.assertEqual(result["escalations"], [f"handover {self.H} was changed: handovers are written once"])
        self.assertNotIn("violations", result)


class InsideClaudeTests(unittest.TestCase):
    """What the allowed files under .claude/ may contain (#169 review)."""

    def errors(self, files):
        tree = {path: ("100644", BLOB) for path in files}
        return pc.claude_path_errors(tree, files.get)

    def test_case_colliding_names_fail(self):
        found = self.errors({".claude/handover/HANDOVER-2026-01-01-0000.md": "a\n",
                             ".claude/handover/handover-2026-01-01-0000.md": "b\n"})
        self.assertTrue(any("same file" in e for e in found), found)

    def test_agent_names_inside_claude_fail_and_escalate(self):
        for path in (".claude/handover/CLAUDE.md", ".claude/skills/x/AGENTS.md", ".claude/skills/x/.claude/y",
                     ".claude/agents/.mcp.json"):
            self.assertTrue(any("not allowed inside" in e for e in self.errors({path: ""})), path)
            self.assertEqual(len(pc.agent_config_escalations([path])), 1, path)

    def test_windows_stripped_names_escalate(self):
        for path in ("docs/CLAUDE.md.", "docs/CLAUDE.md ", "docs/CLAUDE.md::$DATA", ".claude./x", "web/.mcp.json."):
            self.assertEqual(len(pc.agent_config_escalations([path])), 1, path)

    def test_handover_names_are_dated_and_flat(self):
        for path in (".claude/handover/notes.md", ".claude/handover/2026/HANDOVER-2026-01-01-0000.md",
                     ".claude/handover/HANDOVER-2026-01-01-0000.md.bak"):
            self.assertTrue(any("HANDOVER-YYYY-MM-DD-HHMM.md" in e for e in self.errors({path: ""})), path)
        self.assertEqual(self.errors({".claude/handover/HANDOVER-2026-11-21-1422.md": "x\n"}), [])

    def test_prompt_frontmatter_keys_are_allow_listed(self):
        ok = "---\nname: s\ndescription: d\n  more\ndisable-model-invocation: true\n---\nbody\n"
        self.assertEqual(self.errors({".claude/skills/s/SKILL.md": ok, ".claude/agents/a.md": ok}), [])
        for key in ("allowed-tools", "hooks", "model", "permissionMode", "mcpServers", "tools"):
            text = f"---\nname: s\n{key}: x\n---\n"
            found = self.errors({".claude/skills/s/SKILL.md": text})
            self.assertEqual(len(found), 1, key)
            self.assertIn(repr(key), found[0])

    def test_indented_root_keys_are_still_keys(self):
        # YAML allows an indented root mapping, so indentation does not hide a key.
        for text in ("---\n  allowed-tools: Bash\n---\n", "---\n  name: s\n  allowed-tools: Bash\n---\n",
                     "---\n    name: s\n  allowed-tools: Bash\n---\n", "---\n\tallowed-tools: Bash\n---\n"):
            found = self.errors({".claude/skills/s/SKILL.md": text})
            self.assertTrue(any("'allowed-tools'" in e or "tab" in e or "not a plain" in e for e in found), (text, found))
        self.assertEqual(self.errors({".claude/skills/s/SKILL.md": "---\n  name: s\n  description: d\n    more\n---\n"}), [])

    def test_unplain_or_unclosed_frontmatter_fails(self):
        for text in ("---\n? allowed-tools\n: Bash\n---\n", '---\n"allowed-tools": x\n---\n',
                     "---\n{allowed-tools: x}\n---\n", "---\nname: s\n"):
            found = self.errors({".claude/agents/a.md": text})
            self.assertTrue(any("not a plain `key: value`" in e or "not closed" in e for e in found), (text, found))

    def test_shell_injection_fails(self):
        for body in ("Run !`id` first.", "```!\nid\n```", "  ~~~ !\nid\n~~~"):
            found = self.errors({".claude/skills/s/x.md": "---\nname: s\n---\n" + body + "\n"})
            self.assertTrue(any("shell command" in e for e in found), body)
        self.assertEqual(self.errors({".claude/skills/s/x.md": "Use ! to negate, and `x != y`; ```sh\nls\n```\n"}), [])

    def test_settings_edge_cases_report_not_crash(self):
        deep = "[" * 20000 + "]" * 20000  # under the size cap; reported, whatever the parser's depth limit
        for text, phrase in ((deep, "is not a JSON object"), ('{"a": "' + "x" * (70 * 1024) + '"}', "larger than")):
            found = self.errors({".claude/settings.json": text})
            self.assertEqual(len(found), 1)
            self.assertIn(phrase, found[0])

    def test_carriage_returns_in_prompts_fail(self):
        # YAML reads a lone CR as a line break, so it would hide a second key.
        for text in ("---\nname: a\rallowed-tools: Bash(*)\n---\n", "---\r\nallowed-tools: Bash\r\n---\r\n"):
            found = self.errors({".claude/skills/s/SKILL.md": text})
            self.assertTrue(any("carriage return" in e for e in found), (text, found))

    def test_bom_does_not_hide_frontmatter(self):
        found = self.errors({".claude/skills/s/SKILL.md": "\ufeff---\nallowed-tools: Bash\n---\n"})
        self.assertTrue(any("'allowed-tools'" in e for e in found), found)

    def test_upper_case_md_is_a_prompt(self):
        found = self.errors({".claude/skills/s/SKILL.MD": "---\nallowed-tools: Bash\n---\n"})
        self.assertTrue(any("'allowed-tools'" in e for e in found), found)

    def test_names_must_open_as_written(self):
        for path in (".claude/skills/s/SKILL.md.", ".claude/agents/a.MD:x", ".claude/hooks/x ",
                     ".claude/skills/\u00e9/SKILL.md", ".claude/skills/s\u200d/SKILL.md"):
            found = self.errors({path: "---\nallowed-tools: Bash\n---\n"})
            self.assertEqual(len(found), 1, path)
            self.assertIn("plain ASCII", found[0], path)

    def test_format_characters_do_not_hide_names(self):
        found = self.errors({".cla\u200cude/settings.json": "{}"})
        self.assertTrue(any("case-insensitive" in e for e in found), found)
        self.assertEqual(len(pc.agent_config_escalations(["docs/CLA\u200dUDE.md"])), 1)

    def test_unreadable_prompt_is_an_error(self):
        tree = {".claude/agents/a.md": ("100644", BLOB)}
        def broken(path):
            raise ValueError("not UTF-8")
        self.assertTrue(any("cannot be read" in e for e in pc.claude_path_errors(tree, broken)))
        self.assertTrue(any("cannot be read" in e for e in pc.claude_path_errors(tree, lambda path: None)))

    def test_case_variant_of_an_earlier_handover(self):
        earlier = frozenset({pc._folded(".claude/handover/HANDOVER-2026-01-01-0000.md")})
        lower = ".claude/handover/handover-2026-01-01-0000.md"
        found = pc.handover_escalations([lower], {}, {lower: ("100644", BLOB)}, earlier)
        self.assertEqual(found, [f"handover {lower} existed before: a removed handover is not written again"])


class RepositoryTests(unittest.TestCase):
    """The checker as a black box in a throwaway repository."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        for key, value in (("user.email", "t@localhost"), ("user.name", "t"), ("commit.gpgsign", "false"),
                           ("core.autocrlf", "false")):
            self.git("config", key, value)
        for name in ("ci/lanes.toml", ".github/CODEOWNERS", "crates/containment-host/Cargo.toml",
                     "crates/containment-kernel/src/lib.rs", "tools/policy_check.py", "tools/rust_tokens.py"):
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, self.repo / name)
        self.write(".claude/handover/HANDOVER-2026-01-01-0000.md", "notes\n")
        self.base = self.commit("base")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True,
                              check=True).stdout

    def write(self, name, text, newline="\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline=newline)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def checker(self, *argv):
        child = subprocess.run([sys.executable, "-I", "-B", str(self.repo / "tools/policy_check.py"), *argv],
                               cwd=self.repo, capture_output=True, text=True, timeout=120)
        return child.returncode, json.loads(child.stdout[child.stdout.index("{"):]), child.stderr

    def invariants(self, head):
        code, result, _ = self.checker("invariants", "--ref", head)
        return code, result["errors"]

    def link(self, target, name):
        oid = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"], input=target,
                             capture_output=True, text=True, check=True).stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", f"120000,{oid},{name}")

    def test_base_passes(self):
        self.assertEqual(self.invariants(self.base), (0, []))

    def test_symlink_at_an_allowed_path_fails(self):
        self.link("../../docs/hook.py", ".claude/hooks/x.py")
        self.git("commit", "-q", "-m", "link")
        code, errors = self.invariants("HEAD")
        self.assertEqual(code, 1)
        self.assertTrue(any(".claude/hooks/x.py" in e and "symbolic link" in e for e in errors), errors)

    def test_claude_itself_as_a_symlink_fails(self):
        self.git("rm", "-r", "-q", "--cached", ".claude")
        shutil.rmtree(self.repo / ".claude")
        self.link("docs/agent", ".claude")
        self.git("commit", "-q", "-m", "link")
        code, errors = self.invariants("HEAD")
        self.assertEqual(code, 1)
        self.assertTrue(any(e.startswith(".claude: ") and "symbolic link" in e for e in errors), errors)

    def test_gitlink_fails(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},.claude/skills/x")
        self.git("commit", "-q", "-m", "gitlink")
        code, errors = self.invariants("HEAD")
        self.assertEqual(code, 1)
        self.assertTrue(any("gitlink" in e for e in errors), errors)

    def test_working_tree_reads_the_index_not_the_disk(self):
        self.write(".claude/ship-state.md", "local\n")
        self.write(".claude/tmp/x", "local\n")
        code, result, _ = self.checker("invariants")
        self.assertEqual((code, result["errors"]), (0, []))
        self.git("add", "-f", ".claude/ship-state.md")
        code, result, _ = self.checker("invariants")
        self.assertEqual(code, 1)
        self.assertTrue(any(".claude/ship-state.md" in e for e in result["errors"]), result)

    def classify(self, head, approve=False, enforce=False):
        argv = ["classify", "--base", self.base, "--head", head]
        if enforce and not approve:
            argv += ["--head-sha", head, "--enforce"]
        if approve:
            reviews = self.repo.parent / f"{self.repo.name}-reviews.json"
            reviews.write_text(json.dumps([{"user": {"login": OWNER.lstrip("@")}, "state": "APPROVED",
                                            "commit_id": head}]), encoding="utf-8")
            self.addCleanup(reviews.unlink)
            argv += ["--reviews", str(reviews), "--head-sha", head, "--enforce"]
        return self.checker(*argv)

    def flagged(self, head, reason):
        """Escalated with `reason`: refused under --enforce until approved, then passes."""
        code, result, stderr = self.classify(head, enforce=True)
        self.assertEqual((code, result["lane"], result["approved"]), (1, "C", False), stderr)
        self.assertIn(reason, result["escalations"])
        code, result, _ = self.classify(head, approve=True)
        self.assertEqual((code, result["approved"]), (0, True))

    def test_crlf_only_rewrite_is_flagged(self):
        self.write(".claude/handover/HANDOVER-2026-01-01-0000.md", "notes\n", newline="\r\n")
        self.flagged(self.commit("crlf"), "handover .claude/handover/HANDOVER-2026-01-01-0000.md was changed: handovers are written once")

    def test_mode_only_change_is_flagged(self):
        self.git("update-index", "--chmod=+x", ".claude/handover/HANDOVER-2026-01-01-0000.md")
        self.git("commit", "-q", "-m", "mode")
        self.flagged(self.git("rev-parse", "HEAD").strip(), "handover .claude/handover/HANDOVER-2026-01-01-0000.md was changed: handovers are written once")

    def test_recreating_a_removed_handover_is_flagged(self):
        self.git("rm", "-q", ".claude/handover/HANDOVER-2026-01-01-0000.md")
        self.base = self.commit("remove")
        self.write(".claude/handover/HANDOVER-2026-01-01-0000.md", "new words\n")
        self.flagged(self.commit("re-add"), "handover .claude/handover/HANDOVER-2026-01-01-0000.md existed before: a removed handover is not written again")

    def test_recreating_under_another_case_is_flagged(self):
        self.git("rm", "-q", ".claude/handover/HANDOVER-2026-01-01-0000.md")
        self.base = self.commit("remove")
        lower = ".claude/handover/handover-2026-01-01-0000.md"
        self.write(lower, "new words\n")
        self.flagged(self.commit("re-add"), f"handover {lower} existed before: a removed handover is not written again")

    def test_removed_handover_is_flagged(self):
        self.git("rm", "-q", ".claude/handover/HANDOVER-2026-01-01-0000.md")
        self.flagged(self.commit("remove"), "handover .claude/handover/HANDOVER-2026-01-01-0000.md was removed")

    def test_new_handover_alone_raises_nothing(self):
        self.write(".claude/handover/HANDOVER-2026-01-02-0000.md", "more\n")
        code, result, _ = self.classify(self.commit("add"), approve=True)
        self.assertEqual((code, result["lane"], result["escalations"]), (0, "C", []))


if __name__ == "__main__":
    unittest.main()

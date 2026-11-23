#!/usr/bin/env python3
"""Tests for the shared .claude/ rules in tools/policy_check.py (#169).

The pure rules are tested directly. What needs real git objects (symbolic links,
gitlinks, a CRLF-only or mode-only rewrite, the exit status of a violation that an
approval cannot clear) runs the checker as a child process in a throwaway repository,
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
        self.assertEqual(result["violations"], [])


class ClaudePathTests(unittest.TestCase):
    def errors(self, tree, settings=None):
        return pc.claude_path_errors(tree, lambda path: settings)

    def test_allowed_regular_files_pass(self):
        tree = entries(".claude/hooks/guard.py", ".claude/skills/s/SKILL.md", ".claude/agents/a.md",
                       ".claude/handover/H.md", "README.md", "docs/x.md")
        tree[".claude/hooks/run.sh"] = ("100755", BLOB)
        self.assertEqual(self.errors(tree), [])

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
            self.assertEqual(len(self.errors(tree, text)), 1, text)


class HandoverRuleTests(unittest.TestCase):
    H = ".claude/handover/HANDOVER-1.md"

    def test_unchanged_and_added_are_not_violations(self):
        base = {self.H: ("100644", "a" * 40)}
        head = dict(base, **{".claude/handover/HANDOVER-2.md": ("100644", "b" * 40)})
        self.assertEqual(pc.handover_violations(base, head), [])
        self.assertEqual(pc.handover_escalations([".claude/handover/HANDOVER-2.md"], base, head), [])

    def test_bytes_or_mode_changed_is_a_violation(self):
        base = {self.H: ("100644", "a" * 40)}
        for head in ({self.H: ("100644", "c" * 40)}, {self.H: ("100755", "a" * 40)}):
            self.assertEqual(pc.handover_violations(base, head), [f"handover {self.H} was changed: handovers are written once"])

    def test_rename_is_a_violation_and_removal_an_escalation(self):
        base = {self.H: ("100644", "a" * 40)}
        moved = {".claude/handover/OTHER.md": ("100644", "a" * 40)}
        self.assertIn("renamed", pc.handover_violations(base, moved)[0])
        self.assertEqual(pc.handover_escalations([self.H, ".claude/handover/OTHER.md"], base, moved), [])
        self.assertEqual(pc.handover_violations(base, {}), [])
        self.assertEqual(pc.handover_escalations([self.H], base, {}), [f"handover {self.H} was removed"])

    def test_handover_with_other_paths_escalates(self):
        head = {".claude/handover/H2.md": ("100644", "b" * 40)}
        found = pc.handover_escalations([".claude/handover/H2.md", "docs/x.md"], {}, head)
        self.assertEqual(found, ["a change that adds a handover also touches other paths: docs/x.md"])

    def test_violation_is_also_an_escalation(self):
        empty = lambda path: None
        base = {self.H: ("100644", "a" * 40)}
        result = pc.classify([self.H], empty, empty, LANES, handovers=(base, {self.H: ("100644", "c" * 40)}))
        self.assertEqual(result["lane"], "C")
        self.assertEqual(len(result["violations"]), 1)
        self.assertIn(result["violations"][0], result["escalations"])


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
        self.write(".claude/handover/H.md", "notes\n")
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

    def classify(self, head, approve=False):
        argv = ["classify", "--base", self.base, "--head", head]
        if approve:
            reviews = self.repo.parent / f"{self.repo.name}-reviews.json"
            reviews.write_text(json.dumps([{"user": {"login": OWNER.lstrip("@")}, "state": "APPROVED",
                                            "commit_id": head}]), encoding="utf-8")
            self.addCleanup(reviews.unlink)
            argv += ["--reviews", str(reviews), "--head-sha", head, "--enforce"]
        return self.checker(*argv)

    def test_crlf_only_rewrite_fails_even_when_approved(self):
        self.write(".claude/handover/H.md", "notes\n", newline="\r\n")
        head = self.commit("crlf")
        code, result, stderr = self.classify(head, approve=True)
        self.assertTrue(result["approved"])
        self.assertEqual(code, 1)
        self.assertEqual(result["violations"], ["handover .claude/handover/H.md was changed: handovers are written once"])
        self.assertIn("no approval clears", stderr)

    def test_mode_only_change_fails(self):
        self.git("update-index", "--chmod=+x", ".claude/handover/H.md")
        self.git("commit", "-q", "-m", "mode")
        code, result, _ = self.classify(self.git("rev-parse", "HEAD").strip(), approve=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(result["violations"]), 1)

    def test_new_handover_alone_passes_once_approved(self):
        self.write(".claude/handover/H2.md", "more\n")
        head = self.commit("add")
        code, result, _ = self.classify(head, approve=True)
        self.assertEqual((code, result["lane"], result["violations"], result["escalations"]), (0, "C", [], []))

    def test_removed_handover_needs_approval_only(self):
        self.git("rm", "-q", ".claude/handover/H.md")
        head = self.commit("remove")
        code, result, _ = self.classify(head, approve=True)
        self.assertEqual((code, result["violations"]), (0, []))
        self.assertIn("handover .claude/handover/H.md was removed", result["escalations"])
        code, result, _ = self.classify(head)
        self.assertEqual(code, 0)  # without --enforce an unapproved lane C change is reported, not failed
        self.assertFalse(result["approved"])


if __name__ == "__main__":
    unittest.main()

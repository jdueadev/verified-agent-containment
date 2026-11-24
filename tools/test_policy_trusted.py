#!/usr/bin/env python3
"""Tests for the trusted-author rule in tools/policy_check.py (#206).

A lane C change by an author on the lane map's `trusted` list needs no approval.
Everyone else, and every fork, still needs the owner's approval of the head.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc
import test_policy_check as tpc  # the module, not its classes, so its tests are not collected twice

ROOT = Path(__file__).resolve().parent.parent
LANES_TEXT = (ROOT / "ci/lanes.toml").read_text(encoding="utf-8")


class LoadTrustedTests(unittest.TestCase):
    def test_the_committed_list_parses_and_names_the_owner_and_the_agents(self):
        trusted = pc.load_trusted(LANES_TEXT)
        self.assertEqual(trusted, {"jdueadev", "jdueadev-agent", "claude", "vac-agent-app[bot]", "vac-lab-runner[bot]"})

    def test_a_missing_list_trusts_nobody(self):
        self.assertEqual(pc.load_trusted('owner = "@x"\n'), set())

    def test_a_malformed_list_is_refused(self):
        for bad in ('trusted = "@x"\n', 'trusted = ["x"]\n', 'trusted = ["@"]\n', "trusted = [1]\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pc.load_trusted(bad)

    def test_matching_ignores_case_and_the_at_sign_and_never_trusts_no_author(self):
        trusted = {"jdueadev-agent"}
        self.assertTrue(pc.is_trusted("JDueaDev-Agent", trusted))
        self.assertTrue(pc.is_trusted("@jdueadev-agent", trusted))
        self.assertFalse(pc.is_trusted("someone", trusted))
        self.assertFalse(pc.is_trusted("", trusted))
        self.assertFalse(pc.is_trusted(None, trusted))


class TrustedEnforceTests(unittest.TestCase):
    """`classify --enforce` end to end, with git replaced by fixed trees (as in test_policy_check)."""

    LANES_TEXT = LANES_TEXT
    run_classify = tpc.EnforceExitTests.run_classify

    def classify_with_commits(self, commits, author="jdueadev-agent", pinned=None):
        if pinned is None:
            pinned = {c["sha"] for c in pc.flat_commits(commits)}
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "commits.json"
            path.write_text(json.dumps(commits), encoding="utf-8")
            with mock.patch.object(pc, "pinned_commits", lambda base, head: seen.append((base, head)) or pinned):
                result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", author,
                                           "--commits", str(path), "--enforce", reviews=[])
        self.assertEqual(seen, [("b", "h")])
        return result

    def test_a_trusted_authors_lane_c_change_passes_without_approval(self):
        code, result = self.classify_with_commits([[commit("claude"), commit("jdueadev-agent")]])
        self.assertEqual((code, result["lane"], result["trusted"], result["needs_maintainer"]), (0, "C", True, False))

    def test_a_trusted_author_without_a_commit_list_still_needs_approval(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", "jdueadev-agent",
                                         "--enforce", reviews=[])
        self.assertEqual((code, result["trusted"], result["needs_maintainer"], result["not_trusted_because"]),
                         (1, False, True, "its commits were not given"))

    def test_a_commit_list_that_is_not_the_pinned_heads_needs_approval(self):
        listed = [[commit("claude", sha="a" * 40)]]
        for pinned in ({"b" * 40}, {"a" * 40, "b" * 40}, set()):
            with self.subTest(pinned=pinned):
                code, result = self.classify_with_commits(listed, pinned=pinned)
                self.assertEqual((code, result["trusted"], result["needs_maintainer"]), (1, False, True))
                self.assertIn("not the commits of the head", result["not_trusted_because"])

    def test_a_trusted_authors_change_with_an_untrusted_commit_needs_approval(self):
        code, result = self.classify_with_commits([[commit("claude"), commit("outside-person")]])
        self.assertEqual((code, result["trusted"], result["needs_maintainer"]), (1, False, True))
        self.assertIn("outside-person", result["not_trusted_because"])

    def test_an_untrusted_authors_lane_c_change_still_needs_approval(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", "outside-person",
                                         "--enforce", reviews=[])
        self.assertEqual((code, result["trusted"], result["needs_maintainer"], result["approved"]),
                         (1, False, True, False))

    def test_without_an_author_nobody_is_trusted(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--enforce", reviews=[])
        self.assertEqual((code, result["trusted"], result["needs_maintainer"]), (1, False, True))

    def test_a_fork_needs_approval_even_from_a_trusted_login(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", "jdueadev-agent",
                                         "--fork", "--enforce", reviews=[])
        self.assertEqual((code, result["needs_maintainer"]), (1, True))

    def test_the_trusted_list_comes_from_the_map_ref_not_the_head(self):
        added = LANES_TEXT.replace('trusted = [', 'trusted = ["@outside-person", ', 1)
        self.assertNotEqual(added, LANES_TEXT)
        base = dict(tpc.BASE, **{"ci/lanes.toml": LANES_TEXT})
        head = dict(tpc.BASE, **{"ci/lanes.toml": added})
        code, result = self.run_classify(["ci/lanes.toml"], "--map-ref", "m", "--head-sha", "h1",
                                         "--author", "outside-person", "--enforce", reviews=[],
                                         trees={"b": base, "h": head, "m": base})
        self.assertEqual((code, result["trusted"]), (1, False))

    def test_an_untrusted_author_with_a_fresh_approval_passes(self):
        approval = [{"user": {"login": "jdueadev"}, "state": "APPROVED", "commit_id": "h1"}]
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", "outside-person",
                                         "--enforce", reviews=approval)
        self.assertEqual((code, result["approved"]), (0, True))



def commit(author, committer=None, verified=True, sha="c" * 40):
    return {"sha": sha, "author": {"login": author}, "committer": {"login": committer or author},
            "commit": {"verification": {"verified": verified}}}


class TrustedCommitsTests(unittest.TestCase):
    TRUSTED = {"jdueadev", "claude"}

    def test_commits_by_trusted_logins_with_verified_signatures_are_trusted(self):
        for commits in ([commit("claude")], [[commit("claude")], [commit("jdueadev")]]):
            with self.subTest(commits=commits):
                self.assertIsNone(pc.untrusted_commits(commits, self.TRUSTED))

    def test_any_commit_that_does_not_prove_a_trusted_identity_is_refused(self):
        cases = {
            "not given": None,
            "not a list": {"sha": "x"},
            "empty": [],
            "an untrusted author": [commit("claude"), commit("outside-person")],
            "an untrusted committer": [commit("claude", committer="outside-person")],
            "no linked account": [{"sha": "x", "author": None, "committer": None,
                                   "commit": {"verification": {"verified": True}}}],
            "made through web-flow": [commit("jdueadev", committer="web-flow")],
            "unsigned": [commit("claude", verified=False)],
            "not an object": ["c" * 40],
            "too many to list": [commit("claude")] * pc.COMMIT_LIST_LIMIT,
        }
        for name, commits in cases.items():
            with self.subTest(name=name):
                self.assertIsNotNone(pc.untrusted_commits(commits, self.TRUSTED))

    def test_the_commit_list_must_be_exactly_the_expected_commits(self):
        listed = [commit("claude", sha="a" * 40), commit("jdueadev", sha="b" * 40)]
        self.assertIsNone(pc.untrusted_commits(listed, self.TRUSTED, {"b" * 40, "a" * 40}))
        for expected in ({"a" * 40}, {"a" * 40, "b" * 40, "d" * 40}, {"d" * 40, "e" * 40}):
            with self.subTest(expected=expected):
                self.assertIsNotNone(pc.untrusted_commits(listed, self.TRUSTED, expected))
        self.assertFalse(pc.approval_exempt("jdueadev", listed, self.TRUSTED, False, {"a" * 40})[0])

    def test_pinned_commits_are_git_rev_list_from_base_to_head(self):
        calls = []
        with mock.patch.object(pc, "git", lambda *a: calls.append(a) or "a" * 40 + "\n" + "b" * 40 + "\n"):
            self.assertEqual(pc.pinned_commits("base1", "head1"), {"a" * 40, "b" * 40})
        self.assertEqual(calls, [("rev-list", "base1..head1")])

    def test_a_trusted_change_needs_a_trusted_author_trusted_commits_and_no_fork(self):
        good = [commit("claude")]
        self.assertEqual(pc.approval_exempt("jdueadev", good, self.TRUSTED, False), (True, None))
        self.assertFalse(pc.approval_exempt("jdueadev", good, self.TRUSTED, True)[0])
        self.assertFalse(pc.approval_exempt("outside-person", good, self.TRUSTED, False)[0])
        self.assertFalse(pc.approval_exempt(None, good, self.TRUSTED, False)[0])
        self.assertFalse(pc.approval_exempt("jdueadev", [commit("outside-person")], self.TRUSTED, False)[0])


if __name__ == "__main__":
    unittest.main()

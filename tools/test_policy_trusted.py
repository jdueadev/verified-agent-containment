#!/usr/bin/env python3
"""Tests for the trusted-author rule in tools/policy_check.py (#206).

A lane C change by an author on the lane map's `trusted` list needs no approval.
Everyone else, and every fork, still needs the owner's approval of the head.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc
import test_policy_check as tpc  # the module, not its classes, so its tests are not collected twice

ROOT = Path(__file__).resolve().parent.parent
LANES_TEXT = (ROOT / "ci/lanes.toml").read_text(encoding="utf-8")


class LoadTrustedTests(unittest.TestCase):
    def test_the_committed_list_parses_and_names_the_owner_and_the_agents(self):
        trusted = pc.load_trusted(LANES_TEXT)
        self.assertEqual(trusted, {"jdueadev", "jdueadev-agent", "vac-agent-app[bot]", "vac-lab-runner[bot]"})

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

    def test_a_trusted_authors_lane_c_change_passes_without_approval(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--author", "jdueadev-agent",
                                         "--enforce", reviews=[])
        self.assertEqual((code, result["lane"], result["trusted"], result["needs_maintainer"]), (0, "C", True, False))

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


if __name__ == "__main__":
    unittest.main()

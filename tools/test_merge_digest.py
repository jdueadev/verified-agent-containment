#!/usr/bin/env python3
"""Unit tests for tools/merge_digest.py report. They classify real merge commits from
this repository's history (check.yml checks out the full history), with review data
supplied by the test, so each approval state has a case that produces it."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import merge_digest as md
import policy_check as pc

LANE_C = "c3facd1"   # #84: ci/lanes.toml, AGENTS.md, tools/ (lane C)
LANE_B = "33b909e"   # #81: crates/containment-kernel/src/lib.rs (lane B, claim R-DIFF-01)
BEFORE_MAP = "8923e6d"  # #58: introduced ci/lanes.toml, so its parent has none


def full(sha):
    return pc.git("rev-parse", sha).strip()


def pr(author="jdueadev-agent", head="h1", reviews=()):
    return {"number": 1, "title": "t", "author": author, "merged_by": "jdueadev", "head_sha": head,
            "reviews": list(reviews)}


def review(login, state, sha="h1"):
    return {"user": {"login": login}, "state": state, "commit_id": sha}


class AnalyzeTests(unittest.TestCase):
    def test_a_lane_c_merge_approved_at_its_head_is_approved(self):
        row = md.analyze({"sha": full(LANE_C), "pr": pr(reviews=[review("jdueadev", "APPROVED")])})
        self.assertEqual((row["lane"], row["approval"], row["alert"]), ("C", "approved", False))

    def test_a_lane_c_merge_approved_at_an_older_head_is_an_alert(self):
        row = md.analyze({"sha": full(LANE_C), "pr": pr(head="h2", reviews=[review("jdueadev", "APPROVED", "h1")])})
        self.assertEqual((row["approval"], row["alert"]), ("UNAPPROVED", True))

    def test_approval_by_someone_else_is_an_alert(self):
        row = md.analyze({"sha": full(LANE_C), "pr": pr(reviews=[review("jdueadev-agent", "APPROVED")])})
        self.assertEqual((row["approval"], row["alert"]), ("UNAPPROVED", True))

    def test_the_maintainers_own_lane_c_pr_is_a_bypass_merge_not_an_alert(self):
        row = md.analyze({"sha": full(LANE_C), "pr": pr(author="JDueaDev")})
        self.assertEqual((row["approval"], row["alert"]), ("maintainer merge (bypass)", False))

    def test_a_commit_with_no_pull_request_is_an_alert_in_any_lane(self):
        for sha in (LANE_C, LANE_B):
            with self.subTest(sha=sha):
                row = md.analyze({"sha": full(sha), "pr": None})
                self.assertEqual((row["approval"], row["alert"]), ("no pull request", True))

    def test_a_lane_b_merge_lists_its_claims_and_needs_no_approval(self):
        row = md.analyze({"sha": full(LANE_B), "pr": pr()})
        self.assertEqual((row["lane"], row["approval"], row["alert"]), ("B", "not needed", False))
        self.assertIn("R-DIFF-01", row["claims"])

    def test_the_lane_map_is_the_one_before_the_merge(self):
        # #84 put crates/containment-host/** in lane C. Judged by the map before it, a
        # host-only change is lane B, so the change that moves a path cannot escape review
        # by moving it first; a later change to that path is judged by the new map.
        parent_map = pc.reader(full(LANE_C) + "^")(pc.LANES_FILE)
        _, lanes = pc.load_lanes(parent_map)
        self.assertEqual(pc.lane_of("crates/containment-host/src/sandbox.rs", lanes)[0], "B")
        _, after = pc.load_lanes(pc.reader(full(LANE_C))(pc.LANES_FILE))
        self.assertEqual(pc.lane_of("crates/containment-host/src/sandbox.rs", after)[0], "C")

    def test_a_merge_before_the_lane_map_is_not_judged(self):
        row = md.analyze({"sha": full(BEFORE_MAP), "pr": pr()})
        self.assertEqual((row["lane"], row["alert"]), ("-", False))


class ReportTests(unittest.TestCase):
    def run_report(self, merges, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "merges.json"
            path.write_text(json.dumps(merges), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(md, "stale_now", lambda: ["CI-4 X-1: stale"]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = md.main(["report", str(path), *extra])
        return code, out.getvalue()

    def test_alerts_come_first_and_fail_only_when_asked(self):
        merges = [{"sha": full(LANE_C), "pr": pr()}, {"sha": full(LANE_B), "pr": pr()}]
        code, text = self.run_report(merges)
        self.assertEqual(code, 0)
        self.assertLess(text.index("## Alerts"), text.index("## Lane B merges"))
        self.assertIn("UNAPPROVED", text.split("## Lane B merges")[0])
        self.assertIn("R-DIFF-01", text)
        self.assertIn("CI-4 X-1: stale", text)
        code, _ = self.run_report(merges, "--fail-on-unapproved")
        self.assertEqual(code, 1)

    def test_a_clean_week_says_so_and_passes(self):
        merges = [{"sha": full(LANE_C), "pr": pr(reviews=[review("jdueadev", "APPROVED")])}]
        code, text = self.run_report(merges, "--fail-on-unapproved")
        self.assertEqual(code, 0)
        self.assertIn("None. Every lane C merge was approved", text)


if __name__ == "__main__":
    unittest.main()

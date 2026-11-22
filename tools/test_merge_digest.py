#!/usr/bin/env python3
"""Unit tests for tools/merge_digest.py report. They classify real merge commits from
this repository's history (check.yml checks out the full history), with review data
supplied by the test, so each approval state has a case that produces it."""
import contextlib
import html
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


def root_commit():
    return pc.git("rev-list", "--first-parent", "--max-parents=0", LANE_C).strip()


def pr(sha, author="jdueadev-agent", merged_by="jdueadev-agent", head=None, reviews=(), **extra):
    """A pull request that merged `sha`. Its head defaults to `sha` itself, whose tree is
    by definition the merged tree."""
    out = {"number": 1, "title": "t", "author": author, "merged_by": merged_by, "merged_at": "2026-11-22T00:00:00Z",
           "base": "main", "merge_commit_sha": sha, "head_sha": head or sha, "reviews": list(reviews)}
    out.update(extra)
    return out


def review(login, state, sha):
    return {"user": {"login": login}, "state": state, "commit_id": sha}


def commit(author="jdueadev", committer="jdueadev", verified=True):
    """One entry of GET /pulls/N/commits, reduced to the fields the digest reads."""
    return {"author": {"login": author}, "committer": {"login": committer},
            "commit": {"verification": {"verified": verified}}}


OWNERS_OWN = [[commit()]]  # as the API returns it with --slurp: a list of pages


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.c, self.b = full(LANE_C), full(LANE_B)

    def state(self, sha, pr_data, pulls=None):
        row = md.analyze({"sha": sha, "pr": pr_data, "pulls": pulls if pulls is not None else [1]})
        return row["approval"], row["alert"]

    def test_a_lane_c_merge_approved_at_its_head_is_approved(self):
        self.assertEqual(self.state(self.c, pr(self.c, reviews=[review("jdueadev", "APPROVED", self.c)])),
                         ("approved", False))

    def test_review_sequences(self):
        cases = {
            ("APPROVED", "DISMISSED"): ("UNAPPROVED", True),
            ("APPROVED", "CHANGES_REQUESTED"): ("UNAPPROVED", True),
            ("APPROVED", "COMMENTED"): ("approved", False),
        }
        for states, want in cases.items():
            with self.subTest(states=states):
                reviews = [review("jdueadev", s, self.c) for s in states]
                self.assertEqual(self.state(self.c, pr(self.c, reviews=reviews)), want)
        # As the API returns them with --slurp: a list of pages.
        pages = [[review("jdueadev", "APPROVED", self.c)], [review("jdueadev", "COMMENTED", self.c)]]
        self.assertEqual(self.state(self.c, pr(self.c, reviews=pages)), ("approved", False))

    def test_an_approval_of_an_older_head_or_by_someone_else_is_an_alert(self):
        self.assertEqual(self.state(self.c, pr(self.c, reviews=[review("jdueadev", "APPROVED", "0" * 40)])),
                         ("UNAPPROVED", True))
        self.assertEqual(self.state(self.c, pr(self.c, reviews=[review("jdueadev-agent", "APPROVED", self.c)])),
                         ("UNAPPROVED", True))

    def test_a_bypass_merge_needs_the_owner_as_author_and_merger(self):
        self.assertEqual(self.state(self.c, pr(self.c, author="JDueaDev", merged_by="jdueadev", commits=OWNERS_OWN)),
                         ("maintainer merge (bypass)", False))
        self.assertEqual(self.state(self.c, pr(self.c, author="jdueadev", merged_by="jdueadev-agent")),
                         ("UNAPPROVED", True))

    def test_a_bypass_merge_needs_every_commit_verified_as_the_owners(self):
        bad = "maintainer merge (bypass) of commits not proven to be the owner's"
        cases = {
            "no commits listed": [],
            "one commit by another identity": [[commit(), commit(author="jdueadev-agent", committer="jdueadev-agent")]],
            "the owner as author but someone else as committer": [[commit(committer="jdueadev-agent")]],
            "made in the web UI or through the API": [[commit(committer="web-flow")]],
            "unsigned": [[commit(verified=False)]],
            "a second page with a stranger": [[commit()], [commit(author="someone", committer="someone")]],
        }
        for name, commits in cases.items():
            with self.subTest(name=name):
                data = pr(self.c, author="jdueadev", merged_by="jdueadev", commits=commits)
                self.assertEqual(self.state(self.c, data), (bad, True))

    def test_the_merged_tree_must_be_the_approved_heads_tree(self):
        other = full(LANE_B)
        reviews = [review("jdueadev", "APPROVED", other)]
        self.assertEqual(self.state(self.c, pr(self.c, head=other, reviews=reviews)),
                         ("merged tree is not the pull request head's tree", True))

    def test_pull_request_data_must_match_the_merge(self):
        for extra in ({"merge_commit_sha": "f" * 40}, {"merged_at": None}, {"base": "release"}):
            with self.subTest(extra=extra):
                approval, alert = self.state(self.c, pr(self.c, **extra))
                self.assertEqual((approval, alert), ("pull request data does not match this merge", True))

    def test_no_pull_request_or_several_are_alerts_in_any_lane(self):
        for sha in (self.c, self.b):
            with self.subTest(sha=sha):
                self.assertEqual(self.state(sha, None, pulls=[]), ("no pull request", True))
                self.assertEqual(self.state(sha, None, pulls=[1, 2]), ("several pull requests", True))

    def test_a_lane_b_merge_lists_its_claims_and_needs_no_approval(self):
        row = md.analyze({"sha": self.b, "pr": pr(self.b), "pulls": [1]})
        self.assertEqual((row["lane"], row["approval"], row["alert"]), ("B", "not needed", False))
        self.assertIn("R-DIFF-01", row["claims"])

    def test_a_lane_b_merge_with_different_content_is_still_an_alert(self):
        self.assertEqual(self.state(self.b, pr(self.b, head=self.c)),
                         ("merged tree is not the pull request head's tree", True))

    def test_the_lane_map_is_the_one_before_the_merge(self):
        _, lanes = pc.load_lanes(pc.reader(self.c + "^")(pc.LANES_FILE))
        self.assertEqual(pc.lane_of("crates/containment-host/src/sandbox.rs", lanes)[0], "B")
        _, after = pc.load_lanes(pc.reader(self.c)(pc.LANES_FILE))
        self.assertEqual(pc.lane_of("crates/containment-host/src/sandbox.rs", after)[0], "C")

    def test_an_unreadable_claims_file_is_an_alert_not_a_crash(self):
        real = pc.reader

        def reader(ref):
            get = real(ref)
            return lambda path: "[[claim]\nid = " if path == "claims.toml" and ref == self.b else get(path)
        with mock.patch.object(md.policy_check, "reader", reader):
            row = md.analyze({"sha": self.b, "pr": pr(self.b), "pulls": [1]})
        self.assertTrue(row["alert"])
        self.assertIn("claims.toml at this merge cannot be read", row["approval"])

    def test_a_merge_before_the_lane_map_is_not_judged(self):
        row = md.analyze({"sha": full(BEFORE_MAP), "pr": pr(full(BEFORE_MAP)), "pulls": [1]})
        self.assertEqual((row["lane"], row["alert"]), ("-", False))

    def test_a_lost_lane_map_is_an_alert_not_a_free_pass(self):
        # The parent of a lane B merge, as if a merge before it had deleted ci/lanes.toml.
        real = pc.reader

        def reader(ref):
            get = real(ref)
            return lambda path: None if path == pc.LANES_FILE else get(path)
        with mock.patch.object(md.policy_check, "reader", reader):
            row = md.analyze({"sha": self.b, "pr": pr(self.b), "pulls": [1]})
            self.assertEqual((row["lane"], row["alert"]), ("-", True))
            self.assertIn("lane map is missing", row["approval"])
            row = md.analyze({"sha": self.b, "pr": None, "pulls": []})
            self.assertEqual((row["approval"], row["alert"]), ("no pull request", True))

    def test_a_merge_before_the_lane_map_still_needs_its_pull_request(self):
        sha = full(BEFORE_MAP)
        for data, pulls, want in ((None, [], "no pull request"), (None, [1, 2], "several pull requests"),
                                  (pr(sha, head=full(LANE_B)), [1], "merged tree is not the pull request head's tree")):
            with self.subTest(want=want):
                row = md.analyze({"sha": sha, "pr": data, "pulls": pulls})
                self.assertEqual((row["approval"], row["alert"]), (want, True))

    def test_a_parentless_commit_is_an_alert(self):
        sha = root_commit()
        pr_data = pr(sha)
        row = md.analyze({"sha": sha, "pr": pr_data, "pulls": [1]})
        self.assertEqual((row["sha"], row["pr"], row["lane"], row["alert"]), (sha, pr_data, "-", True))
        self.assertIn("first parent", row["approval"])


class CollectTests(unittest.TestCase):
    def collect(self, answers):
        calls = []

        def fake(*args):
            calls.append(args)
            return answers(args)
        with mock.patch.object(md, "gh_json", fake), mock.patch.object(md.time, "sleep", lambda s: None), \
                mock.patch.object(md, "fetch_pr_head", lambda number: None):
            return md.collect("o/r", commit=LANE_C), calls

    def test_only_a_pull_request_that_merged_this_commit_counts(self):
        sha = full(LANE_C)
        merges, _ = self.collect(lambda a: [{"number": 9, "merge_commit_sha": "f" * 40}] if "pulls" in a[0] else None)
        self.assertEqual((merges[0]["pr"], merges[0]["pulls"]), (None, []))

    def test_several_pull_requests_are_kept_as_several(self):
        sha = full(LANE_C)
        merges, _ = self.collect(lambda a: [{"number": 1, "merge_commit_sha": sha},
                                            {"number": 2, "merge_commit_sha": sha}] if a[0].endswith("/pulls") else None)
        self.assertEqual((merges[0]["pr"], merges[0]["pulls"]), (None, [1, 2]))

    def test_the_pull_requests_commits_are_collected(self):
        sha = full(LANE_C)

        def answers(a):
            if a[0].endswith("/pulls"):
                return [{"number": 7, "merge_commit_sha": sha}]
            if "/commits?" in a[-1]:
                return OWNERS_OWN
            if "/reviews?" in a[-1]:
                return [[]]
            return {"head": {"sha": sha}, "user": {"login": "jdueadev"}}
        merges, calls = self.collect(answers)
        self.assertEqual(merges[0]["pr"]["commits"], OWNERS_OWN)
        self.assertTrue(any(c[:2] == ("--paginate", "--slurp") and c[-1].startswith("repos/o/r/pulls/7/commits")
                            for c in calls))

    def test_an_empty_lookup_is_retried(self):
        merges, calls = self.collect(lambda a: [] if a[0].endswith("/pulls") else None)
        self.assertEqual(sum(1 for c in calls if c[0].endswith("/pulls")), 4)
        self.assertIsNone(merges[0]["pr"])


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
        merges = [{"sha": full(LANE_C), "pr": pr(full(LANE_C)), "pulls": [1]},
                  {"sha": full(LANE_B), "pr": pr(full(LANE_B)), "pulls": [1]}]
        code, text = self.run_report(merges)
        self.assertEqual(code, 0)
        self.assertLess(text.index("## Alerts"), text.index("## Lane B merges"))
        self.assertIn("UNAPPROVED", text.split("## Lane B merges")[0])
        self.assertIn("R-DIFF-01", text)
        self.assertIn("CI-4 X-1: stale", text)
        code, _ = self.run_report(merges, "--fail-on-unapproved")
        self.assertEqual(code, 1)

    def test_pull_request_text_cannot_hide_or_forge_rows(self):
        hostile = 'x <!-- | @jdueadev [None.](http://e) **ok**\n## Alerts'
        merges = [{"sha": full(LANE_C), "pulls": [1], "pr": pr(full(LANE_C), title=hostile)}]
        _, text = self.run_report(merges)
        for raw in ("<!--", "@jdueadev", "](", "**ok", "\n## Alerts\n\nNone"):
            self.assertNotIn(raw, text.split("## Lane B")[0].replace("## Alerts\n\nThese", ""), raw)
        self.assertEqual(text.count("\n## Alerts"), 0 if text.startswith("## Alerts") else 1)

    def test_pull_request_text_cannot_mention_reference_or_link(self):
        hostile = "ping @octocat, see #1, o/r#2 and GH-3, at https://e.com or www.e.com, mail a@b.com"
        merges = [{"sha": full(LANE_C), "pulls": [1], "pr": pr(full(LANE_C), title=hostile)}]
        _, text = self.run_report(merges)
        lines = [line for line in text.splitlines() if "ping" in line]
        self.assertEqual(len(lines), 2)  # the alert and the lane C row
        # Read it as GitHub renders it: entities decoded, the digest's own "#1 " link removed.
        shown = html.unescape("\n".join(lines)).replace("**#1 ", "**").replace("| #1 ", "| ")
        self.assertIn("ping", shown)
        self.assertNotRegex(shown, r"[@#]\w")
        self.assertNotRegex(shown, r"(?i)gh-\w")
        for raw in ("://", "www."):
            self.assertNotIn(raw, shown)

    def test_stale_rows_say_which_commit_they_describe(self):
        _, text = self.run_report([])
        self.assertIn("## Stale rows at `", text)
        self.assertNotIn("Stale rows on main now", text)

    def test_a_clean_week_says_so_and_passes(self):
        merges = [{"sha": full(LANE_C), "pulls": [1],
                   "pr": pr(full(LANE_C), reviews=[review("jdueadev", "APPROVED", full(LANE_C))])}]
        code, text = self.run_report(merges, "--fail-on-unapproved")
        self.assertEqual(code, 0)
        self.assertIn("None. Every lane C merge was approved", text)

    def test_report_includes_other_merges_after_a_parentless_commit(self):
        root, lane_b = root_commit(), full(LANE_B)
        merges = [{"sha": root, "pr": None, "pulls": []},
                  {"sha": lane_b, "pr": pr(lane_b), "pulls": [1]}]
        code, text = self.run_report(merges, "--fail-on-unapproved")
        self.assertEqual(code, 1)
        alerts, rest = text.split("## Lane B merges", 1)
        self.assertIn(root[:7], alerts)
        self.assertIn("first parent", alerts)
        self.assertIn(lane_b[:7], rest)
        self.assertIn("R-DIFF-01", rest)


if __name__ == "__main__":
    unittest.main()

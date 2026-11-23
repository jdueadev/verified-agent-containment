#!/usr/bin/env python3
"""Unit tests for the corpus runner's `approval` kind (#149, PR 1).

The checker side, `policy_check.py fresh-reviews`, does not exist yet. These tests give
the runner a head whose policy_check.py is a stub: it answers fresh-reviews itself and
runs an embedded copy of this checkout's real policy_check.py for everything else. They
show that every way an approval case can come out wrong fails it: a checker that keeps
a stale approval, one that keeps nothing, one without fresh-reviews, a crash, a refusal
for the wrong reason or in the wrong form, unreadable output, a lane that is not C, and
inputs the runner would not pass on. Nothing here depends on the real checker gaining
or lacking fresh-reviews."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import corpus_run as cr
from test_corpus_run import head_copy, write_case

ROOT = TOOLS.parent

# fresh-reviews in the stub: a review counts only when it was submitted after the
# newest push of the head, read from --activity. Without --activity it refuses. The
# settings line switches in one fault at a time.
STUB = '''import json
import sys
from pathlib import Path

REAL = @REAL@
KEEP_ALL = False
KEEP_NONE = False
OUTPUT = json.dumps
HAS_FRESH = True
CRASH = False
PREFIX = "fresh-reviews: "
@SETTINGS@

def fresh(argv):
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--head-sha", required=True)
    p.add_argument("--reviews", required=True)
    p.add_argument("--activity")
    a, _ = p.parse_known_args(argv)
    reviews = json.loads(Path(a.reviews).read_text(encoding="utf-8"))
    if not a.activity:
        if CRASH:
            raise KeyError("no arrival time")
        sys.exit(PREFIX + "no activity, so no arrival time")
    pushes = [e["timestamp"] for e in json.loads(Path(a.activity).read_text(encoding="utf-8"))
              if e.get("after") == a.head_sha]
    arrived = max(pushes) if pushes else None
    kept = []
    for r in reviews:
        r = dict(r)
        if not KEEP_ALL and (KEEP_NONE or arrived is None or not r.get("submitted_at", "") > arrived):
            r["commit_id"] = None
        kept.append(r)
    print(OUTPUT(kept))
    return 0


if sys.argv[1:2] == ["fresh-reviews"]:
    if not HAS_FRESH:
        sys.stderr.write("usage: policy_check.py [-h] {classify,codeowners,invariants} ...\\n"
                         "policy_check.py: error: argument command: invalid choice: 'fresh-reviews'"
                         " (no arrival time)\\n")
        sys.exit(2)
    sys.exit(fresh(sys.argv[2:]))
exec(compile(REAL, __file__, "exec"), {"__name__": "__main__", "__file__": __file__})
'''

OWNER_REVIEW = {"user": {"login": "jdueadev"}, "state": "APPROVED", "commit_id": "@HEAD@"}
PUSH = [{"after": "@HEAD@", "timestamp": "2026-11-22T23:06:16Z", "activity_type": "push"}]
LANE_C = {"base/AGENTS.md": "a\n", "head/AGENTS.md": "b\n"}


def review(submitted_at):
    return json.dumps([dict(OWNER_REVIEW, submitted_at=submitted_at)])


STALE = {**LANE_C, "inputs/reviews.json": review("2026-11-22T04:59:19Z"), "inputs/activity.json": json.dumps(PUSH)}
FRESH_AFTER = {**LANE_C, "inputs/reviews.json": review("2026-11-22T23:10:00Z"), "inputs/activity.json": json.dumps(PUSH)}
NO_ACTIVITY = {**LANE_C, "inputs/reviews.json": review("2026-11-22T23:10:00Z")}


def case(expect, twin=None, error=None):
    text = f'checker = "approval"\norigin = "test"\nexpect = "{expect}"\n'
    if twin:
        text += f'twin = "{twin}"\n'
    if error:
        text += f'expect_error = "{error}"\n'
    return text


def stub_head(tmp, settings=""):
    head = head_copy(tmp)
    gate = head / "tools/policy_check.py"
    real = gate.read_text(encoding="utf-8")
    gate.write_text(STUB.replace("@REAL@", repr(real)).replace("@SETTINGS@", settings), encoding="utf-8")
    return head


class ApprovalKindTests(unittest.TestCase):
    def failures(self, build, settings=""):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "corpus"
            corpus.mkdir()
            build(corpus)
            return cr.run(stub_head(tmp, settings), corpus)["failed"]

    @staticmethod
    def pair(corpus):
        write_case(corpus, "approval/stale", case("reject", twin="fresh"), STALE)
        write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)

    @classmethod
    def trio(cls, corpus):
        cls.pair(corpus)
        write_case(corpus, "approval/no-activity", case("refuse", twin="fresh", error="no arrival time"), NO_ACTIVITY)

    def test_a_checker_that_drops_stale_approvals_passes_every_kind(self):
        self.assertEqual(self.failures(self.trio), {})

    def test_a_checker_that_keeps_a_stale_approval_fails_the_reject_case(self):
        failed = self.failures(self.pair, "KEEP_ALL = True")
        self.assertEqual(list(failed), ["approval/stale"])
        self.assertIn("approved is True, expected False", failed["approval/stale"])

    def test_a_checker_that_keeps_nothing_fails_the_accept_twin(self):
        failed = self.failures(self.pair, "KEEP_NONE = True")
        self.assertEqual(list(failed), ["approval/fresh"])
        self.assertIn("approved is False, expected True", failed["approval/fresh"])

    def test_a_checker_without_fresh_reviews_fails_every_kind(self):
        # Its argparse error even contains the refuse case's expect_error.
        failed = self.failures(self.trio, "HAS_FRESH = False")
        self.assertEqual(sorted(failed), ["approval/fresh", "approval/no-activity", "approval/stale"])
        self.assertIn("fresh-reviews failed", failed["approval/stale"])
        self.assertIn("did not refuse", failed["approval/no-activity"])
        self.assertIn("exit 2", failed["approval/no-activity"])

    def test_a_crash_is_not_a_refusal(self):
        failed = self.failures(self.trio, "CRASH = True")
        self.assertEqual(list(failed), ["approval/no-activity"])
        self.assertIn("did not refuse", failed["approval/no-activity"])

    def test_a_refusal_without_the_prefix_is_not_a_refusal(self):
        failed = self.failures(self.trio, 'PREFIX = ""')
        self.assertEqual(list(failed), ["approval/no-activity"])

    def test_a_refusal_must_give_the_expected_reason(self):
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            write_case(corpus, "approval/right", case("refuse", twin="fresh", error="no arrival time"), NO_ACTIVITY)
            write_case(corpus, "approval/wrong", case("refuse", twin="fresh", error="rate limited"), NO_ACTIVITY)
            write_case(corpus, "approval/kept", case("refuse", twin="fresh", error="no arrival time"), FRESH_AFTER)
        failed = self.failures(build)
        self.assertEqual(sorted(failed), ["approval/kept", "approval/wrong"])
        self.assertIn("rate limited", failed["approval/wrong"])
        self.assertIn("expected fresh-reviews to refuse", failed["approval/kept"])

    def test_output_that_is_not_a_json_list_fails(self):
        failed = self.failures(self.pair, 'OUTPUT = lambda kept: json.dumps({"kept": kept})')
        self.assertEqual(sorted(failed), ["approval/fresh", "approval/stale"])
        self.assertIn("no JSON list", failed["approval/stale"])

    def test_a_change_that_is_not_lane_c_fails(self):
        # Also shows the inputs stay out of the change: inputs/ is a path the lane map
        # does not list, so if it were in the diff the case would be lane C.
        lane_a = {"base/docs/x.md": "a\n", "head/docs/x.md": "b\n"}
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            write_case(corpus, "approval/lane-a", case("accept"),
                       {**lane_a, "inputs/reviews.json": review("2026-11-22T23:10:00Z"),
                        "inputs/activity.json": json.dumps(PUSH)})
            write_case(corpus, "approval/lane-a-refuse", case("refuse", twin="fresh", error="no arrival time"),
                       {**lane_a, "inputs/reviews.json": review("2026-11-22T23:10:00Z")})
        failed = self.failures(build)
        self.assertEqual(sorted(failed), ["approval/lane-a", "approval/lane-a-refuse"])
        self.assertIn("must be lane C", failed["approval/lane-a"])
        self.assertIn("must be lane C", failed["approval/lane-a-refuse"])

    def test_only_well_named_regular_json_files_are_inputs(self):
        bad = {"typo": "inputs/activity.jsn", "upper": "inputs/Activity.json", "nested": "inputs/x/activity.json",
               "flag": "inputs/head-sha.json"}
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            for name, path in bad.items():
                write_case(corpus, f"approval/{name}", case("accept"), {**FRESH_AFTER, path: "[]"})
            write_case(corpus, "approval/link", case("accept"), FRESH_AFTER)
            os.symlink(corpus / "approval/fresh/inputs/activity.json", corpus / "approval/link/inputs/more.json")
        failed = self.failures(build)
        self.assertEqual(sorted(failed), sorted([f"approval/{n}" for n in bad] + ["approval/link"]))
        for problem in failed.values():
            self.assertIn("is not an input", problem)

    def test_a_case_without_reviews_fails(self):
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            write_case(corpus, "approval/empty", case("accept"), {**LANE_C, "inputs/activity.json": json.dumps(PUSH)})
        self.assertIn("needs inputs/reviews.json", self.failures(build)["approval/empty"])

    def test_a_bad_expectation_fails_before_it_runs(self):
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            write_case(corpus, "approval/maybe", case("maybe"), FRESH_AFTER)
            write_case(corpus, "approval/refuse-why", case("refuse", twin="fresh"), FRESH_AFTER)
        failed = self.failures(build)
        self.assertEqual(sorted(failed), ["approval/maybe", "approval/refuse-why"])
        self.assertIn("expect = accept, reject or refuse", failed["approval/maybe"])

    def test_reject_and_refuse_cases_need_an_accept_twin(self):
        def build(corpus):
            write_case(corpus, "approval/fresh", case("accept"), FRESH_AFTER)
            write_case(corpus, "approval/stale", case("reject", twin="missing"), STALE)
            write_case(corpus, "approval/no-activity", case("refuse", twin="stale", error="no arrival time"),
                       NO_ACTIVITY)
        failed = self.failures(build)
        self.assertIn("needs an accept twin", failed["approval/stale"])
        self.assertIn("needs an accept twin", failed["approval/no-activity"])


class StagingTests(unittest.TestCase):
    # These hold both while approval is staged and after it moves into CHECKERS.
    def test_the_runner_knows_approval(self):
        self.assertIn("approval", cr.KINDS)

    def test_staged_kinds_are_known_but_not_checkers(self):
        self.assertFalse(set(cr.STAGED) & set(cr.CHECKERS))
        self.assertEqual(cr.KINDS, cr.CHECKERS + cr.STAGED)

    def test_a_staged_kind_with_real_cases_must_move_into_checkers(self):
        # Once the corpus has a case of a staged kind, that kind belongs in CHECKERS,
        # where the real-corpus test requires it to keep having cases.
        for kind in cr.STAGED:
            cases = sorted((ROOT / "ci/corpus").glob(f"{kind}/*/case.toml"))
            self.assertEqual(cases, [], f"ci/corpus has {kind} cases: move {kind!r} from STAGED into CHECKERS")


if __name__ == "__main__":
    unittest.main()

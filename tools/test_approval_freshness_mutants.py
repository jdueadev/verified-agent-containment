#!/usr/bin/env python3
"""Seeded weakenings of approval freshness (#149). mutation_check.py covers the kernel
only, so these tests weaken the real tools/policy_check.py and tools/gate_check.py one
rule at a time, each by an exact edit that must apply once, and require that at least
one case that must not approve then approves. A weakening no case notices means the
tests do not hold that rule.

The corpus is run too: a weakening of the rule the #93 case rests on must make
approval/carried-over-93 fail under the corpus runner."""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import corpus_run as cr
import gate_check as gc
import policy_check as pc
import test_gate_approval_freshness as gate_tests
from test_approval_freshness import HEAD, OTHER, OWNER, corpus_inputs, owner_review
from test_corpus_run import head_copy

ROOT = TOOLS.parent


def weakened(module, old, new):
    path = Path(module.__file__)
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"{path.name}: the edit no longer applies: {old!r}"
    mod = types.ModuleType(module.__name__ + "_weakened")
    mod.__file__ = str(path)
    exec(compile(text.replace(old, new), str(path), "exec"), mod.__dict__)
    return mod


def must_not_approve():
    """(name, inputs) for cases that must not approve the head."""
    cases = [("carried-over-93", corpus_inputs("carried-over-93"))]

    def fresh147(change):
        data = corpus_inputs("fresh-after-push-147")
        change(data)
        return data

    def same_second(d):
        d["reviews"][0]["submitted_at"] = "2026-11-22T22:16:44Z"

    def lagging(d):
        d["activity"][0]["after"] = OTHER

    def reopened_after(d):
        d["timeline"].append({"event": "reopened", "created_at": "2026-11-22T22:30:00Z"})

    def other_ref_only(d):
        d["activity"] = [dict(d["activity"][0], ref="refs/heads/seed")]

    def before_pr_created(d):
        d["reviews"][0]["submitted_at"] = "2026-11-22T22:16:30Z"

    def no_review_time(d):
        del d["reviews"][0]["submitted_at"]

    def a_b_a(d):
        ref = d["activity"][0]["ref"]
        d["activity"] = [{"ref": ref, "after": HEAD, "timestamp": "2026-11-22T22:25:00Z"},
                         {"ref": ref, "after": OTHER, "timestamp": "2026-11-22T22:23:00Z"}] + d["activity"]

    def oldest_first(d):
        ref = d["activity"][0]["ref"]
        d["activity"] += [{"ref": ref, "after": OTHER, "timestamp": "2026-11-22T22:23:00Z"},
                          {"ref": ref, "after": HEAD, "timestamp": "2026-11-22T22:25:00Z"}]

    for change in (oldest_first, same_second, lagging, reopened_after, other_ref_only, before_pr_created, no_review_time, a_b_a):
        cases.append((change.__name__, fresh147(change)))
    stale_then_fresh_comment = corpus_inputs("carried-over-93")
    stale_then_fresh_comment["reviews"].append(owner_review("COMMENTED", "2026-11-22T23:10:00Z"))
    cases.append(("stale-then-fresh-comment", stale_then_fresh_comment))
    return cases


def approvals(mod):
    out = []
    for name, data in must_not_approve():
        kept, _ = mod.review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], HEAD)
        if mod.approved(kept, OWNER, HEAD):
            out.append(name)
    return out


POLICY_WEAKENINGS = {
    "fresh_reviews keeps every review": (
        "        out.append(dict(review) if fresh else dict(review, commit_id=None))\n",
        "        out.append(dict(review))\n"),
    "a review in the arrival's second counts": (
        "submitted is not None and submitted > arrived_at\n",
        "submitted is not None and submitted >= arrived_at\n"),
    "an unknown arrival counts as fresh": (
        "        fresh = arrived_at is not None and submitted is not None and submitted > arrived_at\n",
        "        fresh = arrived_at is None or (submitted is not None and submitted > arrived_at)\n"),
    "the earliest arrival is used": (
        "    return max(candidates), None\n",
        "    return min(candidates), None\n"),
    "a lagging log is believed": (
        "    if pushes[0].get(\"after\") != head_sha:\n",
        "    if False:\n"),
    "the timeline is ignored": (
        "            candidates.append(github_time(event.get(\"created_at\")))\n",
        "            pass\n"),
    "another ref's push counts": (
        "        if not isinstance(entry, dict) or entry.get(\"ref\") != ref:\n",
        "        if not isinstance(entry, dict):\n"),
    "the PR's creation is ignored": (
        "    candidates = [times[0], github_time(pr.get(\"created_at\"))]\n",
        "    candidates = [times[0]]\n"),
    "a log in any order is believed": (
        "    if None in times or any(t > times[0] for t in times):\n",
        "    if None in times:\n"),
    "a review without a time counts": (
        "        submitted = github_time(review.get(\"submitted_at\"))\n",
        "        submitted = github_time(review.get(\"submitted_at\")) or datetime.datetime.max\n"),
}


class PolicyWeakenings(unittest.TestCase):
    def test_the_real_checker_approves_none_of_them(self):
        self.assertEqual(approvals(pc), [])

    def test_the_real_checker_approves_147(self):
        data = corpus_inputs("fresh-after-push-147")
        kept, _ = pc.review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], HEAD)
        self.assertTrue(pc.approved(kept, OWNER, HEAD))

    def test_each_weakening_approves_a_case_it_must_not(self):
        for name, (old, new) in POLICY_WEAKENINGS.items():
            with self.subTest(name):
                self.assertNotEqual(approvals(weakened(pc, old, new)), [], name)

    def test_the_corpus_catches_the_weakenings_93_rests_on(self):
        for name in ("fresh_reviews keeps every review", "the earliest arrival is used"):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                failed = cr.run(head_copy(tmp, [POLICY_WEAKENINGS[name]]), ROOT / "ci/corpus")["failed"]
                self.assertIn("approval/carried-over-93", failed)
                self.assertNotIn("approval/fresh-after-push-147", failed)


class GateWeakenings(unittest.TestCase):
    def run_93(self, module):
        case = gate_tests.Judge("test_93_with_a_github_change_fails_every_run_context")
        case.setUp()
        try:
            with mock.patch.object(gate_tests, "gc", module):
                verdicts, _ = case.judge(gate_tests.corpus_inputs("carried-over-93"), [".github/workflows/check.yml"])
        finally:
            case.doCleanups()
        return verdicts["gate/check"]["conclusion"]

    def test_the_real_gate_fails_93(self):
        self.assertEqual(self.run_93(gc), "failure")

    def test_a_gate_that_passes_the_unfiltered_reviews_on_passes_93(self):
        mod = weakened(gc, "    reviews, void = policy_check.review_freshness(reviews, activity, pr, timeline, head_sha)\n",
                       "    _, void = policy_check.review_freshness(reviews, activity, pr, timeline, head_sha)\n")
        self.assertEqual(self.run_93(mod), "success")


if __name__ == "__main__":
    unittest.main()

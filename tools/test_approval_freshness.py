#!/usr/bin/env python3
"""Unit tests for approval freshness in tools/policy_check.py (#149).

An owner approval counts for a head only if it was submitted strictly after the head
arrived on the pull request, judged on server time. These tests drive
`review_freshness` and then the unchanged `approved()` on what it keeps, starting from
the real #93 (carried over, must not count) and #147 (fresh, must count) inputs in
ci/corpus/approval/."""
import copy
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import policy_check as pc

ROOT = TOOLS.parent
HEAD = "1" * 40
BASE = "2" * 40
OTHER = "3" * 40
OWNER = "@jdueadev"


def corpus_inputs(case):
    folder = ROOT / "ci/corpus/approval" / case / "inputs"
    out = {}
    for name in ("reviews", "activity", "pr", "timeline"):
        text = (folder / f"{name}.json").read_text(encoding="utf-8")
        out[name] = json.loads(text.replace("@HEAD@", HEAD).replace("@BASE@", BASE))
    return out


def counts(data, head=HEAD):
    kept, _ = pc.review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], head)
    return pc.approved(kept, OWNER, head)


def why(data, head=HEAD):
    return pc.review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], head)[1]


def owner_review(state, at, commit=HEAD, login="jdueadev"):
    return {"user": {"login": login} if login is not None else None, "state": state, "commit_id": commit,
            "submitted_at": at}


class SeededCases(unittest.TestCase):
    def test_the_carried_over_approval_of_93_does_not_count(self):
        data = corpus_inputs("carried-over-93")
        self.assertTrue(pc.approved(data["reviews"], OWNER, HEAD))   # what the old rule said
        self.assertFalse(counts(data))
        self.assertIsNone(why(data))                                 # the arrival is known; it is just later

    def test_the_fresh_approval_of_147_counts(self):
        self.assertTrue(counts(corpus_inputs("fresh-after-push-147")))

    def test_the_arrival_of_93_is_its_last_push(self):
        data = corpus_inputs("carried-over-93")
        arrived, _ = pc.head_arrival(data["activity"], data["pr"], data["timeline"], HEAD)
        self.assertEqual(arrived, pc.github_time("2026-11-22T23:06:16Z"))

    def test_the_arrival_of_147_is_the_pr_creation(self):
        data = corpus_inputs("fresh-after-push-147")
        arrived, _ = pc.head_arrival(data["activity"], data["pr"], data["timeline"], HEAD)
        self.assertEqual(arrived, pc.github_time("2026-11-22T22:16:44Z"))

    def test_slurped_pages_give_the_same_answer(self):
        for case, expected in (("carried-over-93", False), ("fresh-after-push-147", True)):
            data = corpus_inputs(case)
            paged = {k: ([v[:1], v[1:]] if isinstance(v, list) else v) for k, v in data.items()}
            self.assertEqual(counts(paged), expected, case)


class Times(unittest.TestCase):
    def fresh_at(self, at):
        data = corpus_inputs("fresh-after-push-147")
        data["reviews"][0]["submitted_at"] = at
        return data

    def test_a_review_in_the_same_second_as_the_arrival_does_not_count(self):
        self.assertFalse(counts(self.fresh_at("2026-11-22T22:16:44Z")))
        self.assertTrue(counts(self.fresh_at("2026-11-22T22:16:45Z")))

    def test_a_review_time_in_any_other_form_does_not_count(self):
        for at in ("2026-11-22T22:21:25+00:00", "2026-11-22T22:21:25.000Z", "2026-11-22 22:21:25Z",
                   "2026-11-22T22:21:25", 1795385000, None, "", "2026-13-40T22:21:25Z"):
            with self.subTest(at=at):
                self.assertFalse(counts(self.fresh_at(at)))

    def test_a_missing_review_time_does_not_count(self):
        data = corpus_inputs("fresh-after-push-147")
        del data["reviews"][0]["submitted_at"]
        self.assertFalse(counts(data))

    def test_a_push_time_in_another_form_voids_every_review(self):
        for at in ("2026-11-22T22:16:26+00:00", "2026-11-22T22:16:26.5Z", 1795385000, None):
            with self.subTest(at=at):
                data = corpus_inputs("fresh-after-push-147")
                data["activity"][0]["timestamp"] = at
                self.assertFalse(counts(data))
                self.assertIn("server time", why(data))

    def test_a_pr_without_a_creation_time_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        del data["pr"]["created_at"]
        self.assertFalse(counts(data))


class Reviews(unittest.TestCase):
    def with_reviews(self, *reviews):
        data = corpus_inputs("fresh-after-push-147")
        data["reviews"] = list(reviews)
        return data

    def test_a_fresh_review_of_an_older_commit_does_not_count(self):
        self.assertFalse(counts(self.with_reviews(owner_review("APPROVED", "2026-11-22T22:21:25Z", commit=OTHER))))

    def test_a_later_changes_requested_or_dismissed_review_wins(self):
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            with self.subTest(state=state):
                self.assertFalse(counts(self.with_reviews(owner_review("APPROVED", "2026-11-22T22:21:25Z"),
                                                          owner_review(state, "2026-11-22T22:30:00Z"))))

    def test_a_fresh_comment_does_not_refresh_a_stale_approval(self):
        data = corpus_inputs("carried-over-93")
        data["reviews"].append(owner_review("COMMENTED", "2026-11-22T23:10:00Z"))
        self.assertFalse(counts(data))

    def test_a_stale_approval_after_a_fresh_one_still_blocks(self):
        # Order is the API's; the owner's latest decision is the stale one, and it must not
        # fall through to an earlier approval.
        data = corpus_inputs("carried-over-93")
        data["reviews"] = [owner_review("APPROVED", "2026-11-22T23:07:00Z"),
                           owner_review("CHANGES_REQUESTED", "2026-11-22T23:08:00Z"),
                           owner_review("APPROVED", "2026-11-22T04:59:19Z")]
        self.assertFalse(counts(data))

    def test_a_fresh_reapproval_counts(self):
        data = corpus_inputs("carried-over-93")
        data["reviews"].append(owner_review("APPROVED", "2026-11-22T23:07:00Z"))
        self.assertTrue(counts(data))

    def test_the_owner_name_is_matched_without_case(self):
        self.assertTrue(counts(self.with_reviews(owner_review("APPROVED", "2026-11-22T22:21:25Z", login="JDueaDev"))))

    def test_another_reviewer_or_no_user_does_not_count(self):
        for login in ("someone-else", None):
            with self.subTest(login=login):
                self.assertFalse(counts(self.with_reviews(owner_review("APPROVED", "2026-11-22T22:21:25Z",
                                                                       login=login))))

    def test_every_review_is_kept_and_only_stale_ones_lose_their_commit(self):
        data = self.with_reviews(owner_review("APPROVED", "2026-11-22T22:00:00Z"),
                                 owner_review("COMMENTED", "2026-11-22T22:21:25Z"))
        kept, _ = pc.review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], HEAD)
        self.assertEqual([r["commit_id"] for r in kept], [None, HEAD])
        self.assertEqual([r["state"] for r in kept], ["APPROVED", "COMMENTED"])
        self.assertEqual(data["reviews"][0]["commit_id"], HEAD)        # the input is not changed


class Arrival(unittest.TestCase):
    def test_a_to_b_to_a_needs_a_new_approval(self):
        data = corpus_inputs("fresh-after-push-147")
        ref = data["activity"][0]["ref"]
        data["activity"] = [
            {"ref": ref, "before": OTHER, "after": HEAD, "timestamp": "2026-11-22T22:25:00Z", "activity_type": "force_push"},
            {"ref": ref, "before": HEAD, "after": OTHER, "timestamp": "2026-11-22T22:23:00Z", "activity_type": "push"},
        ] + data["activity"]
        self.assertFalse(counts(data))

    def test_a_lagging_log_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        data["activity"][0]["after"] = OTHER
        self.assertFalse(counts(data))
        self.assertIn("not the head", why(data))

    def test_a_deleted_branch_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        ref = data["activity"][0]["ref"]
        data["activity"].insert(0, {"ref": ref, "before": HEAD, "after": "0" * 40,
                                    "timestamp": "2026-11-22T22:21:52Z", "activity_type": "branch_deletion"})
        self.assertFalse(counts(data))

    def test_an_empty_log_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        data["activity"] = []
        self.assertFalse(counts(data))

    def test_a_log_entry_for_another_ref_voids_every_review(self):
        # The head may have been pushed to another branch long before: only this ref counts,
        # and an entry for any other ref means the query was not what it should be.
        data = corpus_inputs("fresh-after-push-147")
        data["activity"].append(dict(data["activity"][0], ref="refs/heads/seed", timestamp="2026-11-22T20:00:00Z"))
        self.assertFalse(counts(data))

    def test_a_log_not_newest_first_voids_every_review(self):
        # Oldest first, A -> B -> A: the first entry is the head's first arrival, so only
        # the order check stops the approval between the two arrivals of A from counting.
        data = corpus_inputs("fresh-after-push-147")
        ref = data["activity"][0]["ref"]
        data["activity"] += [
            {"ref": ref, "before": HEAD, "after": OTHER, "timestamp": "2026-11-22T22:23:00Z", "activity_type": "push"},
            {"ref": ref, "before": OTHER, "after": HEAD, "timestamp": "2026-11-22T22:25:00Z", "activity_type": "force_push"}]
        self.assertFalse(counts(data))
        self.assertIn("newest first", why(data))

    def test_a_reopen_or_base_change_after_the_approval_voids_it(self):
        for event in ("reopened", "base_ref_changed", "head_ref_force_pushed"):
            with self.subTest(event=event):
                data = corpus_inputs("fresh-after-push-147")
                data["timeline"].append({"event": event, "created_at": "2026-11-22T22:30:00Z"})
                self.assertFalse(counts(data))

    def test_a_reopen_without_a_time_voids_every_review(self):
        for created in (None, "yesterday"):
            with self.subTest(created=created):
                data = corpus_inputs("fresh-after-push-147")
                data["timeline"].append({"event": "reopened", "created_at": created})
                self.assertFalse(counts(data))

    def test_an_earlier_reopen_changes_nothing(self):
        data = corpus_inputs("fresh-after-push-147")
        data["timeline"].append({"event": "reopened", "created_at": "2026-11-22T22:17:00Z"})
        self.assertTrue(counts(data))

    def test_other_timeline_events_change_nothing(self):
        data = corpus_inputs("fresh-after-push-147")
        data["timeline"].append({"event": "labeled", "created_at": "2026-11-22T23:59:59Z"})
        data["timeline"].append({"event": "committed", "created_at": None})
        self.assertTrue(counts(data))

    def test_a_pr_with_odd_head_or_base_values_voids_every_review(self):
        for part, value in (("head", "x"), ("base", ["x"]), ("head.repo", "x"), ("base.repo", 7)):
            with self.subTest(part=part):
                data = corpus_inputs("fresh-after-push-147")
                where = data["pr"]
                *path, last = part.split(".")
                for key in path:
                    where = where[key]
                where[last] = value
                self.assertFalse(counts(data))

    def test_a_pr_whose_head_is_not_the_head_sha_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        data["pr"]["head"]["sha"] = OTHER
        self.assertFalse(counts(data))

    def test_a_fork_voids_every_review(self):
        for repo in ("someone/fork", None):
            with self.subTest(repo=repo):
                data = corpus_inputs("fresh-after-push-147")
                data["pr"]["head"]["repo"] = {"full_name": repo} if repo else None
                self.assertFalse(counts(data))

    def test_a_missing_head_ref_voids_every_review(self):
        data = corpus_inputs("fresh-after-push-147")
        data["pr"]["head"]["ref"] = ""
        self.assertFalse(counts(data))

    def test_the_inputs_are_not_changed(self):
        data = corpus_inputs("carried-over-93")
        before = copy.deepcopy(data)
        counts(data)
        self.assertEqual(data, before)


if __name__ == "__main__":
    unittest.main()

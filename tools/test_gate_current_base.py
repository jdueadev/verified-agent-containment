#!/usr/bin/env python3
"""The gate judges against main's tip, not the pull request's base.sha (#206, #217).

GitHub's base.sha stays at the main of the PR's last push. judge() must take the merge
base and the lane map from the commit of its own checkout (main), so a rule or trusted
list that landed after that push applies to the next judgment."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import gate_check as gc
from test_gate_approval_freshness import corpus_inputs, REPO, HEAD, OLD, WORKFLOW_IDS
from test_gate_check import green

MAIN = "d" * 40


class CurrentBase(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        patcher = mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "RUNNER_TEMP": d.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def judged_with(self, data):
        runs, jobs = green()
        number = data["pr"]["number"]
        seen = {}

        def pages(path):
            if path.startswith(f"repos/{REPO}/commits/{HEAD}/pulls?"):
                return [data["pr"]]
            if path.startswith(f"repos/{REPO}/actions/runs?head_sha={HEAD}"):
                return runs
            if path.startswith(f"repos/{REPO}/actions/runs/") and "/jobs?" in path:
                return jobs[int(path.split("/")[5])]
            if path.startswith(f"repos/{REPO}/pulls/{number}/reviews?"):
                return data["reviews"]
            if path.startswith(f"repos/{REPO}/activity?"):
                return data["activity"]
            if path.startswith(f"repos/{REPO}/issues/{number}/timeline?"):
                return data["timeline"]
            if path.startswith(f"repos/{REPO}/pulls/{number}/commits?"):
                return []
            raise AssertionError(f"unexpected GET {path}")

        def fetch_head(pr):
            seen["fetch_base"] = pr["base"]["sha"]
            return "c" * 40

        def changed_paths(base, head):
            seen["changed_from"] = base
            return ["src/x.rs"]

        def policy_result(pr, merge_base, reviews_file, enforce, commits_file=None):
            seen["policy_base"], seen["merge_base"] = pr["base"]["sha"], merge_base
            return True, "ok"

        with mock.patch.multiple(gc, pages=pages, gh=lambda path: {"id": WORKFLOW_IDS[path.rsplit("/", 1)[1]]},
                                 proven=lambda by_path, *a: (by_path, {}),
                                 merge_problem=lambda *a, **kw: None,
                                 main_tip=lambda: MAIN, fetch_head=fetch_head,
                                 changed_paths=changed_paths, policy_result=policy_result,
                                 proofs_of=lambda repo: None, signing_keys=lambda: {}), \
                redirect_stderr(io.StringIO()):
            gc.judged(HEAD)
        return seen

    def test_merge_base_and_lane_map_come_from_main_tip(self):
        data = corpus_inputs("fresh-after-push-147")
        self.assertEqual(data["pr"]["base"]["sha"], OLD)
        seen = self.judged_with(data)
        self.assertEqual(seen["fetch_base"], MAIN)
        self.assertEqual(seen["policy_base"], MAIN)
        self.assertEqual(seen["changed_from"], "c" * 40)
        self.assertEqual(seen["merge_base"], "c" * 40)

    def test_the_fetched_pull_request_is_left_as_github_sent_it(self):
        data = corpus_inputs("fresh-after-push-147")
        self.judged_with(data)
        self.assertEqual(data["pr"]["base"]["sha"], OLD)

    def test_on_main_tip_moves_only_base_sha(self):
        pr = {"number": 7, "base": {"ref": "main", "sha": OLD}, "head": {"sha": HEAD}}
        with mock.patch.object(gc, "main_tip", lambda: MAIN):
            now = gc.on_main_tip(pr)
        self.assertEqual(now["base"], {"ref": "main", "sha": MAIN})
        self.assertEqual(now["head"], pr["head"])
        self.assertEqual(pr["base"]["sha"], OLD)

    def test_main_tip_is_this_checkout_head(self):
        calls = []
        with mock.patch.object(gc, "git", lambda *a: calls.append(a) or MAIN + "\n"):
            self.assertEqual(gc.main_tip(), MAIN)
        self.assertEqual(calls, [("rev-parse", "HEAD")])


if __name__ == "__main__":
    unittest.main()

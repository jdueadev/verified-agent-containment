#!/usr/bin/env python3
"""The gate's own use of approval freshness (#149): the real `gate_check.judge()`, with
GitHub and git mocked, on the #93 and #147 inputs from ci/corpus/approval/.

judge() filters the reviews once, right after fetching them. These tests show that
every consumer sees only the filtered list: the `.github` rule for gate/check and
gate/spec, the merge-commit rule (merge_problem), and the reviews file that main's
classify reads for gate/policy. A failed fetch of the push log fails every context."""
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import gate_check as gc
import policy_check as pc
from test_gate_check import green

ROOT = TOOLS.parent
REPO = "o/r"
HEAD = "a" * 40
OLD = "b" * 40
OWNER = "@jdueadev"     # main's lane map, which judge() reads from this checkout
WORKFLOW_IDS = {"check.yml": 1, "spec.yml": 2}


def corpus_inputs(case):
    folder = ROOT / "ci/corpus/approval" / case / "inputs"
    data = {p.stem: json.loads(p.read_text(encoding="utf-8").replace("@HEAD@", HEAD).replace("@BASE@", OLD))
            for p in folder.glob("*.json")}
    # The gate's pull request, in this test's repository and on its head branch "topic".
    data["pr"]["head"].update(ref="topic", repo={"full_name": REPO})
    data["pr"]["base"].update(sha=OLD, repo={"full_name": REPO})
    for entry in data["activity"]:
        entry["ref"] = "refs/heads/topic"
    return data


class Judge(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "RUNNER_TEMP": self.tmp()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def tmp(self):
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name

    def judge(self, data, paths, activity_error=None):
        runs, jobs = green()
        seen = {}

        def pages(path):
            if path.startswith(f"repos/{REPO}/commits/{HEAD}/pulls?"):
                return [data["pr"]]
            if path.startswith(f"repos/{REPO}/actions/runs?head_sha={HEAD}"):
                return runs
            if path.startswith(f"repos/{REPO}/actions/runs/") and "/jobs?" in path:
                return jobs[int(path.split("/")[5])]
            if path.startswith(f"repos/{REPO}/pulls/{data['pr']['number']}/reviews?"):
                return data["reviews"]
            if path.startswith(f"repos/{REPO}/activity?"):
                seen["activity"] = path
                if activity_error:
                    raise activity_error
                return data["activity"]
            if path.startswith(f"repos/{REPO}/issues/{data['pr']['number']}/timeline?"):
                return data["timeline"]
            if path.startswith(f"repos/{REPO}/pulls/{data['pr']['number']}/commits?"):
                return []
            raise AssertionError(f"unexpected GET {path}")

        def gh(path):
            return {"id": WORKFLOW_IDS[path.rsplit("/", 1)[1]]}

        def proven(by_path, pr, repo, proofs_of, keys, binding):
            seen["merge_problem"] = binding({})
            return by_path, {}

        def merge_problem(claims, pr, workflows_approved, git=None):
            seen["workflows_approved"] = workflows_approved

        def policy_result(pr, merge_base, reviews_file, enforce, commits_file=None):
            seen["policy_reviews"] = json.loads(Path(reviews_file).read_text(encoding="utf-8"))
            return True, "ok"

        with mock.patch.object(gc, "pages", pages), mock.patch.object(gc, "gh", gh), \
                mock.patch.object(gc, "proven", proven), mock.patch.object(gc, "merge_problem", merge_problem), \
                mock.patch.object(gc, "policy_result", policy_result), \
                mock.patch.object(gc, "fetch_head", lambda pr: OLD), \
                mock.patch.object(gc, "changed_paths", lambda base, head: list(paths)), \
                mock.patch.object(gc, "proofs_of", lambda repo: None), \
                mock.patch.object(gc, "signing_keys", lambda: {}), \
                redirect_stderr(io.StringIO()) as err:
            batch = gc.judged(HEAD)
        seen["stderr"] = err.getvalue()
        return {v["context"]: v for v in batch["verdicts"]}, seen

    def test_93_with_a_github_change_fails_every_run_context(self):
        verdicts, seen = self.judge(corpus_inputs("carried-over-93"), [".github/workflows/check.yml"])
        for context in gc.CONTEXTS:
            if context != gc.POLICY:
                self.assertEqual(verdicts[context]["conclusion"], "failure", context)
        self.assertIs(seen["workflows_approved"], False)
        self.assertFalse(pc.approved(seen["policy_reviews"], OWNER, HEAD))

    def test_93_passed_under_the_old_rule(self):
        # The control: the same inputs, unfiltered, approve the head.
        self.assertTrue(pc.approved(corpus_inputs("carried-over-93")["reviews"], OWNER, HEAD))

    def test_147_with_a_github_change_passes(self):
        verdicts, seen = self.judge(corpus_inputs("fresh-after-push-147"), [".github/workflows/check.yml"])
        self.assertEqual(verdicts["gate/check"]["conclusion"], "success", verdicts["gate/check"])
        self.assertIs(seen["workflows_approved"], True)
        self.assertTrue(pc.approved(seen["policy_reviews"], OWNER, HEAD))

    def test_the_push_log_is_read_for_the_head_ref(self):
        _, seen = self.judge(corpus_inputs("fresh-after-push-147"), ["src/x.rs"])
        self.assertIn("ref=refs%2Fheads%2Ftopic", seen["activity"])

    def test_a_failed_push_log_read_fails_every_context(self):
        error = subprocess.CalledProcessError(1, ["gh", "api"], stderr="HTTP 403: rate limit")
        verdicts, seen = self.judge(corpus_inputs("fresh-after-push-147"), [".github/x"], activity_error=error)
        self.assertEqual(set(verdicts), set(gc.CONTEXTS))
        self.assertTrue(all(v["conclusion"] == "failure" for v in verdicts.values()))
        self.assertNotIn("policy_reviews", seen)

    def test_a_lagging_log_voids_the_approval_and_says_why(self):
        data = corpus_inputs("fresh-after-push-147")
        data["activity"][0]["after"] = OLD
        verdicts, seen = self.judge(data, [".github/x"])
        self.assertEqual(verdicts["gate/check"]["conclusion"], "failure")
        self.assertFalse(pc.approved(seen["policy_reviews"], OWNER, HEAD))
        self.assertIn("no review of", seen["stderr"])


if __name__ == "__main__":
    unittest.main()

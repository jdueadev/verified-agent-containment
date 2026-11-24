import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_check as gc

REPO = "owner/repo"


def pr(author="jdueadev-agent", head_repo=REPO, base_repo=REPO):
    return {"number": 7, "user": {"login": author} if author else {},
            "base": {"ref": "main", "sha": "a" * 40, "repo": {"full_name": base_repo} if base_repo else {}},
            "head": {"ref": "topic", "sha": "b" * 40, "repo": {"full_name": head_repo} if head_repo else {}}}


def classify_args(p):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with mock.patch.object(gc.subprocess, "run", fake_run):
        gc.policy_result(p, "c" * 40, "reviews.json", True)
    return next(c for c in seen if "classify" in c)


class GateClassifyArguments(unittest.TestCase):
    def test_the_author_reaches_the_classifier(self):
        args = classify_args(pr())
        self.assertEqual(args[args.index("--author") + 1], "jdueadev-agent")
        self.assertNotIn("--fork", args)

    def test_a_pull_request_without_an_author_is_classified_untrusted(self):
        self.assertNotIn("--author", classify_args(pr(author=None)))

    def test_a_fork_is_flagged_whoever_opened_it(self):
        args = classify_args(pr(head_repo="someone/repo"))
        self.assertIn("--fork", args)
        self.assertIn("--author", args)

    def test_an_unknown_head_repository_counts_as_a_fork(self):
        self.assertIn("--fork", classify_args(pr(head_repo=None)))
        self.assertIn("--fork", classify_args(pr(base_repo=None)))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for tools/gate_check.py. Each rule has a case that makes it fire."""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_check as gc
import workflow_lint as wl

ROOT = Path(__file__).resolve().parent.parent
REPO = "o/r"
HEAD = "a" * 40
OLD = "b" * 40
IDS = {".github/workflows/check.yml": 1, ".github/workflows/spec.yml": 2, ".github/workflows/policy.yml": 3}
PR = {"number": 7, "state": "open", "base": {"ref": "main", "sha": OLD},
      "head": {"sha": HEAD, "repo": {"full_name": REPO}}}
OWNER = "@owner"
SPEC_JOBS = ["spec (base)", "spec (new)", "spec (corpus)"]


def run(i, path, event=None, status="completed", sha=HEAD, repo=REPO, wid=None):
    event = event or gc.WORKFLOWS[path][0]
    return {"id": i, "path": path, "event": event, "status": status, "head_sha": sha,
            "head_repository": {"full_name": repo}, "workflow_id": IDS[path] if wid is None else wid}


def green():
    runs = [run(10, ".github/workflows/check.yml"), run(20, ".github/workflows/spec.yml"),
            run(30, ".github/workflows/policy.yml")]
    jobs = {10: [{"name": "check", "conclusion": "success"}, {"name": "evidence-freshness", "conclusion": "failure"}],
            20: [{"name": n, "conclusion": "success"} for n in SPEC_JOBS],
            30: [{"name": "policy", "conclusion": "success"}]}
    return runs, jobs


def judge(runs, jobs, paths=("src/x.rs",), reviews=()):
    by_path = gc.qualifying(runs, REPO, HEAD, IDS)
    return {v["context"]: v for v in gc.verdicts(PR, by_path, jobs, list(paths), list(reviews), OWNER)}


def review(state, commit=HEAD, user="owner"):
    return {"user": {"login": user}, "state": state, "commit_id": commit}


class Verdicts(unittest.TestCase):
    def test_every_required_job_green_passes_every_context(self):
        result = judge(*green())
        self.assertEqual(sorted(result), sorted(gc.CONTEXTS))
        self.assertTrue(all(v["conclusion"] == "success" for v in result.values()), result)

    def test_the_job_is_judged_not_the_run(self):
        # evidence-freshness failed in run 10; only `check` is required.
        self.assertEqual(judge(*green())["gate/check"]["conclusion"], "success")

    def test_a_failed_job_fails_its_context_only(self):
        runs, jobs = green()
        jobs[20][1]["conclusion"] = "failure"
        result = judge(runs, jobs)
        self.assertEqual(result["gate/spec (new)"]["conclusion"], "failure")
        self.assertEqual(result["gate/spec (base)"]["conclusion"], "success")

    def test_no_run_yet_is_in_progress(self):
        runs, jobs = green()
        result = judge([r for r in runs if r["id"] != 30], jobs)
        self.assertEqual((result["gate/policy"]["status"], result["gate/policy"]["conclusion"]), ("in_progress", None))

    def test_a_run_still_going_is_in_progress(self):
        runs, jobs = green()
        runs.append(run(11, ".github/workflows/check.yml", status="in_progress"))
        self.assertEqual(judge(runs, jobs)["gate/check"]["status"], "in_progress")

    def test_every_qualifying_run_must_pass(self):
        # A second run of check.yml on the same commit, from a PR into another branch,
        # fails at the base guard. The runs API cannot tell the two apart.
        runs, jobs = green()
        runs.append(run(12, ".github/workflows/check.yml"))
        jobs[12] = [{"name": "check", "conclusion": "failure"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_a_cancelled_run_is_ignored_when_another_run_counts(self):
        runs, jobs = green()
        runs.append(run(9, ".github/workflows/check.yml"))
        jobs[9] = [{"name": "check", "conclusion": "cancelled"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "success")

    def test_only_cancelled_runs_fail(self):
        runs, jobs = green()
        jobs[10] = [{"name": "check", "conclusion": "cancelled"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_skipped_or_missing_or_doubled_jobs_fail(self):
        for jobs10 in ([{"name": "check", "conclusion": "skipped"}], [],
                       [{"name": "check", "conclusion": "success"}] * 2):
            with self.subTest(jobs10=jobs10):
                runs, jobs = green()
                jobs[10] = jobs10
                self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_runs_that_do_not_qualify_are_ignored(self):
        # Each look-alike run is green; none of them may stand in for the missing real one.
        look_alikes = [
            run(40, ".github/workflows/check.yml", wid=99),                    # a branch-only file
            run(41, ".github/workflows/check.yml", event="push"),
            run(42, ".github/workflows/check.yml", repo="fork/r"),
            run(43, ".github/workflows/check.yml", sha=OLD),
            dict(run(44, ".github/workflows/check.yml"), path=".github/workflows/x.yml"),
            run(45, ".github/workflows/policy.yml", event="pull_request"),
        ]
        runs, jobs = green()
        runs = [r for r in runs if r["id"] != 10] + look_alikes
        for r in look_alikes:
            jobs[r["id"]] = [{"name": "check", "conclusion": "success"}, {"name": "policy", "conclusion": "success"}]
        result = judge(runs, jobs)
        self.assertEqual(result["gate/check"]["status"], "in_progress")
        self.assertEqual(result["gate/policy"]["conclusion"], "success")  # run 30, not 45
        self.assertEqual(gc.qualifying(runs, REPO, HEAD, IDS)[".github/workflows/policy.yml"], [runs[1]])


class WorkflowChanges(unittest.TestCase):
    def test_a_workflow_change_needs_the_owners_approval_of_this_head(self):
        result = judge(*green(), paths=[".github/workflows/check.yml"])
        self.assertTrue(all(v["conclusion"] == "failure" for v in result.values()))
        self.assertIn("needs @owner's approval", result["gate/check"]["summary"])

    def test_an_approval_of_this_head_passes(self):
        result = judge(*green(), paths=[".github/workflows/check.yml"], reviews=[review("APPROVED")])
        self.assertTrue(all(v["conclusion"] == "success" for v in result.values()))

    def test_approvals_that_do_not_count_fail(self):
        for reviews in ([review("APPROVED", commit=OLD)], [review("APPROVED", user="someone")],
                        [review("APPROVED"), review("CHANGES_REQUESTED")], [review("COMMENTED")]):
            with self.subTest(reviews=reviews):
                result = judge(*green(), paths=[".github/x"], reviews=reviews)
                self.assertEqual(result["gate/check"]["conclusion"], "failure")

    def test_an_approval_does_not_rescue_a_failed_job(self):
        runs, jobs = green()
        jobs[10] = [{"name": "check", "conclusion": "failure"}]
        result = judge(runs, jobs, paths=[".github/x"], reviews=[review("APPROVED")])
        self.assertEqual(result["gate/check"]["conclusion"], "failure")


class PostInput(unittest.TestCase):
    def good(self):
        verdicts = [{"context": c, "status": "completed", "conclusion": "success", "summary": "s"} for c in gc.CONTEXTS]
        return {"head_sha": HEAD, "pr": 7, "verdicts": verdicts}

    def test_good_verdicts_pass(self):
        self.assertEqual(gc.checked_verdicts(json.dumps(self.good())), self.good())

    def test_anything_judge_cannot_produce_is_refused(self):
        bad = []
        d = self.good(); d["extra"] = 1; bad.append(d)
        d = self.good(); d["head_sha"] = "main"; bad.append(d)
        d = self.good(); d["pr"] = "7"; bad.append(d)
        d = self.good(); d["verdicts"][0]["context"] = "check"; bad.append(d)
        d = self.good(); d["verdicts"][0]["conclusion"] = "neutral"; bad.append(d)
        d = self.good(); d["verdicts"][0]["status"] = "in_progress"; bad.append(d)
        d = self.good(); d["verdicts"].pop(); bad.append(d)
        d = self.good(); d["verdicts"].append(dict(d["verdicts"][0])); bad.append(d)
        d = self.good(); d["verdicts"][0]["details_url"] = "x"; bad.append(d)
        for d in bad:
            with self.subTest(d=str(d)[:80]), self.assertRaises(ValueError):
                gc.checked_verdicts(json.dumps(d))


class Post(unittest.TestCase):
    def test_creates_once_then_updates_in_place(self):
        data = PostInput().good()
        calls = []
        existing = {"gate/check": [{"id": 5, "app": {"id": 123}}, {"id": 6, "app": {"id": 999}}]}

        def pages(path):
            calls.append(("GET", path))
            name = next(c for c in gc.CONTEXTS if f"check_name={gc.urllib.parse.quote(c, safe='')}&" in path)
            return existing.get(name, [])

        def gh(*args, data=None):
            calls.append((args[1], args[2], data))

        with mock.patch.object(gc, "pages", pages), mock.patch.object(gc, "gh", gh):
            gc.post(data, "123", REPO)
        writes = [c for c in calls if c[0] != "GET"]
        self.assertEqual([w[1] for w in writes if w[0] == "PATCH"], [f"repos/{REPO}/check-runs/5"])
        self.assertEqual(len([w for w in writes if w[0] == "POST"]), len(gc.CONTEXTS) - 1)
        self.assertNotIn("head_sha", writes[0][2] if writes[0][0] == "PATCH" else {})
        self.assertTrue(any("check_name=gate%2Fspec%20%28base%29&app_id=123" in c[1] for c in calls if c[0] == "GET"))


class Judge(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO})
        self.env.start()
        self.addCleanup(self.env.stop)

    def fake(self, prs, runs_seq, jobs):
        state = {"runs": list(runs_seq)}

        def gh(path, *rest, data=None):
            if path.endswith("/pulls"):
                return prs
            return {"id": IDS[".github/workflows/" + path.rsplit("/", 1)[1]]}

        def pages(path):
            if "/actions/runs?" in path:
                return state["runs"].pop(0) if len(state["runs"]) > 1 else state["runs"][0]
            if path.endswith("/jobs?filter=latest&per_page=100"):
                return jobs[int(path.split("/runs/")[1].split("/")[0])]
            return []

        return mock.patch.multiple(gc, gh=gh, pages=pages, changed_paths=lambda pr: ["src/x"])

    def test_no_open_pull_request_into_main_from_this_repository_posts_nothing(self):
        for pr in (dict(PR, state="closed"), dict(PR, base={"ref": "other", "sha": OLD}),
                   dict(PR, head={"sha": HEAD, "repo": {"full_name": "fork/r"}}),
                   dict(PR, head={"sha": OLD, "repo": {"full_name": REPO}})):
            with self.subTest(pr=pr), self.fake([pr], [[]], {}):
                self.assertEqual(gc.judge(HEAD), (None, []))

    def test_waits_for_runs_still_going_then_judges(self):
        runs, jobs = green()
        going = [dict(r, status="in_progress") if r["id"] == 30 else r for r in runs]
        clock, slept = [0.0], []
        with self.fake([PR], [going, runs], jobs):
            pr, result = gc.judge(HEAD, now=lambda: clock[0], sleep=lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s)))
        self.assertEqual(slept, [gc.POLL_SECONDS])
        self.assertTrue(all(v["conclusion"] == "success" for v in result))

    def test_stops_waiting_at_the_deadline(self):
        runs, jobs = green()
        going = [dict(r, status="in_progress") if r["id"] == 30 else r for r in runs]
        clock = [0.0]
        with self.fake([PR], [going], jobs):
            pr, result = gc.judge(HEAD, now=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        self.assertEqual({v["context"]: v["status"] for v in result}["gate/policy"], "in_progress")
        self.assertGreaterEqual(clock[0], gc.WAIT_SECONDS)

    def test_refuses_a_head_that_is_not_a_commit_id(self):
        with self.assertRaises(ValueError):
            gc.judge("main")


class Repository(unittest.TestCase):
    def test_the_gate_workflow_passes_the_lint_and_names_the_jobs_it_judges(self):
        text = (ROOT / ".github/workflows/gate.yml").read_text(encoding="utf-8")
        allowed = wl.load_allowed((ROOT / wl.ALLOW_FILE).read_text(encoding="utf-8"))
        self.assertEqual(wl.lint("gate.yml", text, allowed), [])
        self.assertIn("workflows: [check, spec, policy, policy-refresh]", text)
        self.assertIn("environment: gate", text)
        self.assertIn("permission-checks: write", text)

    def test_the_judged_jobs_exist_in_their_workflows(self):
        check = (ROOT / ".github/workflows/check.yml").read_text(encoding="utf-8")
        spec = (ROOT / ".github/workflows/spec.yml").read_text(encoding="utf-8")
        policy = (ROOT / ".github/workflows/policy.yml").read_text(encoding="utf-8")
        self.assertIn("\n  check:\n", check)
        self.assertIn("part: [base, new, corpus]", spec)
        self.assertIn("\n  policy:\n", policy)
        self.assertIn("pull_request_target:", policy)
        for text in (check, spec):
            self.assertIn("\n  pull_request:\n", text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for tools/gate_check.py. Each rule has a case that makes it fire."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_check as gc
import workflow_lint as wl

ROOT = Path(__file__).resolve().parent.parent
REPO = "o/r"
HEAD = "a" * 40
OLD = "b" * 40
IDS = {".github/workflows/check.yml": 1, ".github/workflows/spec.yml": 2}
PR = {"number": 7, "state": "open", "base": {"ref": "main", "sha": OLD},
      "head": {"sha": HEAD, "ref": "topic", "repo": {"full_name": REPO}}}
OWNER = "@owner"
SPEC_JOBS = ["spec (base)", "spec (new)", "spec (corpus)"]
POLICY_OK = (True, "ok")
RUN_CONTEXTS = [c for c in gc.CONTEXTS if c != gc.POLICY]


def run(i, path, event="pull_request", status="completed", sha=HEAD, repo=REPO, wid=None, branch="topic"):
    return {"id": i, "path": path, "event": event, "status": status, "head_sha": sha, "head_branch": branch,
            "head_repository": {"full_name": repo}, "workflow_id": IDS[path] if wid is None else wid}


def green():
    runs = [run(10, ".github/workflows/check.yml"), run(20, ".github/workflows/spec.yml")]
    jobs = {10: [{"name": "check", "conclusion": "success"}, {"name": "evidence-freshness", "conclusion": "failure"}],
            20: [{"name": n, "conclusion": "success"} for n in SPEC_JOBS]}
    return runs, jobs


def judge(runs, jobs, paths=("src/x.rs",), reviews=(), policy=POLICY_OK):
    by_path = gc.qualifying(runs, REPO, PR, IDS)
    out = gc.verdicts(PR, by_path, jobs, list(paths), list(reviews), OWNER, policy)
    return {v["context"]: v for v in out}


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
        result = judge([r for r in runs if r["id"] != 20], jobs)
        self.assertEqual((result["gate/spec (base)"]["status"], result["gate/spec (base)"]["conclusion"]),
                         ("in_progress", None))

    def test_a_run_still_going_is_in_progress(self):
        runs, jobs = green()
        runs.append(run(11, ".github/workflows/check.yml", status="in_progress"))
        self.assertEqual(judge(runs, jobs)["gate/check"]["status"], "in_progress")

    def test_every_qualifying_run_must_pass(self):
        runs, jobs = green()
        runs.append(run(12, ".github/workflows/check.yml"))
        jobs[12] = [{"name": "check", "conclusion": "failure"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_a_cancelled_run_is_skipped_when_another_run_counts(self):
        runs, jobs = green()
        runs.append(run(9, ".github/workflows/check.yml"))
        jobs[9] = [{"name": "check", "conclusion": "cancelled"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "success")

    def test_only_cancelled_runs_fail(self):
        runs, jobs = green()
        jobs[10] = [{"name": "check", "conclusion": "cancelled"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_skipped_missing_or_doubled_jobs_fail(self):
        for jobs10 in ([{"name": "check", "conclusion": "skipped"}], [],
                       [{"name": "check", "conclusion": "success"}] * 2):
            with self.subTest(jobs10=jobs10):
                runs, jobs = green()
                jobs[10] = jobs10
                self.assertEqual(judge(runs, jobs)["gate/check"]["conclusion"], "failure")

    def test_runs_that_do_not_qualify_are_ignored(self):
        # Each look-alike run is green; none may stand in for the missing real one.
        look_alikes = [
            run(40, ".github/workflows/check.yml", wid=99),                    # a branch-only file
            run(41, ".github/workflows/check.yml", event="push"),
            run(42, ".github/workflows/check.yml", event="pull_request_target"),
            run(43, ".github/workflows/check.yml", repo="fork/r"),
            run(44, ".github/workflows/check.yml", sha=OLD),
            dict(run(46, ".github/workflows/check.yml"), path=".github/workflows/x.yml"),
            dict(run(47, ".github/workflows/check.yml"), path=".github/workflows/policy.yml"),
        ]
        runs, jobs = green()
        runs = [r for r in runs if r["id"] != 10] + look_alikes
        for r in look_alikes:
            jobs[r["id"]] = [{"name": "check", "conclusion": "success"}]
        self.assertEqual(judge(runs, jobs)["gate/check"]["status"], "in_progress")
        self.assertEqual(gc.qualifying(runs, REPO, PR, IDS)[".github/workflows/check.yml"], [])

    def test_policy_comes_from_mains_checkers(self):
        result = judge(*green(), policy=(False, "classify failed"))
        self.assertEqual((result[gc.POLICY]["conclusion"], result[gc.POLICY]["summary"]),
                         ("failure", "classify failed"))
        self.assertEqual(result["gate/check"]["conclusion"], "success")


class WorkflowChanges(unittest.TestCase):
    def test_without_approval_a_workflow_change_says_so_even_with_no_runs(self):
        result = judge([], {}, paths=[".github/workflows/check.yml"])
        self.assertIn("needs @owner's approval", result["gate/check"]["summary"])
        self.assertEqual(result["gate/check"]["conclusion"], "failure")

    def test_a_workflow_change_needs_the_owners_approval_of_this_head(self):
        for path in (".github/workflows/check.yml", ".github"):
            with self.subTest(path=path):
                result = judge(*green(), paths=[path])
                self.assertTrue(all(result[c]["conclusion"] == "failure" for c in RUN_CONTEXTS))
                self.assertIn("needs @owner's approval", result["gate/check"]["summary"])

    def test_a_lookalike_path_is_not_a_workflow_change(self):
        self.assertEqual(judge(*green(), paths=[".github-notes", "docs/.github/x"])["gate/check"]["conclusion"],
                         "success")

    def test_an_approval_of_this_head_passes(self):
        result = judge(*green(), paths=[".github/workflows/check.yml"], reviews=[review("APPROVED")])
        self.assertTrue(all(v["conclusion"] == "success" for v in result.values()))

    def test_approvals_that_do_not_count_fail(self):
        for reviews in ([review("APPROVED", commit=OLD)], [review("APPROVED", user="someone")],
                        [review("APPROVED"), review("CHANGES_REQUESTED")], [review("APPROVED"), review("DISMISSED")],
                        [review("COMMENTED")]):
            with self.subTest(reviews=reviews):
                result = judge(*green(), paths=[".github/x"], reviews=reviews)
                self.assertEqual(result["gate/check"]["conclusion"], "failure")

    def test_an_approval_does_not_rescue_a_failed_job(self):
        runs, jobs = green()
        jobs[10] = [{"name": "check", "conclusion": "failure"}]
        result = judge(runs, jobs, paths=[".github/x"], reviews=[review("APPROVED")])
        self.assertEqual(result["gate/check"]["conclusion"], "failure")


def good():
    verdicts = [{"context": c, "status": "completed", "conclusion": "success", "summary": "s"} for c in gc.CONTEXTS]
    return {"head_sha": HEAD, "pr": 7, "verdicts": verdicts}


class PostInput(unittest.TestCase):
    def test_good_verdicts_pass(self):
        self.assertEqual(gc.checked_verdicts(json.dumps([good()]), HEAD), [good()])
        self.assertEqual(gc.checked_verdicts(json.dumps([dict(good(), pr=None)]), HEAD)[0]["pr"], None)
        both = [good(), dict(good(), head_sha=OLD)]
        self.assertEqual(gc.checked_verdicts(json.dumps(both)), both)       # a sweep

    def test_batches_must_fit_the_trigger(self):
        for data, head in (([good(), dict(good(), head_sha=OLD)], HEAD),   # a triggered run judges one head
                           ([], HEAD), ([good(), good()], None),           # none, or a head twice
                           (good(), None)):                                # not a list
            with self.subTest(data=str(data)[:60]), self.assertRaises(ValueError):
                gc.checked_verdicts(json.dumps(data), head)

    def test_anything_judge_cannot_produce_is_refused(self):
        bad = []
        d = good(); d["extra"] = 1; bad.append(d)
        d = good(); d["head_sha"] = OLD; bad.append(d)                 # not the triggering commit
        d = good(); d["pr"] = "7"; bad.append(d)
        d = good(); d["verdicts"][0]["context"] = "check"; bad.append(d)
        d = good(); d["verdicts"][0]["conclusion"] = "neutral"; bad.append(d)
        d = good(); d["verdicts"][0]["status"] = "in_progress"; bad.append(d)
        d = good(); d["verdicts"].pop(); bad.append(d)
        d = good(); d["verdicts"].append(dict(d["verdicts"][0])); bad.append(d)
        d = good(); d["verdicts"][0]["details_url"] = "x"; bad.append(d)
        d = good(); d["pr"] = True; bad.append(d)
        for d in bad:
            with self.subTest(d=str(d)[:80]), self.assertRaises(ValueError):
                gc.checked_verdicts(json.dumps([d]), HEAD)


class Post(unittest.TestCase):
    def capture(self, existing, data):
        calls = []

        def pages(path):
            calls.append(("GET", path, None))
            name = next(c for c in gc.CONTEXTS if f"check_name={gc.urllib.parse.quote(c, safe='')}&" in path)
            return existing.get(name, [])

        def gh(*args, data=None):
            calls.append((args[1], args[2], data))

        with mock.patch.object(gc, "pages", pages), mock.patch.object(gc, "gh", gh), redirect_stdout(io.StringIO()):
            gc.post(data, "123", REPO)
        return calls

    def test_failures_go_first_and_one_failed_write_does_not_stop_the_rest(self):
        data = good()
        data["verdicts"][-1] = dict(data["verdicts"][-1], conclusion="failure", summary="x" * 5000)
        order, calls = [], []

        def pages(path):
            return []

        def gh(*args, data=None):
            order.append(data["name"])
            calls.append(data)
            if data["name"] == "gate/check":
                raise subprocess.CalledProcessError(1, "gh", stderr="boom")

        with mock.patch.object(gc, "pages", pages), mock.patch.object(gc, "gh", gh), \
                redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            gc.post(data, "123", REPO)
        self.assertEqual(order[0], data["verdicts"][-1]["context"])
        self.assertEqual(sorted(order), sorted(gc.CONTEXTS))
        self.assertLessEqual(max(len(c["output"]["summary"]) for c in calls), gc.SUMMARY_LIMIT)

    def test_without_a_pr_only_existing_runs_are_updated(self):
        data = dict(good(), pr=None, verdicts=gc.all_failed("gone"))
        calls = self.capture({"gate/check": [{"id": 5, "name": "gate/check", "app": {"id": 123}}]}, data)
        writes = [c for c in calls if c[0] != "GET"]
        self.assertEqual([(w[0], w[1]) for w in writes], [("PATCH", f"repos/{REPO}/check-runs/5")])
        self.assertEqual(writes[0][2]["conclusion"], "failure")

    def test_creates_once_then_updates_in_place(self):
        existing = {"gate/check": [{"id": 5, "name": "gate/check", "app": {"id": 123}},
                                   {"id": 6, "name": "gate/check", "app": {"id": 999}},
                                   {"id": 8, "name": "gate/other", "app": {"id": 123}}]}
        calls = self.capture(existing, good())
        writes = [c for c in calls if c[0] != "GET"]
        patches = [w for w in writes if w[0] == "PATCH"]
        self.assertEqual([w[1] for w in patches], [f"repos/{REPO}/check-runs/5"])
        self.assertNotIn("head_sha", patches[0][2])
        self.assertEqual(len([w for w in writes if w[0] == "POST"]), len(gc.CONTEXTS) - 1)
        self.assertTrue(any("check_name=gate%2Fspec%20%28base%29&app_id=123" in c[1] for c in calls if c[0] == "GET"))

    def test_an_undecided_verdict_never_moves_a_completed_run_back(self):
        data = good()
        data["verdicts"][0] = {"context": "gate/check", "status": "in_progress", "conclusion": None, "summary": "wait"}
        calls = self.capture({"gate/check": [{"id": 5, "name": "gate/check", "app": {"id": 123}}]}, data)
        patch = next(c for c in calls if c[0] == "PATCH")[2]
        self.assertEqual((patch["status"], patch["conclusion"]), ("completed", "failure"))
        create = self.capture({}, data)
        first = next(c for c in create if c[0] == "POST" and c[2]["name"] == "gate/check")[2]
        self.assertEqual(first["status"], "in_progress")
        self.assertNotIn("conclusion", first)


class Main(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = gc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_a_judge_error_fails_every_context(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(gc, "judge", side_effect=RuntimeError("two open pull requests")):
            out = Path(tmp) / "out"
            code, _, err = self.run_main(["judge", "--head-sha", HEAD, "--out", str(out)])
            data = gc.checked_verdicts(out.read_text().split("=", 1)[1], HEAD)
        self.assertEqual(code, 0)
        self.assertIn("two open pull requests", err)
        self.assertEqual(data[0]["pr"], None)
        self.assertTrue(all(v["conclusion"] == "failure" for v in data[0]["verdicts"]))

    def test_no_pull_request_writes_failures_with_no_pr(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(gc, "judge", return_value=(None, gc.all_failed("no PR"))):
            out = Path(tmp) / "out"
            self.run_main(["judge", "--head-sha", HEAD, "--out", str(out)])
            data = gc.checked_verdicts(out.read_text().split("=", 1)[1], HEAD)
        self.assertIsNone(data[0]["pr"])

    def test_a_sweep_judges_every_open_pull_requests_head(self):
        judged = []

        def judge(head):
            judged.append(head)
            if head == OLD:
                raise RuntimeError("boom")
            return 7, gc.all_failed("x")

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(gc, "sweep_heads", lambda repo: [HEAD, OLD]), \
                mock.patch.object(gc, "judge", judge):
            out = Path(tmp) / "out"
            self.run_main(["judge", "--sweep", "--out", str(out)])
            data = gc.checked_verdicts(out.read_text().split("=", 1)[1])
        self.assertEqual(judged, [HEAD, OLD])
        self.assertEqual([(b["head_sha"], b["pr"]) for b in data], [(HEAD, 7), (OLD, None)])

    def test_sweep_heads_lists_open_prs_from_this_repository_whatever_their_base(self):
        prs = [dict(PR), dict(PR, base={"ref": "evil", "sha": OLD}, head={"sha": OLD, "ref": "x", "repo": {"full_name": REPO}}),
               dict(PR, head={"sha": "c" * 40, "ref": "y", "repo": {"full_name": "fork/r"}})]
        with mock.patch.object(gc, "pages", lambda path: prs):
            self.assertEqual(gc.sweep_heads(REPO), sorted([HEAD, OLD]))

    def test_post_without_verdicts_after_a_failed_judge_fails_every_context(self):
        posted = []
        with mock.patch.dict(os.environ, {"VERDICTS": ""}), \
                mock.patch.object(gc, "post", lambda data, app, repo: posted.append(data)):
            self.run_main(["post", "--app-id", "1", "--head-sha", HEAD, "--judge-result", "failure"])
            self.run_main(["post", "--app-id", "1", "--head-sha", HEAD, "--judge-result", "cancelled"])
        self.assertEqual(len(posted), 2)
        self.assertTrue(all(d["pr"] is None for d in posted))
        with mock.patch.dict(os.environ, {"VERDICTS": ""}), \
                mock.patch.object(gc, "post", lambda data, app, repo: posted.append(data)):
            self.run_main(["post", "--app-id", "1", "--sweep", "--judge-result", "failure"])
        self.assertEqual(len(posted), 2)                                   # a sweep knows no head to fail
        self.assertTrue(all(v["conclusion"] == "failure" for d in posted for v in d["verdicts"]))

    def test_post_refuses_verdicts_for_another_commit(self):
        with mock.patch.dict(os.environ, {"VERDICTS": json.dumps([dict(good(), head_sha=OLD)])}), \
                mock.patch.object(gc, "post", lambda *a: self.fail("posted")), self.assertRaises(SystemExit):
            self.run_main(["post", "--app-id", "1", "--head-sha", HEAD, "--judge-result", "success"])


class Judge(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "RUNNER_TEMP": tempfile.gettempdir()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake(self, prs, runs_seq, jobs):
        state = {"runs": list(runs_seq)}

        def gh(path, *rest, data=None):
            return {"id": IDS[".github/workflows/" + path.rsplit("/", 1)[1]]}

        def pages(path):
            if "/commits/" in path and path.split("?")[0].endswith("/pulls"):
                return prs
            if "/actions/runs?" in path:
                return state["runs"].pop(0) if len(state["runs"]) > 1 else state["runs"][0]
            if "/jobs?filter=latest" in path:
                return jobs[int(path.split("/runs/")[1].split("/")[0])]
            return []

        return mock.patch.multiple(gc, gh=gh, pages=pages, fetch_head=lambda pr: OLD,
                                   changed_paths=lambda base, head: ["src/x"],
                                   proofs_of=lambda repo: (lambda run: ["proof"]),
                                   signing_keys=lambda: {},
                                   proven=lambda by_path, *a: (by_path, {}),
                                   policy_result=lambda *a: POLICY_OK)

    def test_no_open_pull_request_into_main_fails_every_context_without_a_pr(self):
        # A retarget or a close must not leave an earlier success standing; post only
        # updates existing check runs when pr is None.
        for pr in (dict(PR, state="closed"), dict(PR, base={"ref": "other", "sha": OLD}),
                   dict(PR, head={"sha": HEAD, "ref": "topic", "repo": {"full_name": "fork/r"}}),
                   dict(PR, head={"sha": OLD, "ref": "topic", "repo": {"full_name": REPO}})):
            with self.subTest(pr=pr), self.fake([pr], [[]], {}):
                number, result = gc.judge(HEAD)
                self.assertIsNone(number)
                self.assertEqual(sorted(v["context"] for v in result), sorted(gc.CONTEXTS))
                self.assertTrue(all(v["conclusion"] == "failure" for v in result))

    def test_two_open_pull_requests_into_main_raise(self):
        with self.fake([PR, dict(PR, number=8)], [[]], {}), self.assertRaises(RuntimeError):
            gc.judge(HEAD)

    def test_a_run_still_going_is_judged_at_once_never_waited_for(self):
        # Waiting would hold an earlier success open after an approval is withdrawn.
        runs, jobs = green()
        going = [dict(r, status="in_progress") if r["id"] == 20 else r for r in runs]
        with self.fake([PR], [going], jobs):
            number, result = gc.judge(HEAD)
        self.assertEqual(number, 7)
        states = {v["context"]: (v["status"], v["conclusion"]) for v in result}
        self.assertEqual(states["gate/spec (base)"], ("in_progress", None))
        self.assertEqual(states["gate/check"], ("completed", "success"))
        self.assertFalse(hasattr(gc, "WAIT_SECONDS"))

    def test_refuses_a_head_that_is_not_a_commit_id(self):
        with self.assertRaises(ValueError):
            gc.judge("main")


class PolicyResult(unittest.TestCase):
    def test_runs_mains_checkers_with_policy_ymls_arguments(self):
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 1 if "invariants" in cmd else 0, "", "")

        with mock.patch.object(gc.subprocess, "run", fake_run):
            passed, summary = gc.policy_result(PR, "c" * 40, "reviews.json", True)
        self.assertFalse(passed)
        self.assertIn("invariants", summary)
        classify = next(c for c in seen if "classify" in c)
        for arg in ("--base", "c" * 40, "--map-ref", OLD, "--head", HEAD, "--head-sha", "--reviews", "--enforce"):
            self.assertIn(arg, classify)
        self.assertTrue(any("--ref" in c and "invariants" in c for c in seen))
        self.assertTrue(any(c[1].endswith("workflow_lint.py") and "--ref" in c for c in seen))
        with mock.patch.object(gc.subprocess, "run",
                               lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", "")):
            self.assertTrue(gc.policy_result(PR, "c" * 40, "r.json", False)[0])


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


class Proof(unittest.TestCase):
    """Tokens are signed by openssl, so the verifier is not checked against itself."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        key = Path(cls.tmp.name) / "key.pem"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
        cls.key = key
        modulus = openssl("rsa", "-in", str(key), "-noout", "-modulus").decode().strip().split("=", 1)[1]
        n = bytes.fromhex(modulus)
        cls.jwks = {"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256", "n": cls.b64(n),
                              "e": cls.b64((65537).to_bytes(3, "big"))}]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def b64(data):
        return gc.base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def token(self, header=None, **changes):
        claims = {"iss": gc.ISSUER, "aud": "gate", "repository": REPO, "event_name": "pull_request",
                  "base_ref": "main", "ref": "refs/pull/7/merge", "head_ref": "topic", "run_id": "10",
                  "run_attempt": "1", "workflow_ref": f"{REPO}/.github/workflows/check.yml@refs/pull/7/merge"}
        claims.update(changes)
        head = self.b64(json.dumps(header or {"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
        body = self.b64(json.dumps(claims).encode())
        signature = openssl("dgst", "-sha256", "-sign", str(self.key), data=f"{head}.{body}".encode())
        return f"{head}.{body}.{self.b64(signature)}"

    def check(self, token, run_id=10, path=".github/workflows/check.yml"):
        return gc.proof_problem(gc.verify_rs256(token, self.jwks), {"id": run_id}, PR, REPO, path)

    def test_a_proof_from_this_run_on_this_pr_into_main_verifies(self):
        self.assertIsNone(self.check(self.token()))
        self.assertIsNone(self.check(self.token(aud=["other", "gate"])))

    def test_a_reran_attempt_keeps_its_runs_proof(self):
        # rerun --failed does not repeat the attestation job; the proof is bound to the run.
        self.assertIsNone(self.check(self.token(run_attempt="1")))

    def test_claims_that_do_not_prove_main_are_refused(self):
        for change in ({"base_ref": "probe-base"},                       # a PR into another branch
                       {"ref": "refs/pull/8/merge"},                     # another PR
                       {"head_ref": "renamed"},                          # a renamed branch's old runs
                       {"run_id": "11"},                                 # another run's proof
                       {"event_name": "pull_request_target"}, {"repository": "fork/r"},
                       {"aud": "other"}, {"iss": "https://example.invalid"},
                       {"workflow_ref": f"{REPO}/.github/workflows/x.yml@refs/pull/7/merge"},
                       {"workflow_ref": f"other/r/.github/workflows/check.yml@refs/pull/7/merge"}):
            with self.subTest(change=change):
                self.assertIsNotNone(self.check(self.token(**change)))

    def test_spec_proofs_name_spec_yml(self):
        token = self.token(workflow_ref=f"{REPO}/.github/workflows/spec.yml@refs/pull/7/merge")
        self.assertIsNone(self.check(token, path=".github/workflows/spec.yml"))
        self.assertIsNotNone(self.check(token))

    def test_bad_signatures_and_headers_are_refused(self):
        good = self.token()
        head, body, sig = good.split(".")
        forged_body = self.b64(json.dumps({"base_ref": "main"}).encode())
        cases = {
            "altered payload": f"{head}.{forged_body}.{sig}",
            "altered signature": f"{head}.{body}.{sig[:-4]}AAAA",
            "unknown kid": self.token(header={"alg": "RS256", "kid": "k2"}),
            "alg none": self.b64(json.dumps({"alg": "none", "kid": "k1"}).encode()) + f".{body}.",
            "alg HS256": self.token(header={"alg": "HS256", "kid": "k1"}),
            "not a JWT": "abc",
            "short signature": f"{head}.{body}.{self.b64(b'x' * 10)}",
        }
        for label, token in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                gc.verify_rs256(token, self.jwks)

    def test_proven_keeps_runs_with_a_valid_proof_and_says_why_others_are_left_out(self):
        runs = {".github/workflows/check.yml": [{"id": 10}, {"id": 11}, {"id": 12}],
                ".github/workflows/spec.yml": []}
        tokens = {10: ["junk", self.token()],                            # a bad token, then a good one
                  11: [self.token(run_id="11", base_ref="probe-base")],  # the base was changed later
                  12: []}
        kept, ignored = gc.proven(runs, PR, REPO, lambda run: tokens[run["id"]], self.jwks)
        self.assertEqual(kept[".github/workflows/check.yml"], [{"id": 10}])
        reasons = dict(ignored[".github/workflows/check.yml"])
        self.assertIn("base_ref", reasons[11])
        self.assertEqual(reasons[12], "no proof")

    def test_runs_without_proof_leave_the_context_undecided(self):
        runs, jobs = green()
        by_path = gc.qualifying(runs, REPO, PR, IDS)
        kept, ignored = gc.proven(by_path, PR, REPO, lambda run: [], self.jwks)
        result = {v["context"]: v for v in gc.verdicts(PR, kept, jobs, [], [], OWNER, POLICY_OK, ignored)}
        self.assertEqual(result["gate/check"]["status"], "in_progress")
        self.assertIn("without a valid proof", result["gate/check"]["summary"])

    def test_odd_headers_and_out_of_range_signatures_are_refused(self):
        good = self.token()
        head, body, sig = good.split(".")
        list_header = self.b64(b"[]") + f".{body}.{sig}"
        n = int.from_bytes(gc.b64url(self.jwks["keys"][0]["n"]), "big")
        too_big = self.b64((n + 1).to_bytes(256, "big"))
        for token in (list_header, f"{head}.{body}.{too_big}"):
            with self.subTest(token=token[:20]), self.assertRaises(ValueError):
                gc.verify_rs256(token, self.jwks)

    def test_a_broken_artifact_or_binding_is_no_proof_and_does_not_stop_judging(self):
        runs = {".github/workflows/check.yml": [{"id": 10}, {"id": 11}], ".github/workflows/spec.yml": []}

        def proofs(run):
            if run["id"] == 11:
                raise gc.zipfile.BadZipFile("junk")
            return [self.token()]

        kept, ignored = gc.proven(runs, PR, REPO, proofs, self.jwks, binding=lambda c: None)
        self.assertEqual(kept[".github/workflows/check.yml"], [{"id": 10}])
        self.assertIn("unreadable", dict(ignored[".github/workflows/check.yml"])[11])
        kept, ignored = gc.proven(runs, PR, REPO, lambda r: [self.token()], self.jwks,
                                  binding=lambda c: "ran other .github files")
        self.assertEqual(kept[".github/workflows/check.yml"], [])


class MergeBinding(unittest.TestCase):
    """merge_problem against a real repository: main, a head, and merges of them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

        def raw(*a):
            return subprocess.run(["git", "-C", self.dir, *a], capture_output=True, text=True, check=True).stdout

        self.raw = raw
        raw("init", "-q", "-b", "main")
        raw("config", "user.email", "t@example.invalid")
        raw("config", "user.name", "t")
        self.write(".github/workflows/check.yml", "honest\n")
        self.main1 = self.commit("main 1")
        raw("switch", "-q", "-c", "topic")
        self.write("src.txt", "change\n")
        self.head = self.commit("head")
        raw("switch", "-q", "main")
        self.write("other.txt", "main moves\n")
        self.main2 = self.commit("main 2")
        raw("switch", "-q", "-c", "planted", self.main1)
        self.write(".github/workflows/check.yml", "stub\n")
        self.planted = self.commit("planted")
        raw("switch", "-q", "main")
        self.pr = dict(PR, head=dict(PR["head"], sha=self.head))

    def write(self, path, text):
        target = Path(self.dir) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message):
        self.raw("add", "-A")
        self.raw("commit", "-q", "-m", message)
        return self.raw("rev-parse", "HEAD").strip()

    def merge(self, base):
        tree = self.raw("merge-tree", "--write-tree", base, self.head).split()[0]
        return self.raw("commit-tree", tree, "-p", base, "-p", self.head, "-m", "merge").strip()

    def git(self, *a):
        if a[0] == "fetch":
            return ""
        return self.raw(*a)

    def problem(self, sha, approved=False):
        return gc.merge_problem({"sha": sha}, self.pr, approved, git=self.git)

    def test_a_merge_of_the_head_into_main_binds(self):
        self.assertIsNone(self.problem(self.merge(self.main2)))
        self.assertIsNone(self.problem(self.merge(self.main1)))

    def test_a_merge_into_a_planted_base_is_refused(self):
        self.assertIn("not made on main", self.problem(self.merge(self.planted)))

    def test_a_merge_of_another_head_is_refused(self):
        other = self.raw("commit-tree", self.raw("rev-parse", f"{self.main2}^{{tree}}").strip(),
                         "-p", self.main2, "-p", self.planted, "-m", "x").strip()
        self.assertIn("not a merge of this head", self.problem(other))
        self.assertIn("not a merge of this head", self.problem(self.main2))

    def test_github_files_that_are_not_mains_need_an_approved_change(self):
        tree = self.raw("merge-tree", "--write-tree", self.main2, self.head).split()[0]
        self.write("x", "")
        self.raw("switch", "-q", "-c", "scratch", self.main2)
        self.raw("read-tree", tree)
        Path(self.dir, ".github/workflows/check.yml").write_text("changed in the merge\n")
        self.raw("add", ".github/workflows/check.yml")
        changed = self.raw("write-tree").strip()
        self.raw("switch", "-q", "-f", "main")
        sha = self.raw("commit-tree", changed, "-p", self.main2, "-p", self.head, "-m", "m").strip()
        self.assertIn("not main's", self.problem(sha))
        self.assertIsNone(self.problem(sha, approved=True))

    def test_no_merge_commit_in_the_proof_is_refused(self):
        self.assertEqual(gc.merge_problem({}, self.pr, False, git=self.git), "no merge commit in the proof")


class SigningKeys(unittest.TestCase):
    def test_retries_then_fails_closed(self):
        calls = []

        def urlopen(url, timeout):
            calls.append(url)
            raise OSError("down")

        with mock.patch.object(gc.urllib.request, "urlopen", urlopen), self.assertRaises(OSError):
            gc.signing_keys(tries=3, sleep=lambda s: None)
        self.assertEqual(calls, [gc.JWKS_URL] * 3)


class Repository(unittest.TestCase):
    def test_the_gate_workflow_passes_the_lint_and_names_its_triggers(self):
        text = (ROOT / ".github/workflows/gate.yml").read_text(encoding="utf-8")
        allowed = wl.load_allowed((ROOT / wl.ALLOW_FILE).read_text(encoding="utf-8"))
        self.assertEqual(wl.lint("gate.yml", text, allowed), [])
        for needle in ("workflows: [check, spec, policy, policy-refresh, gate-events]", "environment: gate",
                       "permission-checks: write", "if: always()", "cron: '*/10 * * * *'",
                       "judge --sweep", "post --app-id \"$APP_ID\" --sweep"):
            self.assertIn(needle, text)

    def test_gate_events_brings_retargets_closes_and_reopens_to_the_gate(self):
        text = (ROOT / ".github/workflows/gate-events.yml").read_text(encoding="utf-8")
        self.assertIn("name: gate-events\n", text)
        self.assertIn("pull_request_target:\n    types: [edited, closed, reopened]\n", text)
        self.assertNotIn("actions/checkout", text)
        self.assertNotIn("secrets", text.lower().replace("# ", ""))

    def test_the_judged_jobs_exist_in_their_workflows(self):
        check = (ROOT / ".github/workflows/check.yml").read_text(encoding="utf-8")
        spec = (ROOT / ".github/workflows/spec.yml").read_text(encoding="utf-8")
        self.assertIn("\n  check:\n", check)
        self.assertIn("part: [base, new, corpus]", spec)
        for text in (check, spec):
            self.assertIn("\n  pull_request:\n", text)
            self.assertIn("Only pull requests into main", text)
            # The proof job: its own job, OIDC only there, audience gate, the artifact judge reads.
            job = text.split("\n  gate-attestation:\n", 1)[1].split("\n  evidence-freshness:\n")[0]
            self.assertIn("      id-token: write\n", job)
            self.assertIn("audience=gate", job)
            self.assertIn("name: gate-attestation-${{ github.run_attempt }}", job)
            self.assertNotIn("actions/checkout", job)
            self.assertEqual(text.count("id-token: write"), 1)


if __name__ == "__main__":
    unittest.main()

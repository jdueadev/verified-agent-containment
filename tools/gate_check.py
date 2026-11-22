#!/usr/bin/env python3
"""Turn the required checks into gate App check runs (#137, stage 2).

Usage:
  gate_check.py judge (--head-sha SHA | --sweep) [--out FILE]
  gate_check.py post --app-id ID (--head-sha SHA | --sweep) --judge-result RESULT   (verdicts in $VERDICTS)

The `gate` workflow runs from main on `workflow_run`. Its `judge` job has no
secret. It calls `judge` with a read-only token, which writes one verdict per
gate context to the job's outputs. Its `post` job holds the gate App's key in
the main-only `gate` environment. It calls `post`, which creates each check
run once and then updates it in place. A context keeps one check run per head
commit: GitHub counts every same-name run from one App, so a fresh run per
event would let one early failure block for good (#136, P3).

judge works on the one open pull request into main, from this repository,
whose head is that commit:

- gate/policy does not come from a workflow run. judge runs main's own
  checkers against the head: `policy_check.py classify` (with the PR's reviews,
  and always with --enforce, because gate/policy is the authority; otherwise the arguments of
  policy.yml), `policy_check.py invariants --ref` and `workflow_lint.py --ref`.
  They read the head through git and run none of its code. A `policy` run can't
  be trusted: `pull_request_target` takes policy.yml from the PR's base, and
  nothing in a run says which base it was.
- gate/check and gate/spec (base|new|corpus) have to come from runs, because
  those jobs run the head's code. Nothing in a run's API record says which
  base it used, and three rounds of review broke every heuristic for it:
  requiring every run, the head branch's PR history, and branch renames. So a
  run counts only if it proves its base. check.yml and spec.yml each have a
  `gate-attestation` job that runs no head code, mints a GitHub OIDC token
  with audience `gate`, and uploads it as an artifact. judge verifies the
  token's RS256 signature against GitHub's published key set. Then it checks
  the claims GitHub sets from the event:
  - `repository` is this repository and `event_name` is `pull_request`;
  - `base_ref` is `main` and `ref` is this PR's `refs/pull/N/merge`;
  - `head_ref` is the PR's head branch;
  - `run_id` is the run's id, and `workflow_ref` is main's workflow file.

  The token's `sha` claim is the merge commit the run checked out. judge
  fetches it and requires that its second parent is the PR's head, that its
  first parent is a commit on main, and that its `.github` tree is that
  parent's. The only exception is a `.github` change the owner has approved at
  this head. So the code that ran is main's, plus the head.

  A run without a valid proof is ignored, never counted. The proof is bound to
  the run, not the attempt, because a re-run reuses the original event and
  `rerun --failed` does not repeat the attestation job. Expiry is not
  enforced: the proof attests a fact, it is not a login. A run must also have
  main's workflow path and id, `pull_request` as its event, this repository as
  its head, and the PR's head commit.
- Each of those contexts is one required job, and the job is judged, not the
  run. `evidence-freshness` isn't required, and main may carry stale claims.
  Success needs at least one qualifying run, and every qualifying run's latest
  attempt of that job must have succeeded, with no run still going. A
  cancelled job is skipped when another qualifying run of it exists; on its
  own, it fails.
- If the pull request changes `.github` or anything under it, from its merge
  base to its head, then the head's own workflow files decided check and spec.
  Those contexts then also need the owner's latest review to approve exactly
  this head, the rule `policy` uses.

Any error, or more than one open pull request into main with this head, makes
every context fail for that commit. If no open pull request into main has
this head, for example because one was retargeted or closed, the gate's
existing check runs on it are set to failure, and none are created. A
result posted earlier is never left standing because judging went wrong or
the pull request moved. The `gate-events` workflow brings a retarget to main,
a close or a reopen here. Whether a retarget away from main is seen depends
on the new base's copy of that workflow, which is why the stale results get
updated whenever this workflow next runs for that head.

judge never waits. It judges what has finished when it runs: a qualifying run
still going leaves its context undecided, and over an existing check run that
is posted as a failure. So a withdrawn approval or a new run takes effect at
once, and a stale success is never held open. Each completion of check, spec,
policy, policy-refresh or gate-events runs the gate again for that head. A
sweep every ten minutes (`--sweep`, on schedule) judges the head of every open
pull request from this repository, whatever its base. That covers re-runs
started by GITHUB_TOKEN, which may not fire `workflow_run`, and pull requests
retargeted away from main, whose new base's workflows the agent controls.

Known residual: a pull request retargeted away from main and back within one
sweep keeps its earlier gate results until the gate runs for the `edited`
event, which takes about a minute. It matters only if the owner withdrew an
approval in between. For .github and code-owner paths, the ruleset's
code-owner review still blocks that merge.

What this rests on:
- The ruleset's up-to-date rule. A head that predates a change to main's
  workflows looks unchanged against its merge base, but it can't merge until
  it is brought up to date, and that makes a new commit.
- GitHub's OIDC issuer and its key set. Fetching the keys is retried, and any
  failure fails every context.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check  # noqa: E402  (owner and the approval rule, from the same main checkout)

ROOT = Path(__file__).resolve().parent.parent
SHA = re.compile(r"[0-9a-f]{40}")
# workflow file -> {gate context: required job name}; all on pull_request.
RUN_WORKFLOWS = {
    ".github/workflows/check.yml": {"gate/check": "check"},
    ".github/workflows/spec.yml": {"gate/spec (base)": "spec (base)", "gate/spec (new)": "spec (new)",
                                   "gate/spec (corpus)": "spec (corpus)"},
}
POLICY = "gate/policy"
CONTEXTS = [c for jobs in RUN_WORKFLOWS.values() for c in jobs] + [POLICY]
ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = ISSUER + "/.well-known/jwks"
AUDIENCE = "gate"
PROOF_PREFIX = "gate-attestation-"
SUMMARY_LIMIT = 1000
# DER prefix of a SHA-256 DigestInfo, for PKCS#1 v1.5 signatures (RFC 8017, section 9.2).
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def verdict(context, status, conclusion, summary):
    return {"context": context, "status": status, "conclusion": conclusion, "summary": summary}


def all_failed(summary):
    return [verdict(c, "completed", "failure", summary) for c in CONTEXTS]


# ---------- the verdict, as pure functions ----------

def qualifying(runs, repo, pr, workflow_ids):
    """{workflow path: [run, ...]} for the runs that count."""
    out = {path: [] for path in RUN_WORKFLOWS}
    for run in runs:
        path = run.get("path")
        if (path in RUN_WORKFLOWS and run.get("event") == "pull_request"
                and run.get("workflow_id") == workflow_ids.get(path)
                and run.get("head_sha") == pr["head"]["sha"]
                and (run.get("head_repository") or {}).get("full_name") == repo):
            out[path].append(run)
    return out


def b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_rs256(token, keys):
    """The claims of a JWT whose RS256 signature verifies under one of `keys` (a JWKS),
    or ValueError. Only RS256 is accepted; the header cannot pick another algorithm."""
    try:
        head64, body64, sig64 = token.strip().split(".")
        header = json.loads(b64url(head64))
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"not a JWT: {error}") from error
    if not isinstance(header, dict) or not isinstance(keys, dict):
        raise ValueError("not a JWT header or key set")
    if header.get("alg") != "RS256":
        raise ValueError(f"algorithm {header.get('alg')!r}, not RS256")
    found = [k for k in keys.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"]
    if len(found) != 1:
        raise ValueError(f"no single key with kid {header.get('kid')!r}")
    n = int.from_bytes(b64url(found[0]["n"]), "big")
    e = int.from_bytes(b64url(found[0]["e"]), "big")
    size = (n.bit_length() + 7) // 8
    signature = b64url(sig64)
    if size < 256 or len(signature) != size or int.from_bytes(signature, "big") >= n:
        raise ValueError("bad signature length or value")
    digest = hashlib.sha256(f"{head64}.{body64}".encode("ascii")).digest()
    wanted = b"\x00\x01" + b"\xff" * (size - len(SHA256_INFO) - len(digest) - 3) + b"\x00" + SHA256_INFO + digest
    got = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    if not hmac.compare_digest(got, wanted):
        raise ValueError("signature does not verify")
    return json.loads(b64url(body64))


def proof_problem(claims, run, pr, repo, path):
    """Why these claims do not prove that `run` judged `pr` against main, or None."""
    aud = claims.get("aud")
    wanted = {
        "iss": ISSUER, "repository": repo, "event_name": "pull_request", "base_ref": "main",
        "ref": f"refs/pull/{pr['number']}/merge", "head_ref": pr["head"]["ref"], "run_id": str(run["id"]),
    }
    wrong = [k for k, v in wanted.items() if claims.get(k) != v]
    if not (aud == AUDIENCE or (isinstance(aud, list) and AUDIENCE in aud)):
        wrong.append("aud")
    if not str(claims.get("workflow_ref", "")).startswith(f"{repo}/{path}@"):
        wrong.append("workflow_ref")
    return f"claims {', '.join(wrong)} do not match" if wrong else None


def proven(by_path, pr, repo, proofs_of, keys, binding=lambda claims: None):
    """Keep only the runs whose proof verifies. `proofs_of(run)` returns the tokens a
    run uploaded; `binding(claims)` checks the merge commit that ran. Returns
    ({path: [run]}, {path: [(run id, why)]}). Anything odd about a proof, or about
    fetching it, makes that proof count for nothing; it never stops the judging."""
    kept, ignored = {}, {}
    for path, runs in by_path.items():
        kept[path], ignored[path] = [], []
        for run in runs:
            reasons = []
            try:
                tokens = proofs_of(run)
            except Exception as error:  # noqa: BLE001  a broken artifact is no proof
                tokens, reasons = [], [f"proof unreadable: {type(error).__name__}"]
            for token in tokens:
                try:
                    claims = verify_rs256(token, keys)
                    problem = proof_problem(claims, run, pr, repo, path) or binding(claims)
                except Exception as error:  # noqa: BLE001
                    problem = f"bad proof: {type(error).__name__}: {error}"[:200]
                if problem is None:
                    kept[path].append(run)
                    break
                reasons.append(problem)
            else:
                ignored[path].append((run["id"], "; ".join(reasons) or "no proof"))
    return kept, ignored


def merge_problem(claims, pr, workflows_approved, git=None):
    """Why the merge commit a run checked out (its `sha` claim) is not main plus this
    head, or None. `workflows_approved`: the head changes .github and the owner
    approved this head, so a .github difference is allowed."""
    git = git or globals()["git"]
    sha = claims.get("sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        return "no merge commit in the proof"
    git("fetch", "--quiet", "--no-tags", "origin", sha)
    parents = git("rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) != 2 or parents[1] != pr["head"]["sha"]:
        return f"merge commit {sha[:12]} is not a merge of this head"
    try:
        git("merge-base", "--is-ancestor", parents[0], "HEAD")  # HEAD: this checkout of main
    except subprocess.CalledProcessError:
        return f"merge commit {sha[:12]} was not made on main"
    tree = lambda commit: git("rev-parse", "--verify", "--quiet", f"{commit}:.github").strip()
    if tree(sha) != tree(parents[0]) and not workflows_approved:
        return f"merge commit {sha[:12]} ran .github files that are not main's"
    return None


def touches_workflows(path):
    return path == ".github" or path.startswith(".github/")


def verdicts(pr, runs_by_path, jobs_by_run, changed_paths, reviews, owner, policy, ignored=None):
    """Every context's verdict. `runs_by_path` holds only proven runs; `jobs_by_run` maps
    a run id to its latest attempt's jobs; `policy` is (passed, summary) from main's
    checkers; `ignored` lists runs left out for want of a proof."""
    changed = sorted(p for p in changed_paths if touches_workflows(p))
    approved = policy_check.approved(reviews, owner, pr["head"]["sha"])
    out = []
    for path, jobs in RUN_WORKFLOWS.items():
        runs = sorted(runs_by_path.get(path, []), key=lambda r: r["id"])
        skipped = (ignored or {}).get(path, [])
        note = f" Ignored {len(skipped)} run(s) without a valid proof of base main." if skipped else ""
        for context, job_name in jobs.items():
            v = run_verdict(context, job_name, runs, jobs_by_run, changed, approved, owner)
            v["summary"] += note
            out.append(v)
    passed, summary = policy
    out.append(verdict(POLICY, "completed", "success" if passed else "failure", summary))
    return out


def run_verdict(context, job_name, runs, jobs_by_run, changed, approved, owner):
    if changed and not approved:
        return verdict(context, "completed", "failure",
                       f"This pull request changes {len(changed)} path(s) under .github, so the head's own "
                       f"workflows decide `{job_name}`. It needs {owner}'s approval of this head commit.")
    if not runs:
        return verdict(context, "in_progress", None, f"No qualifying run with job `{job_name}` yet.")
    if any(r.get("status") != "completed" for r in runs):
        return verdict(context, "in_progress", None, f"A qualifying run with job `{job_name}` is still going.")
    results = []
    for run in runs:
        found = [j for j in jobs_by_run.get(run["id"], []) if j.get("name") == job_name]
        if len(found) != 1:
            return verdict(context, "completed", "failure", f"Run {run['id']} has {len(found)} jobs named `{job_name}`.")
        results.append((run["id"], found[0].get("conclusion")))
    counted = [(i, c) for i, c in results if c != "cancelled"] or results
    bad = [(i, c) for i, c in counted if c != "success"]
    if bad:
        return verdict(context, "completed", "failure",
                       "Job `{}` did not succeed: {}.".format(job_name, ", ".join(f"run {i} {c}" for i, c in bad)))
    ids = ", ".join(str(i) for i, _ in counted)
    note = f" Its .github changes are approved by {owner} at this head." if changed else ""
    return verdict(context, "completed", "success", f"Job `{job_name}` succeeded in runs {ids}.{note}")


# ---------- GitHub and git ----------

def gh(*args, data=None):
    result = subprocess.run(["gh", "api", *args], input=None if data is None else json.dumps(data),
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def pages(path):
    """Every item of a paginated list endpoint. --slurp gives one entry per page; a page
    is a list, or an object whose one list (workflow_runs, jobs, check_runs) holds the items."""
    out = []
    for page in gh("--paginate", "--slurp", path):
        if isinstance(page, list):
            out.extend(page)
            continue
        lists = [v for v in page.values() if isinstance(v, list)]
        if len(lists) != 1:
            raise RuntimeError(f"{path}: a page with {len(lists)} lists")
        out.extend(lists[0])
    return out


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout


def open_pr_into_main(repo, head_sha):
    prs = [p for p in pages(f"repos/{repo}/commits/{head_sha}/pulls?per_page=100")
           if p.get("state") == "open" and p["base"]["ref"] == "main"
           and (p["head"].get("repo") or {}).get("full_name") == repo and p["head"]["sha"] == head_sha]
    if len(prs) > 1:
        raise RuntimeError(f"{len(prs)} open pull requests into main have head {head_sha}")
    return prs[0] if prs else None


def proofs_of(repo):
    """A function from a run to the tokens its gate-attestation job uploaded, any attempt."""
    def tokens(run):
        out = []
        for artifact in pages(f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=100"):
            if (not artifact.get("name", "").startswith(PROOF_PREFIX) or artifact.get("expired")
                    or not 0 < int(artifact.get("size_in_bytes") or 0) <= 65536):
                continue
            data = subprocess.run(["gh", "api", f"repos/{repo}/actions/artifacts/{artifact['id']}/zip"],
                                  capture_output=True, check=True).stdout
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
                if names != ["gate-attestation.jwt"]:
                    continue
                if archive.getinfo(names[0]).file_size > 16384:
                    continue
                out.append(archive.read(names[0]).decode("ascii", "replace"))
        return out
    return tokens


def signing_keys(tries=3, sleep=time.sleep):
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(JWKS_URL, timeout=20) as response:
                return json.loads(response.read())
        except (OSError, ValueError):
            if attempt == tries - 1:
                raise
            sleep(5)


def sweep_heads(repo):
    """The head of every open pull request from this repository, whatever its base."""
    prs = pages(f"repos/{repo}/pulls?state=open&per_page=100")
    return sorted({p["head"]["sha"] for p in prs if (p["head"].get("repo") or {}).get("full_name") == repo})


def fetch_head(pr):
    git("fetch", "--quiet", "--no-tags", "origin", pr["base"]["sha"])
    git("fetch", "--quiet", "--no-tags", "origin", f"pull/{pr['number']}/head")
    if git("rev-parse", "FETCH_HEAD").strip() != pr["head"]["sha"]:
        raise RuntimeError("pull/N/head moved while judging; the next run judges the new head")
    return git("merge-base", pr["base"]["sha"], pr["head"]["sha"]).strip()


def changed_paths(base, head):
    """Read through git: the compare API stops at 300 files."""
    return [p for p in git("diff", "--name-only", "--no-renames", "-z", base, head).split("\0") if p]


def policy_result(pr, merge_base, reviews_file, enforce):
    """main's checkers against the head, with the arguments policy.yml uses. None runs head code."""
    head, base_sha = pr["head"]["sha"], pr["base"]["sha"]
    classify = ["classify", "--base", merge_base, "--map-ref", base_sha, "--head", head,
                "--reviews", str(reviews_file), "--head-sha", head] + (["--enforce"] if enforce else [])
    steps = [("classify", [sys.executable, str(ROOT / "tools/policy_check.py"), *classify]),
             ("invariants", [sys.executable, str(ROOT / "tools/policy_check.py"), "invariants", "--ref", head]),
             ("workflow lint", [sys.executable, str(ROOT / "tools/workflow_lint.py"), "--ref", head])]
    failed = [name for name, cmd in steps
              if subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).returncode != 0]
    if failed:
        return False, f"main's checkers failed on this head: {', '.join(failed)}. The `policy` run's log has the details."
    return True, "main's lane classifier, invariants and workflow lint passed on this head."


def judge(head_sha):
    """(pr number or None, verdicts). With no open PR into main, the verdicts are all
    failures with pr None, which post only applies to check runs that already exist."""
    repo = os.environ["GITHUB_REPOSITORY"]
    if not SHA.fullmatch(head_sha):
        raise ValueError(f"not a commit id: {head_sha!r}")
    pr = open_pr_into_main(repo, head_sha)
    if pr is None:
        return None, all_failed("No open pull request into main has this head commit.")
    owner, _ = policy_check.load_lanes((ROOT / policy_check.LANES_FILE).read_text(encoding="utf-8"))
    workflow_ids = {p: gh(f"repos/{repo}/actions/workflows/{p.rsplit('/', 1)[1]}")["id"] for p in RUN_WORKFLOWS}
    by_path = qualifying(pages(f"repos/{repo}/actions/runs?head_sha={head_sha}&per_page=100"), repo, pr, workflow_ids)
    reviews = pages(f"repos/{repo}/pulls/{pr['number']}/reviews?per_page=100")
    merge_base = fetch_head(pr)
    changed = changed_paths(merge_base, head_sha)
    workflows_approved = any(touches_workflows(p) for p in changed) and policy_check.approved(reviews, owner, head_sha)
    by_path, ignored = proven(by_path, pr, repo, proofs_of(repo), signing_keys(),
                              lambda claims: merge_problem(claims, pr, workflows_approved))
    jobs = {r["id"]: pages(f"repos/{repo}/actions/runs/{r['id']}/jobs?filter=latest&per_page=100")
            for rs in by_path.values() for r in rs if r.get("status") == "completed"}
    reviews_file = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"gate-reviews-{head_sha}.json"
    reviews_file.write_text(json.dumps(reviews), encoding="utf-8")
    # Always enforcing: gate/policy is the authority, whatever POLICY_ENFORCE says.
    policy = policy_result(pr, merge_base, reviews_file, True)
    return pr["number"], verdicts(pr, by_path, jobs, changed, reviews, owner, policy, ignored)


# ---------- posting ----------

def checked_batch(data, head_sha=None):
    """One head's verdicts, as judge produces them. With `head_sha`, it must be that commit."""
    if not isinstance(data, dict) or set(data) != {"head_sha", "pr", "verdicts"}:
        raise ValueError("verdicts: expected head_sha, pr and verdicts")
    if not SHA.fullmatch(str(data["head_sha"])) or (head_sha is not None and data["head_sha"] != head_sha) \
            or not (data["pr"] is None or (isinstance(data["pr"], int) and not isinstance(data["pr"], bool))):
        raise ValueError("verdicts: bad head_sha or pr")
    seen = []
    for v in data["verdicts"]:
        if (not isinstance(v, dict) or set(v) != {"context", "status", "conclusion", "summary"}
                or v["context"] not in CONTEXTS
                or (v["status"], v["conclusion"]) not in (("in_progress", None), ("completed", "success"),
                                                          ("completed", "failure"))
                or not isinstance(v["summary"], str)):
            raise ValueError(f"verdicts: bad entry {v!r}")
        seen.append(v["context"])
    if sorted(seen) != sorted(CONTEXTS):
        raise ValueError(f"verdicts: expected every context once, got {seen}")
    return data


def checked_verdicts(text, head_sha=None):
    """The post job takes only what judge can produce: a list of batches, one per head.
    For a workflow_run trigger there is exactly one, for the triggering commit."""
    data = json.loads(text)
    if not isinstance(data, list) or (head_sha is not None and len(data) != 1):
        raise ValueError("verdicts: expected a list of batches (one for a triggered run)")
    heads = [checked_batch(b, head_sha)["head_sha"] for b in data]
    if len(set(heads)) != len(heads):
        raise ValueError("verdicts: a head appears twice")
    return data


def post(data, app_id, repo):
    """Failures first, and every context is attempted even if one write fails, so a
    failed write cannot leave the contexts after it standing on an old success."""
    head = data["head_sha"]
    where = f"PR #{data['pr']}. " if data["pr"] else ""
    errors = []
    for v in sorted(data["verdicts"], key=lambda v: v["conclusion"] != "failure"):
        try:
            # Without a pull request into main, only existing check runs are updated (to
            # failure); creating gate results for a commit no PR into main has is noise.
            post_one(v, head, where, app_id, repo, create=data["pr"] is not None)
        except subprocess.CalledProcessError as error:
            errors.append(f"{v['context']}: {error.stderr or error}")
    if errors:
        raise RuntimeError("; ".join(errors))


def post_one(v, head, where, app_id, repo, create=True):
    name = urllib.parse.quote(v["context"], safe="")
    mine = [c for c in pages(f"repos/{repo}/commits/{head}/check-runs?check_name={name}"
                             f"&app_id={app_id}&filter=all&per_page=100")
            if str((c.get("app") or {}).get("id")) == str(app_id) and c.get("name") == v["context"]]
    status, conclusion, summary = v["status"], v["conclusion"], v["summary"]
    if mine and status == "in_progress":
        # A completed run is not moved back to in_progress. "Not decided yet" is posted
        # as a failure, so it blocks and cannot leave an earlier success standing.
        status, conclusion, summary = "completed", "failure", "Not decided yet: " + summary
    summary = (where + summary)[:SUMMARY_LIMIT]
    body = {"name": v["context"], "head_sha": head, "status": status,
            "output": {"title": v["context"], "summary": summary}}
    if status == "completed":
        body["conclusion"] = conclusion
    if not mine and create:
        gh("--method", "POST", f"repos/{repo}/check-runs", "--input", "-", data=body)
    for run in mine:
        # One check run per context, kept current. More than one means two creates raced.
        # Every copy gets the same verdict, so none of them can disagree.
        gh("--method", "PATCH", f"repos/{repo}/check-runs/{run['id']}", "--input", "-",
           data={k: b for k, b in body.items() if k != "head_sha"})
    print(f"{v['context']}: {status} {conclusion or ''}")


def judged(head_sha):
    """One batch for one head; any error fails every context with no PR."""
    try:
        pr, result = judge(head_sha)
    except Exception as error:  # noqa: BLE001  every failure must fail the contexts
        print(f"gate_check: judging {head_sha} failed: {error} {getattr(error, 'stderr', '') or ''}".strip(),
              file=sys.stderr)
        pr, result = None, all_failed(f"Judging this commit failed ({type(error).__name__}); see the gate run's log.")
    return {"head_sha": head_sha, "pr": pr, "verdicts": result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("judge", "post"):
        p = sub.add_parser(name)
        which = p.add_mutually_exclusive_group(required=True)
        which.add_argument("--head-sha")
        which.add_argument("--sweep", action="store_true", help="every open pull request's head (on schedule)")
        if name == "judge":
            p.add_argument("--out", help="append `verdicts=<json>` here (the job's GITHUB_OUTPUT)")
        else:
            p.add_argument("--app-id", required=True)
            p.add_argument("--judge-result", required=True, help="the judge job's result: success, failure, ...")
    args = parser.parse_args(argv)
    if args.command == "judge":
        if args.sweep:
            try:
                heads = sweep_heads(os.environ["GITHUB_REPOSITORY"])
            except Exception as error:  # noqa: BLE001  nothing known to fail; the next sweep retries
                sys.exit(f"gate_check: sweep could not list pull requests: {error}")
        else:
            heads = [args.head_sha]
        batches = [judged(h) for h in heads]
        print(json.dumps(batches, indent=2))
        if args.out:
            with open(args.out, "a", encoding="utf-8") as handle:
                handle.write(f"verdicts={json.dumps(batches, separators=(',', ':'))}\n")
        return 0
    try:
        if not re.fullmatch(r"[0-9]+", args.app_id):
            raise ValueError("--app-id must be a number")
        text = os.environ.get("VERDICTS", "")
        if not text:
            if args.sweep:
                print("The sweep's judge produced nothing; the next sweep retries.")
                return 0
            # judge itself died (it always writes verdicts otherwise): fail every context
            # on this commit that already has a check run.
            text = json.dumps([{"head_sha": args.head_sha, "pr": None,
                                "verdicts": all_failed(f"The judge job ended '{args.judge_result}'.")}])
        errors = []
        for batch in checked_verdicts(text, None if args.sweep else args.head_sha):
            try:
                post(batch, args.app_id, os.environ["GITHUB_REPOSITORY"])
            except (subprocess.CalledProcessError, RuntimeError) as error:
                errors.append(f"{batch['head_sha'][:12]}: {error}")
        if errors:
            raise RuntimeError("; ".join(errors))
        return 0
    except (subprocess.CalledProcessError, ValueError, RuntimeError, KeyError) as error:
        sys.exit(f"gate_check: {error} {getattr(error, 'stderr', '') or ''}".strip())


if __name__ == "__main__":
    sys.exit(main())

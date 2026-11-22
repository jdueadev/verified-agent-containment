#!/usr/bin/env python3
"""Turn the required workflows' results into gate App check runs (#137, stage 2).

Usage:
  gate_check.py judge --head-sha SHA [--out FILE]
  gate_check.py post --app-id ID          (verdicts in the VERDICTS environment variable)

The `gate` workflow runs from main on `workflow_run`. Its `judge` job has no
secret. It calls `judge` with a read-only token, and writes one verdict per
gate context to the job's outputs. Its `post` job holds the gate App's key in
the main-only `gate` environment. It calls `post`, which creates each check
run once and then updates it in place. A context gets one check run per head
commit because GitHub counts every same-name run from one App, so a fresh run
per event would let one early failure block for good (#136, P3).

judge, for the one open pull request into main whose head is that commit, in
this repository:

- A run qualifies when its event, workflow file path and workflow id are
  main's (check.yml on pull_request, spec.yml on pull_request,
  policy.yml on pull_request_target), its head is this repository, and its
  head commit is the pull request's. A branch-only workflow that calls itself
  `check` has a different path or id, so it is ignored, never trusted.
- Each context is one required job: gate/check, gate/spec (base),
  gate/spec (new), gate/spec (corpus) and gate/policy. The job is judged, not
  the run. `evidence-freshness` is not required, and main may carry stale
  claims.
- Success needs at least one qualifying run, every qualifying run's latest
  attempt of that job to have succeeded, and no qualifying run still going.
  A cancelled job counts only when no other qualifying run of that job
  exists, and then it is a failure. Every run must pass because the runs API
  cannot tell a pull request into main from one into another branch on the
  same commit. A run from another base fails at its workflow's base guard
  (#136), so requiring all of them only ever blocks, never passes.
- If the pull request changes anything under `.github/` (from its merge base
  to its head), the head's own workflow files decided those results. Each
  context then also needs the owner's latest review to approve exactly this
  head commit, the same rule `policy` uses.

judge waits, up to its deadline, for qualifying runs that are still going.
After an approval, policy-refresh re-runs `policy` and `spec`, and its own
completion triggers this workflow. Whether a re-run started by GITHUB_TOKEN
fires `workflow_run` itself is not known, so judge waits for those re-runs
instead of relying on it.

What this rests on: the base guards in check.yml, spec.yml and policy.yml,
and the ruleset's up-to-date rule. A head older than a workflow change on
main looks unchanged against its merge base, but it cannot merge until it is
brought up to date, and that makes a new commit with new runs.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check  # noqa: E402  (owner and the approval rule, from the same base checkout)

ROOT = Path(__file__).resolve().parent.parent
SHA = re.compile(r"[0-9a-f]{40}")
# workflow file -> (event, {gate context: required job name})
WORKFLOWS = {
    ".github/workflows/check.yml": ("pull_request", {"gate/check": "check"}),
    ".github/workflows/spec.yml": ("pull_request", {"gate/spec (base)": "spec (base)", "gate/spec (new)": "spec (new)",
                                                    "gate/spec (corpus)": "spec (corpus)"}),
    ".github/workflows/policy.yml": ("pull_request_target", {"gate/policy": "policy"}),
}
CONTEXTS = [c for _, jobs in WORKFLOWS.values() for c in jobs]
WAIT_SECONDS, POLL_SECONDS = 40 * 60, 30


# ---------- the verdict, as a pure function ----------

def qualifying(runs, repo, head_sha, workflow_ids):
    """{workflow path: [run, ...]} for the runs that count."""
    out = {path: [] for path in WORKFLOWS}
    for run in runs:
        path = run.get("path")
        if path not in WORKFLOWS:
            continue
        event, _ = WORKFLOWS[path]
        if (run.get("event") == event and run.get("workflow_id") == workflow_ids.get(path)
                and run.get("head_sha") == head_sha
                and ((run.get("head_repository") or {}).get("full_name") == repo)):
            out[path].append(run)
    return out


def verdicts(pr, runs_by_path, jobs_by_run, changed_paths, reviews, owner):
    """One verdict per context: {"context", "status", "conclusion", "summary"}.
    `jobs_by_run` maps a run id to the jobs of its latest attempt."""
    head = pr["head"]["sha"]
    workflows_changed = sorted(p for p in changed_paths if p.startswith(".github/"))
    approved = policy_check.approved(reviews, owner, head)
    out = []
    for path, (_, jobs) in WORKFLOWS.items():
        runs = sorted(runs_by_path.get(path, []), key=lambda r: r["id"])
        for context, job_name in jobs.items():
            out.append(one_verdict(context, job_name, runs, jobs_by_run, workflows_changed, approved, owner))
    return out


def one_verdict(context, job_name, runs, jobs_by_run, workflows_changed, approved, owner):
    def verdict(status, conclusion, summary):
        return {"context": context, "status": status, "conclusion": conclusion, "summary": summary}

    if not runs:
        return verdict("in_progress", None, f"No qualifying run with job `{job_name}` yet.")
    if any(r.get("status") != "completed" for r in runs):
        return verdict("in_progress", None, f"A qualifying run with job `{job_name}` is still going.")
    results = []
    for run in runs:
        found = [j for j in jobs_by_run.get(run["id"], []) if j.get("name") == job_name]
        if len(found) != 1:
            return verdict("completed", "failure", f"Run {run['id']} has {len(found)} jobs named `{job_name}`.")
        results.append((run["id"], found[0].get("conclusion")))
    counted = [(i, c) for i, c in results if c != "cancelled"] or results
    bad = [(i, c) for i, c in counted if c != "success"]
    if bad:
        return verdict("completed", "failure",
                       "Job `{}` did not succeed: {}.".format(job_name, ", ".join(f"run {i} {c}" for i, c in bad)))
    ids = ", ".join(str(i) for i, _ in counted)
    if workflows_changed and not approved:
        return verdict("completed", "failure",
                       f"Job `{job_name}` succeeded (runs {ids}), but this pull request changes "
                       f"{', '.join(workflows_changed[:5])}, so the head's own workflows decided it. "
                       f"It needs {owner}'s approval of this head commit.")
    note = f" The workflow changes are approved by {owner} at this head." if workflows_changed else ""
    return verdict("completed", "success", f"Job `{job_name}` succeeded in runs {ids}.{note}")


# ---------- GitHub, through gh ----------

def gh(*args, data=None):
    result = subprocess.run(["gh", "api", *args], input=None if data is None else json.dumps(data),
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def pages(path):
    """Every item of a paginated list endpoint. --slurp returns one entry per page."""
    out = []
    for page in gh("--paginate", "--slurp", path):
        out.extend(page if isinstance(page, list) else next(v for k, v in page.items() if isinstance(v, list)))
    return out


def open_pr_into_main(repo, head_sha):
    prs = [p for p in gh(f"repos/{repo}/commits/{head_sha}/pulls")
           if p.get("state") == "open" and p["base"]["ref"] == "main"
           and (p["head"].get("repo") or {}).get("full_name") == repo and p["head"]["sha"] == head_sha]
    if len(prs) > 1:
        raise RuntimeError(f"{len(prs)} open pull requests into main have head {head_sha}")
    return prs[0] if prs else None


def changed_paths(pr):
    """Paths from the merge base to the head, read through git: the compare API stops at 300 files."""
    git = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True, check=True).stdout
    git("fetch", "--quiet", "--no-tags", "origin", pr["base"]["sha"])
    git("fetch", "--quiet", "--no-tags", "origin", f"pull/{pr['number']}/head")
    if git("rev-parse", "FETCH_HEAD").strip() != pr["head"]["sha"]:
        raise RuntimeError("pull/N/head moved while judging; the next run judges the new head")
    out = git("diff", "--name-only", "--no-renames", "-z", f"{pr['base']['sha']}...{pr['head']['sha']}")
    return [p for p in out.split("\0") if p]


def judge(head_sha, now=time.monotonic, sleep=time.sleep):
    repo = os.environ["GITHUB_REPOSITORY"]
    if not SHA.fullmatch(head_sha):
        raise ValueError(f"not a commit id: {head_sha!r}")
    pr = open_pr_into_main(repo, head_sha)
    if pr is None:
        return None, []
    owner, _ = policy_check.load_lanes((ROOT / policy_check.LANES_FILE).read_text(encoding="utf-8"))
    workflow_ids = {path: gh(f"repos/{repo}/actions/workflows/{path.rsplit('/', 1)[1]}")["id"] for path in WORKFLOWS}
    deadline = now() + WAIT_SECONDS
    while True:
        runs = pages(f"repos/{repo}/actions/runs?head_sha={head_sha}&per_page=100")
        by_path = qualifying(runs, repo, head_sha, workflow_ids)
        going = [r for rs in by_path.values() for r in rs if r.get("status") != "completed"]
        if not going or now() >= deadline:
            break
        sleep(POLL_SECONDS)
    jobs = {r["id"]: pages(f"repos/{repo}/actions/runs/{r['id']}/jobs?filter=latest&per_page=100")
            for rs in by_path.values() for r in rs if r.get("status") == "completed"}
    reviews = pages(f"repos/{repo}/pulls/{pr['number']}/reviews?per_page=100")
    return pr, verdicts(pr, by_path, jobs, changed_paths(pr), reviews, owner)


def checked_verdicts(text):
    """The post job takes only what judge can produce."""
    data = json.loads(text)
    if not isinstance(data, dict) or set(data) != {"head_sha", "pr", "verdicts"}:
        raise ValueError("verdicts: expected head_sha, pr and verdicts")
    if not SHA.fullmatch(str(data["head_sha"])) or not isinstance(data["pr"], int):
        raise ValueError("verdicts: bad head_sha or pr")
    seen = []
    for v in data["verdicts"]:
        if (set(v) != {"context", "status", "conclusion", "summary"} or v["context"] not in CONTEXTS
                or (v["status"], v["conclusion"]) not in (("in_progress", None), ("completed", "success"),
                                                          ("completed", "failure"))
                or not isinstance(v["summary"], str)):
            raise ValueError(f"verdicts: bad entry {v!r}")
        seen.append(v["context"])
    if sorted(seen) != sorted(CONTEXTS):
        raise ValueError(f"verdicts: expected every context once, got {seen}")
    return data


def post(data, app_id, repo):
    head = data["head_sha"]
    for v in data["verdicts"]:
        body = {"name": v["context"], "head_sha": head, "status": v["status"],
                "output": {"title": v["context"], "summary": f"PR #{data['pr']}. {v['summary']}"}}
        if v["status"] == "completed":
            body["conclusion"] = v["conclusion"]
        name = urllib.parse.quote(v["context"], safe="")
        mine = [c for c in pages(f"repos/{repo}/commits/{head}/check-runs?check_name={name}"
                                 f"&app_id={app_id}&filter=all&per_page=100")
                if str((c.get("app") or {}).get("id")) == str(app_id)]
        if not mine:
            gh("--method", "POST", f"repos/{repo}/check-runs", "--input", "-", data=body)
        for run in mine:
            # One check run per context, kept current. More than one means an earlier
            # create raced; every copy gets the same verdict, so none of them can disagree.
            gh("--method", "PATCH", f"repos/{repo}/check-runs/{run['id']}", "--input", "-",
               data={k: b for k, b in body.items() if k != "head_sha"})
        print(f"{v['context']}: {v['status']} {v['conclusion'] or ''}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--head-sha", required=True)
    j.add_argument("--out", help="append `verdicts=<json>` here (the job's GITHUB_OUTPUT)")
    p = sub.add_parser("post")
    p.add_argument("--app-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "judge":
            pr, result = judge(args.head_sha)
            line = "" if pr is None else json.dumps({"head_sha": args.head_sha, "pr": pr["number"],
                                                     "verdicts": result}, separators=(",", ":"))
            print(json.dumps(result, indent=2) if pr else f"No open pull request into main has head {args.head_sha}.")
            if args.out:
                with open(args.out, "a", encoding="utf-8") as handle:
                    handle.write(f"verdicts={line}\n")
            return 0
        if not re.fullmatch(r"[0-9]+", args.app_id):
            raise ValueError("--app-id must be a number")
        post(checked_verdicts(os.environ["VERDICTS"]), args.app_id, os.environ["GITHUB_REPOSITORY"])
        return 0
    except (subprocess.CalledProcessError, ValueError, RuntimeError, KeyError) as error:
        detail = getattr(error, "stderr", "") or ""
        sys.exit(f"gate_check: {error} {detail}".strip())


if __name__ == "__main__":
    sys.exit(main())

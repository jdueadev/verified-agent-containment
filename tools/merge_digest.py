#!/usr/bin/env python3
"""After-the-fact audit of what merged to main: the weekly digest (#54) and the
detective check on each merge (#71).

Usage:
  merge_digest.py collect --repo OWNER/NAME [--since ISO_DATE | --commit SHA] > merges.json
  merge_digest.py report merges.json [--fail-on-unapproved] [--title TEXT]

collect  lists merge commits on main (first-parent history) since a date, or one
         commit, and the pull request behind each: number, title, author, who merged
         it, the head SHA it merged at, and its reviews. It calls `gh` and `git`.
report   needs no network. For each merge it works out, with git and the trusted
         checkers:
           - the lane, from the lane map of the commit before the merge, exactly as
             the `policy` check would have judged it, and any ratchet escalation;
           - the claims whose files it touched, and whether they need the lab;
           - for lane C, whether the owner approved the head commit that merged.
         It prints a Markdown digest. Alerts come first: a lane C merge that the
         owner neither approved at its head nor authored. With
         --fail-on-unapproved it exits 1 when there is one.

A lane C pull request the owner authored can only have merged through the ruleset
bypass, since nobody can approve their own pull request. Those are listed as
"maintainer merge (bypass)", not as alerts. A commit on main with no pull request
is always an alert: everything reaches main through a pull request.

This reads other commits only through git and never imports or runs them.
"""
import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims_check  # noqa: E402  (trusted base, lane C)
import policy_check  # noqa: E402  (trusted base, lane C)

ROOT = policy_check.ROOT


def git(*args):
    return policy_check.git(*args)


def gh_json(*args):
    out = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=True).stdout
    return json.loads(out) if out.strip() else None


# ---------- collect (network) ----------

def collect(repo, since=None, commit=None):
    if commit:
        commits = [git("rev-parse", "--verify", f"{commit}^{{commit}}").strip()]
    else:
        commits = [c for c in git("rev-list", "--first-parent", f"--since={since}", "origin/main").split() if c]
    merges = []
    for sha in commits:
        pulls = [p for p in gh_json(f"repos/{repo}/commits/{sha}/pulls") or [] if p.get("merge_commit_sha") == sha]
        entry = {"sha": sha, "pr": None}
        if pulls:
            number = pulls[0]["number"]
            pr = gh_json(f"repos/{repo}/pulls/{number}")
            reviews = gh_json("--paginate", "--slurp", f"repos/{repo}/pulls/{number}/reviews?per_page=100")
            entry["pr"] = {
                "number": number,
                "title": pr.get("title", ""),
                "author": (pr.get("user") or {}).get("login", ""),
                "merged_by": (pr.get("merged_by") or {}).get("login", ""),
                "head_sha": (pr.get("head") or {}).get("sha", ""),
                "reviews": reviews or [],
            }
        merges.append(entry)
    return merges


# ---------- report (offline) ----------

def analyze(merge):
    """Lane, escalations, claims affected and approval state of one merge commit."""
    sha = merge["sha"]
    parent = git("rev-parse", f"{sha}^").strip()
    paths = [p for p in git("diff", "--name-only", "--no-renames", parent, sha).splitlines() if p]
    lanes_text = policy_check.reader(parent)(policy_check.LANES_FILE)
    if lanes_text is None:
        # Merged before the lane map existed (#58): there is no lane to judge it by.
        return {"sha": sha, "pr": merge.get("pr"), "lane": "-", "escalations": [], "claims": [],
                "lab_claims": [], "approval": "before the lane map", "alert": False}
    owner, lanes = policy_check.load_lanes(lanes_text)
    result = policy_check.classify(paths, policy_check.reader(parent), policy_check.reader(sha), lanes)
    claims_text = policy_check.reader(sha)("claims.toml") or ""
    claims = tomllib.loads(claims_text).get("claim", []) if claims_text else []
    hits = claims_check.affected_claims(claims, paths)
    pr = merge.get("pr")
    login = owner.lstrip("@").lower()
    if pr is None:
        state = "no pull request"
    elif result["lane"] != "C":
        state = "not needed"
    elif policy_check.approved(pr.get("reviews", []), owner, pr.get("head_sha")):
        state = "approved"
    elif (pr.get("author") or "").lower() == login:
        state = "maintainer merge (bypass)"
    else:
        state = "UNAPPROVED"
    return {
        "sha": sha,
        "pr": pr,
        "lane": result["lane"],
        "escalations": result["escalations"],
        "claims": [h["id"] for h in hits],
        "lab_claims": [h["id"] for h in hits if h["needs_lab"]],
        "approval": state,
        "alert": state in ("UNAPPROVED", "no pull request"),
    }


def stale_now():
    """Stale rows at the checkout, as claims_check reports them."""
    out = subprocess.run([sys.executable, str(ROOT / "tools/claims_check.py")], capture_output=True, text=True,
                         cwd=ROOT).stdout
    try:
        return json.loads(out).get("stale", [])
    except ValueError:
        return ["claims_check did not report (its output could not be read)"]


def _pr(row):
    pr = row["pr"]
    return f"#{pr['number']} {pr['title']}" if pr else f"`{row['sha'][:7]}` (no pull request)"


def render(rows, stale, title):
    lines = [f"# {title}", ""]
    alerts = [r for r in rows if r["alert"]]
    lines.append("## Alerts")
    if alerts:
        lines.append("")
        lines.append("These reached `main` without the owner's approval of the merged head commit:")
        lines.append("")
        for r in alerts:
            lines.append(f"- **{_pr(r)}**, lane {r['lane']}, `{r['sha'][:7]}`: {r['approval']}")
    else:
        lines.append("")
        lines.append("None. Every lane C merge was approved at its head commit or is the maintainer's own.")
    lines += ["", "## Lane B merges (no human review)", ""]
    lane_b = [r for r in rows if r["lane"] == "B"]
    if lane_b:
        lines += ["| PR | commit | claims affected | need the lab |", "|---|---|---|---|"]
        for r in lane_b:
            lines.append(f"| {_pr(r)} | `{r['sha'][:7]}` | {', '.join(r['claims']) or 'none'} | "
                         f"{', '.join(r['lab_claims']) or 'none'} |")
    else:
        lines.append("None.")
    lines += ["", "## Lane C merges", ""]
    lane_c = [r for r in rows if r["lane"] == "C"]
    if lane_c:
        lines += ["| PR | commit | approval | escalated by |", "|---|---|---|---|"]
        for r in lane_c:
            lines.append(f"| {_pr(r)} | `{r['sha'][:7]}` | {r['approval']} | {'; '.join(r['escalations']) or 'paths'} |")
    else:
        lines.append("None.")
    escalated = [r for r in rows if r["escalations"]]
    lines += ["", "## Ratchet escalations", ""]
    if escalated:
        for r in escalated:
            for e in r["escalations"]:
                lines.append(f"- {_pr(r)}: {e}")
    else:
        lines.append("None.")
    lane_a = sum(r["lane"] == "A" for r in rows)
    lines += ["", f"Lane A merges: {lane_a}.", "", "## Stale rows on main now", ""]
    lines += [f"- {s}" for s in stale] or ["None."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--repo", required=True)
    group = c.add_mutually_exclusive_group(required=True)
    group.add_argument("--since")
    group.add_argument("--commit")
    r = sub.add_parser("report")
    r.add_argument("merges")
    r.add_argument("--fail-on-unapproved", action="store_true")
    r.add_argument("--title", default="Merge digest")
    args = parser.parse_args(argv)
    if args.command == "collect":
        print(json.dumps(collect(args.repo, since=args.since, commit=args.commit), indent=2))
        return 0
    merges = json.loads(Path(args.merges).read_text(encoding="utf-8"))
    rows = [analyze(m) for m in merges]
    print(render(rows, stale_now(), args.title), end="")
    if args.fail_on_unapproved and any(r["alert"] for r in rows):
        print("merge_digest: a lane C change reached main without the owner's approval", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

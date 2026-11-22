#!/usr/bin/env bash
# Turn a passing CI lab run on main into an evidence pull request (#53, AC-051).
#
#   scripts/lab/ci-record.sh RESULTS_DIR COMMIT RUN_URL
#
# Run by the `record` job of .github/workflows/lab.yaml, on a checkout of COMMIT
# (a commit on main), with GH_TOKEN allowed to push a branch and open a PR. It
# builds and runs nothing from the change: only tools/lab_record.py and
# tools/claims_check.py, which are lane C.
#
#   1. If main has moved past COMMIT, a later run records instead: exit 0. (With
#      branches required to be up to date, evidence for an older commit could not
#      merge anyway.) If no lab claim is stale at COMMIT, there is nothing to
#      record: exit 0.
#   2. tools/lab_record.py checks the run (CI-8, every claim's scenario and control
#      evidence) and writes results/ci/lab-<sha7>/ and the platform entries.
#   3. docs/claims.md is regenerated; with the evidence staged, claims_check must
#      report no errors and nothing stale.
#   4. A PR from branch evidence/lab-<sha7> is opened with auto-merge requested.
#      It edits `platforms`, so it is lane C: it merges when the maintainer
#      approves it. Only then are older open evidence PRs closed, and only those
#      recorded for an ancestor of COMMIT.
#   5. The run summary, which a pull request cannot edit, lists the evidence
#      commit, its tree and every file's SHA-256, for the maintainer to compare.
#
# It refuses to run outside GitHub Actions: it force-pushes and opens a PR with
# whatever credentials it finds, and a local run once left this clone's identity
# set for every later commit (#99). The evidence commit's identity is passed to
# that one `git commit`, never written to the repository config.
set -euo pipefail

[ "${GITHUB_ACTIONS:-}" = "true" ] || {
  echo "ci-record: runs only in the record job of .github/workflows/lab.yaml (GITHUB_ACTIONS is not true); nothing was changed" >&2
  exit 2
}

results="${1:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
commit="${2:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
run_url="${3:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
short="${commit:0:7}"
branch="evidence/lab-$short"

[ "$(git rev-parse HEAD)" = "$commit" ] || { echo "ci-record: HEAD is not $commit" >&2; exit 1; }
git fetch -q origin main
if [ "$(git rev-parse origin/main)" != "$commit" ]; then
  echo "main has moved past $short; the run on the newer commit records instead." | tee -a "$summary"
  exit 0
fi

# Lab claims a CI run does not record (an "os" claim such as L-ISO-02): they stay
# stale until a lab on their own platform runs, and do not count here.
python3 tools/lab_record.py --list-skipped > "$RUNNER_TEMP/skipped.txt"
sed 's/^\(.*\)$/CI-4 \1:/' "$RUNNER_TEMP/skipped.txt" > "$RUNNER_TEMP/skipped-patterns.txt"

claims_report() {
  # $1 is "stale" or "errors". claims_check exits non-zero when it reports errors;
  # the report is printed either way. Stale rows of skipped claims are left out.
  python3 tools/claims_check.py > "$RUNNER_TEMP/claims.json" || true
  python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print("\n".join(d[sys.argv[2]]))' \
    "$RUNNER_TEMP/claims.json" "$1" | grep -vF -f "$RUNNER_TEMP/skipped-patterns.txt" || true
}

before="$(claims_report stale)"
# An earlier CI entry that no longer holds for the claims as they are now (a claim
# gained a scenario, say) needs replacing too, even though no listed file changed.
if ! python3 tools/lab_record.py --verify > "$RUNNER_TEMP/verify.json"; then
  before="$before"$'\n'"recorded CI evidence no longer holds: $(cat "$RUNNER_TEMP/verify.json")"
fi
if [ -z "${before//[[:space:]]/}" ]; then
  echo "No lab claim is stale at $short; no evidence to record." | tee -a "$summary"
  exit 0
fi
echo "Needs recording:"; echo "$before"

python3 tools/lab_record.py --results "$results" --commit "$commit" --platform gha-ubuntu-24.04 \
  | tee "$RUNNER_TEMP/record.json"
python3 tools/claims_check.py --write > /dev/null || true

git switch -c "$branch"
# Staged first: CI-9 looks for the results among tracked files.
git add claims.toml docs/claims.md "results/ci/lab-$commit"
after="$(claims_report stale)$(claims_report errors)"
if [ -n "$after" ]; then
  echo "ci-record: the recorded evidence does not leave claims_check clean; refusing to open a PR:" >&2
  echo "$after" >&2
  exit 1
fi
[ -z "$(git status --porcelain --untracked-files=no | grep -v '^[AM]  ')" ] \
  || { echo "ci-record: unexpected changes besides the evidence" >&2; git status --short >&2; exit 1; }
git -c user.name="lab workflow" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "Lab evidence for $short from CI

Recorded by scripts/lab/ci-record.sh from $run_url"
# A retried job finds its own branch already pushed. Only the evidence App can write
# evidence/** (a ruleset), so replacing it with this attempt's commit is safe.
git push -q --force origin "$branch"
evidence_commit="$(git rev-parse HEAD)"

ids="$(python3 -I -c 'import json, sys; print(", ".join(json.load(open(sys.argv[1]))["claims"]))' "$RUNNER_TEMP/record.json")"
skipped_ids="$(python3 -I -c 'import json, sys; print(", ".join(json.load(open(sys.argv[1])).get("skipped", [])) or "none")' "$RUNNER_TEMP/record.json")"
# The description follows .github/pull_request_template.md, like any other PR.
body="$(cat <<EOF
Part of #53: lab evidence recorded by CI for \`$commit\` on \`main\`.

## What changed and why
The CI lab passed on \`$commit\`, and \`tools/lab_record.py\` turned that run into evidence:
- results in \`results/ci/lab-$commit/\` (attack suite, live suite, environment);
- one \`platforms\` entry, \`gha-ubuntu-24.04\` @ \`$commit\`, on each claim below.

Run: $run_url

Evidence commit: \`$evidence_commit\`. The run summary lists it with its tree and every file's SHA-256. A PR cannot edit the summary, so compare against it rather than this description.

## Lane
C: a \`platforms\` edit and lab results (\`results/ci/**\`). The \`policy\` check reports the same.

## Process tier
- [ ] Touches the rules or the gate
- [x] Touches what decides "passed" (lab results)
- [ ] Crosses a trust boundary
- [ ] Removes, narrows or loosens a check, widens what a checker accepts, or modifies or deletes an existing test assertion

Heavy. The issue is #53, and its design reviews are recorded there.

## Claims affected
Recorded: $ids

Skipped (their layer is not one a CI run speaks for; they stay stale until a lab on their own platform runs): $skipped_ids

## Invariants touched
- INV-1: the evidence comes from the run above, written by \`tools/lab_record.py\` in the \`record\` job, not by hand and not by an agent. It is accepted only by the maintainer's approval.
- INV-2: nothing is removed or reworded. Entries are only appended.

## Checked
Before writing anything, \`tools/lab_record.py\` checked that:
- CI-8 holds;
- \`environment.txt\` names this commit and both binaries;
- every recorded claim's scenarios passed and its controls caught their defect, each in its own suite;
- nothing in \`claims.toml\` changed except \`platforms\` lines.

After recording, \`claims_check\` reported no errors and nothing stale, apart from the skipped claims.

## Not run
A lab on any other platform, for the skipped claims.

## Evidence
- [x] I did not edit \`results/\`, a \`platforms\` entry or \`docs/claims.md\` by hand. They were written by the recorder and regenerated with \`--write\`.
- [x] I did not remove or reword a law, mutant, scenario, sabotage control, claim statement or falsifier

Before approving, check that:
- the author is the evidence App;
- the PR has exactly one commit, equal to the evidence commit in the run summary;
- the run is a push of \`$commit\` on \`main\` with \`lab\` passed;
- the diff touches only \`platforms\` lines, \`docs/claims.md\` and \`results/ci/lab-$commit/\`.
EOF
)"
existing="$(gh pr list --state open --head "$branch" --json number --jq '.[0].number // empty')"
if [ -n "$existing" ]; then
  echo "PR #$existing for $branch already exists; it now carries this attempt's commit."
  gh pr comment "$existing" --body "Updated by $run_url (evidence commit $evidence_commit)."
else
  gh pr create --base main --head "$branch" --title "Lab evidence for $short from CI" --body "$body"
fi
gh pr merge --auto --squash "$branch" || echo "auto-merge could not be requested; merge after approval" >&2

# Supersede only after the new PR exists, and only evidence for an ancestor of COMMIT.
for old in $(gh pr list --state open --json number,headRefName \
               --jq '.[] | select(.headRefName | startswith("evidence/lab-")) | select(.headRefName != "'"$branch"'") | .number'); do
  head="$(gh pr view "$old" --json headRefOid --jq .headRefOid)"
  git fetch -q origin "$head" || continue
  if git merge-base --is-ancestor "$head^" "$commit"; then
    gh pr close "$old" --delete-branch --comment "Superseded by the CI lab run on $short." || true
  fi
done

{
  echo "### Evidence PR opened from \`$branch\`"
  echo
  echo "- recorded for: \`$commit\` (run attempt ${GITHUB_RUN_ATTEMPT:-unknown})"
  echo "- evidence commit: \`$evidence_commit\`"
  echo "- tree: \`$(git rev-parse "$evidence_commit^{tree}")\`"
  echo
  echo "| file | sha256 |"
  echo "|---|---|"
  git diff --name-only "$commit" "$evidence_commit" | while read -r f; do
    echo "| \`$f\` | \`$(sha256sum "$f" | cut -d' ' -f1)\` |"
  done
} >> "$summary"

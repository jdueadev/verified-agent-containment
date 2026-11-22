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

claims_report() {
  # $1 is "stale" or "errors". claims_check exits non-zero when it reports errors;
  # the report is printed either way.
  python3 tools/claims_check.py > "$RUNNER_TEMP/claims.json" || true
  python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print("\n".join(d[sys.argv[2]]))' \
    "$RUNNER_TEMP/claims.json" "$1"
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
body="$(cat <<EOF
Lab evidence recorded by CI for $commit (on \`main\`).

- Run: $run_url
- Results: \`results/ci/lab-$commit/\` (attack suite, live suite, environment)
- Platform entry \`gha-ubuntu-24.04\` @ \`$commit\` added to: $ids
- Evidence commit: \`$evidence_commit\`. The run summary lists it with its tree and every file's SHA-256. The summary cannot be edited from a PR, so compare against it rather than this description.

\`tools/lab_record.py\` checked CI-8 and every claim's scenario and control evidence before writing anything. This PR edits \`platforms\`, so it is lane C: approve it to accept the evidence.

Before approving: the author is the evidence App; the PR has exactly one commit, equal to the evidence commit in the run summary; the run is a push of the recorded commit on \`main\` with \`lab\` passed; the diff touches only \`platforms\` lines, \`docs/claims.md\` and \`results/ci/lab-$commit/\`.
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

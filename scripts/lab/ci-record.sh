#!/usr/bin/env bash
# Turn a passing CI lab run on main into an evidence pull request (#53, AC-051).
#
#   scripts/lab/ci-record.sh RESULTS_DIR COMMIT RUN_URL
#
# Run by the `record` job of .github/workflows/lab.yml, on a checkout of COMMIT
# (a commit on main), with GH_TOKEN allowed to push a branch and open a PR. It
# builds and runs nothing from the change: only tools/lab_record.py and
# tools/claims_check.py, which are lane C.
#
#   1. If no lab claim is stale at COMMIT, there is nothing to record: exit 0.
#   2. tools/lab_record.py checks the run (CI-8, every claim's scenario and control
#      evidence) and writes results/ci/lab-<sha7>/ and the platform entries.
#   3. docs/claims.md is regenerated, and no lab claim may still be stale.
#   4. Older open evidence PRs are closed as superseded, and a PR from branch
#      evidence/lab-<sha7> is opened with auto-merge requested. It edits
#      `platforms`, so it is lane C: it merges when the maintainer approves it.
set -euo pipefail

results="${1:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
commit="${2:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
run_url="${3:?usage: ci-record.sh RESULTS_DIR COMMIT RUN_URL}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
short="${commit:0:7}"
branch="evidence/lab-$short"

[ "$(git rev-parse HEAD)" = "$commit" ] || { echo "ci-record: HEAD is not $commit" >&2; exit 1; }

stale_lab_claims() {
  # claims_check exits non-zero when it reports errors; the stale list is still printed.
  python3 tools/claims_check.py > "$RUNNER_TEMP/claims.json" || true
  python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print("\n".join(d.get("stale", [])))' \
    "$RUNNER_TEMP/claims.json"
}

before="$(stale_lab_claims)"
if [ -z "$before" ]; then
  echo "No lab claim is stale at $short; no evidence to record." | tee -a "$summary"
  exit 0
fi
echo "Stale before recording:"; echo "$before"

python3 tools/lab_record.py --results "$results" --commit "$commit" --platform gha-ubuntu-24.04 \
  | tee "$RUNNER_TEMP/record.json"
python3 tools/claims_check.py --write > /dev/null || true
after="$(stale_lab_claims)"
if [ -n "$after" ]; then
  echo "ci-record: claims are still stale after recording; refusing to open a PR:" >&2
  echo "$after" >&2
  exit 1
fi

git config user.name "lab workflow"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -c "$branch"
git add claims.toml docs/claims.md "results/ci/lab-$short"
git commit -q -m "Lab evidence for $short from CI

Recorded by scripts/lab/ci-record.sh from $run_url"
git push -q origin "$branch"

for old in $(gh pr list --state open --json number,headRefName \
               --jq '.[] | select(.headRefName | startswith("evidence/lab-")) | .number'); do
  gh pr close "$old" --delete-branch --comment "Superseded by the CI lab run on $short." || true
done

ids="$(python3 -I -c 'import json, sys; print(", ".join(json.load(open(sys.argv[1]))["claims"]))' "$RUNNER_TEMP/record.json")"
body="$(cat <<EOF
Lab evidence recorded by CI for $commit (on \`main\`).

- Run: $run_url
- Results: \`results/ci/lab-$short/\` (attack suite, live suite, environment)
- Platform entry \`gha-ubuntu-24.04\` @ \`$short\` added to: $ids

\`tools/lab_record.py\` checked CI-8 and every claim's scenario and control evidence before writing anything. This PR edits \`platforms\`, so it is lane C: approve it to accept the evidence.

If no checks have started, the PR was opened with \`GITHUB_TOKEN\`. Close and reopen it to start them.
EOF
)"
gh pr create --base main --head "$branch" --title "Lab evidence for $short from CI" --body "$body"
gh pr merge --auto --squash "$branch" || echo "auto-merge could not be requested; merge after approval" >&2
echo "Evidence PR opened from $branch." >> "$summary"

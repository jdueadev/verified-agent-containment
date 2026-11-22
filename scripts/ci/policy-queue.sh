#!/usr/bin/env bash
# The `policy` check for a merge-queue group (.github/workflows/policy.yml, #102).
#
#   scripts/ci/policy-queue.sh BASE_SHA HEAD_SHA [--enforce]
#
# Runs from a checkout of the group's base commit, so these tools are main's, never the
# group's. It lists the group's pull requests from GitHub's merge-queue API (never from
# commit messages, which pull requests write): every entry up to and including the one
# whose merge-group commit is HEAD_SHA, in queue order. For each it fetches the reviews,
# then has tools/policy_check.py judge the group: one commit per entry, each classified
# with the lane map before it, and a lane C entry approved by the owner at its head.
# Anything it cannot establish is a failure. Needs GH_TOKEN and GH_REPO.
set -euo pipefail

base="${1:?usage: policy-queue.sh BASE_SHA HEAD_SHA [--enforce]}"
head="${2:?usage: policy-queue.sh BASE_SHA HEAD_SHA [--enforce]}"
enforce="${3:-}"
work="${RUNNER_TEMP:-$(mktemp -d)}"
owner="${GH_REPO%%/*}"
name="${GH_REPO##*/}"

git fetch -q origin "$head"
gh api graphql -F owner="$owner" -F name="$name" -f query='
  query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      mergeQueue(branch: "main") {
        entries(first: 100) {
          nodes { position headCommit { oid } pullRequest { number headRefOid } }
        }
      }
    }
  }' > "$work/queue.json"

python3 -I - "$work/queue.json" "$head" "$work/numbers.txt" <<'PYEOF'
import json, sys
queue, head, out = sys.argv[1], sys.argv[2], sys.argv[3]
nodes = json.load(open(queue))["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
nodes.sort(key=lambda n: n["position"])
mine = [n for n in nodes if (n.get("headCommit") or {}).get("oid") == head]
if len(mine) != 1:
    sys.exit(f"policy-queue: {len(mine)} queue entries have merge-group commit {head}")
group = [n for n in nodes if n["position"] <= mine[0]["position"]]
with open(out, "w") as f:
    for n in group:
        f.write(f'{n["pullRequest"]["number"]} {n["pullRequest"]["headRefOid"]}\n')
PYEOF

echo "[" > "$work/entries.json"
first=1
while read -r number head_sha; do
  gh api --paginate --slurp "repos/$GH_REPO/pulls/$number/reviews?per_page=100" > "$work/reviews-$number.json"
  [ "$first" = 1 ] || echo "," >> "$work/entries.json"
  first=0
  python3 -I -c 'import json, sys; print(json.dumps({"number": int(sys.argv[1]), "head_sha": sys.argv[2], "reviews": json.load(open(sys.argv[3]))}))' \
    "$number" "$head_sha" "$work/reviews-$number.json" >> "$work/entries.json"
done < "$work/numbers.txt"
echo "]" >> "$work/entries.json"

python3 tools/policy_check.py queue --base "$base" --head "$head" --entries "$work/entries.json" $enforce

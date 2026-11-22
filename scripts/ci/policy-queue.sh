#!/usr/bin/env bash
# The `policy` check for a merge-queue group (.github/workflows/policy.yml, #102).
#
#   scripts/ci/policy-queue.sh BASE_SHA HEAD_SHA [--enforce]
#
# Runs from a checkout of the group's base commit, so these tools are main's, never the
# group's. It lists the group's pull requests from GitHub's merge-queue API (never from
# commit messages, which pull requests write): every entry up to and including the one
# whose merge-group commit is HEAD_SHA, in queue order, each with its own group commit,
# its head and whether it comes from a fork. It fetches every head and its reviews, then
# has tools/policy_check.py judge the group: one commit per entry, each that entry's
# group commit and its head merged onto the commit before, classified with the lane map
# before it, and a lane C or fork entry approved by the owner at its head.
#
# Anything it cannot establish is a problem. Without --enforce (POLICY_ENFORCE is not
# "true", as for the pull request check) problems are reported and the check passes; a
# failed command still fails it. Needs GH_TOKEN and GH_REPO.
set -euo pipefail

base="${1:?usage: policy-queue.sh BASE_SHA HEAD_SHA [--enforce]}"
head="${2:?usage: policy-queue.sh BASE_SHA HEAD_SHA [--enforce]}"
enforce="${3:-}"
case "$enforce" in
  ""|--enforce) ;;
  *) echo "policy-queue: the third argument must be --enforce or nothing, not '$enforce'" >&2; exit 2 ;;
esac
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/policy-queue.XXXXXX")"
owner="${GH_REPO%%/*}"
name="${GH_REPO##*/}"

git fetch -q origin "$head"
gh api graphql -F owner="$owner" -F name="$name" -f query='
  query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      mergeQueue(branch: "main") {
        entries(first: 100) {
          nodes {
            position
            headCommit { oid }
            pullRequest { number headRefOid isCrossRepository }
          }
        }
      }
    }
  }' > "$work/queue.json"

# The group: entries at or before ours, in position order. Only integers, object ids and
# booleans from the API leave this step.
python3 -I - "$work/queue.json" "$head" "$work/group.json" <<'PYEOF'
import json, re, sys
queue, head, out = sys.argv[1], sys.argv[2], sys.argv[3]
nodes = json.load(open(queue))["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
nodes.sort(key=lambda n: n["position"])
mine = [n for n in nodes if (n.get("headCommit") or {}).get("oid") == head]
if len(mine) != 1:
    sys.exit(f"policy-queue: {len(mine)} queue entries have merge-group commit {head}")
oid = re.compile(r"[0-9a-f]{40}")
group = []
for n in nodes:
    if n["position"] > mine[0]["position"]:
        continue
    pr = n["pullRequest"]
    if not (isinstance(pr["number"], int) and oid.fullmatch(pr["headRefOid"] or "")
            and oid.fullmatch((n.get("headCommit") or {}).get("oid") or "")):
        sys.exit(f"policy-queue: queue entry at position {n['position']} is malformed")
    group.append({"number": pr["number"], "head_sha": pr["headRefOid"],
                  "group_commit": n["headCommit"]["oid"],
                  # Anything but an explicit false is treated as a fork.
                  "fork": pr.get("isCrossRepository") is not False})
json.dump(group, open(out, "w"))
PYEOF

# The head each approval is judged at must be the one git merges, so fetch it and check.
python3 -I -c 'import json, sys; [print(e["number"], e["head_sha"]) for e in json.load(open(sys.argv[1]))]' \
  "$work/group.json" > "$work/numbers.txt"
while read -r number head_sha; do
  git fetch -q origin "pull/$number/head"
  fetched="$(git rev-parse FETCH_HEAD)"
  if [ "$fetched" != "$head_sha" ]; then
    echo "policy-queue: PR #$number's head is $fetched, not $head_sha as queued" >&2
    exit 1
  fi
  gh api --paginate --slurp "repos/$GH_REPO/pulls/$number/reviews?per_page=100" > "$work/reviews-$number.json"
done < "$work/numbers.txt"

python3 -I - "$work/group.json" "$work" "$work/entries.json" <<'PYEOF'
import json, sys
group, work, out = sys.argv[1], sys.argv[2], sys.argv[3]
entries = json.load(open(group))
for e in entries:
    e["reviews"] = json.load(open(f"{work}/reviews-{e['number']}.json"))
json.dump(entries, open(out, "w"))
PYEOF

python3 tools/policy_check.py queue --base "$base" --head "$head" --entries "$work/entries.json" $enforce

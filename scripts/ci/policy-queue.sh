#!/usr/bin/env bash
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
git fetch -q origin main
main_tip="$(git rev-parse FETCH_HEAD)"
if ! git merge-base --is-ancestor "$base" "$main_tip" || ! git merge-base --is-ancestor "$main_tip" "$head"; then
  echo "policy-queue: main is at $main_tip, which is not between the group's base $base and its head $head;" \
    "the group was built on a main that has since moved, so its lane maps may be stale" >&2
  exit 1
fi
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
                  "fork": pr.get("isCrossRepository") is not False})
json.dump(group, open(out, "w"))
PYEOF

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

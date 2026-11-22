#!/usr/bin/env bash
# The root lab on a disposable CI runner (.github/workflows/lab.yml, #53).
#
#   scripts/lab/ci-lab.sh [--if-affected BASE_SHA]
#
# With --if-affected, the lab runs only when `claims_check.py --affected` reports
# a host lab claim for the change since the merge base with BASE_SHA; otherwise
# it exits 0 without building anything, so `lab` can be a required check. Output
# it cannot read is a failure, never a skip.
#
# Then it installs the toolchain rust-toolchain.toml pins, builds the default and
# sabotage binaries, and runs as root:
#   - the honest attack suite (repeat 30) and live suite on the default build,
#     which is the one that ships;
#   - the sabotage controls on the sabotage build, each judged against the
#     honest results, which must catch every deliberate defect.
# Cgroup limits are enforced: --allow-missing-limits is never passed, so a runner
# without the controllers fails instead of producing a waived run.
#
# Exits non-zero if any step fails or any control does not catch its defect.
# Only for a throwaway machine (INV-11): it runs as root and changes cgroups.
set -euo pipefail

work="${RUNNER_TEMP:-$(mktemp -d)}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "${1:-}" = "--if-affected" ]; then
  base_sha="${2:?--if-affected needs BASE_SHA}"
  base="$(git merge-base "$base_sha" HEAD)"
  python3 tools/claims_check.py --affected "$base" | tee "$work/affected.txt"
  if grep -q '^Host claims requiring root lab refresh' "$work/affected.txt"; then
    echo "A host lab claim is affected; running the lab."
  elif grep -qE '^(Affected claims: none|No host lab claims affected)' "$work/affected.txt"; then
    echo "No host lab claim is affected; the lab is not needed." | tee -a "$summary"
    exit 0
  else
    echo "ci-lab: could not tell which claims this change affects; refusing to skip." >&2
    exit 1
  fi
elif [ "$#" -ne 0 ]; then
  echo "usage: ci-lab.sh [--if-affected BASE_SHA]" >&2
  exit 2
fi

echo "::group::toolchain and build"
channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
[ -n "$channel" ] || { echo "ci-lab: no channel in rust-toolchain.toml" >&2; exit 1; }
rustup toolchain install "$channel" --profile minimal
python3 tools/pins_check.py drift --rustc --cargo
target="$work/target"
cargo build --locked --release -p containment-host --target-dir "$target/default"
cargo build --locked --release -p containment-host --features sabotage --target-dir "$target/sabotage"
echo "::endgroup::"

default="$target/default/release/containment-lab"
sabotage="$target/sabotage/release/containment-lab"
out="$work/lab"
for bin in "$default" "$sabotage"; do
  [ -x "$bin" ] || { echo "ci-lab: $bin is missing or not executable" >&2; exit 1; }
done
if cmp -s "$default" "$sabotage"; then
  echo "ci-lab: the default and sabotage binaries are identical; the controls would prove nothing" >&2
  exit 1
fi
mkdir -p "$out"

status=0
step() {
  local name="$1"; shift
  echo "::group::$name"
  if sudo "$@"; then
    echo "| $name | pass |" >> "$summary"
  else
    echo "| $name | **fail** |" >> "$summary"
    status=1
  fi
  echo "::endgroup::"
}

{
  echo "### Lab on $(uname -r), commit $(git rev-parse HEAD)"
  echo
  echo "default build sha256 \`$(sha256sum "$default" | cut -d' ' -f1)\`"
  echo "sabotage build sha256 \`$(sha256sum "$sabotage" | cut -d' ' -f1)\`"
  echo
  echo "| step | result |"
  echo "|---|---|"
} >> "$summary"

step "attack suite, honest (repeat 30)" "$default" attack-suite --repeat 30 --out "$out/attack-suite-honest.json"
step "live suite, honest" "$default" live-suite --out "$out/live-suite-honest.json"
# The controls need the honest results; without them there is nothing to judge against.
if [ "$status" -eq 0 ]; then
  step "attack suite, sabotage controls" "$sabotage" attack-suite \
    --honest-results "$out/attack-suite-honest.json" --out "$out/attack-suite-local.json"
  step "live suite, sabotage controls" "$sabotage" live-suite \
    --honest-results "$out/live-suite-honest.json" --out "$out/live-suite-local.json"
else
  echo "| sabotage controls | not run: an honest suite failed |" >> "$summary"
fi

sudo chown -R "$(id -u):$(id -g)" "$out"
exit "$status"

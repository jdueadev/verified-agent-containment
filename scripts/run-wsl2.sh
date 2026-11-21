#!/usr/bin/env bash
# Builds both binaries as your user, then runs the Linux attack suite as root:
# the honest runs on the default build, the sabotage controls on the sabotage build.
# Run without sudo inside a disposable WSL2 distribution: scripts/run-wsl2.sh [repeat] [extra suite flags]
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" != 0 ] || { echo "Run as your user, not with sudo. The script asks for sudo only for the suite." >&2; exit 2; }
kernel="$(uname -r)"
major="${kernel%%.*}"; rest="${kernel#*.}"; minor="${rest%%.*}"
if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 14 ]; }; then
  echo "Linux 5.14 or newer is required for cgroup.kill; found $kernel" >&2
  exit 2
fi
if [ ! -e /sys/fs/cgroup/cgroup.controllers ] && [ ! -e /sys/fs/cgroup/unified/cgroup.controllers ]; then
  echo "A cgroup v2 mount is required." >&2
  exit 2
fi
echo "kernel $kernel; cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || cat /sys/fs/cgroup/unified/cgroup.controllers)"
cargo build --release -p containment-host
cargo build --release -p containment-host --features sabotage --target-dir target-sabotage
out="results/attack-suite-$(uname -n).json"
repeat="${1:-30}"; shift || true
status=0
honest="${out%.json}-honest.json"
{
  sudo target/release/containment-lab attack-suite --repeat "$repeat" --out "$honest" "$@" \
    && sudo target-sabotage/release/containment-lab attack-suite --honest-results "$honest" --out "$out" "$@"
} 2>&1 | tee "${out%.json}.log" || status=$?
for file in "$honest" "$out"; do [ ! -e "$file" ] || sudo chown "$(id -u):$(id -g)" "$file"; done
exit "$status"

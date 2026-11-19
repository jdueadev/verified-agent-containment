#!/usr/bin/env bash
# Builds and runs the Linux attack suite. Run as root inside a disposable WSL2 distribution.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "Run as root: sudo scripts/run-wsl2.sh" >&2; exit 2; }
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
cargo build --release -p containment-host
target/release/containment-lab attack-suite --repeat "${1:-30}" --out "results/attack-suite-$(uname -n).json"

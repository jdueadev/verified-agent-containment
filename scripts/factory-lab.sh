#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

repeat="${1:-30}"
out=target/verify/lab
mkdir -p "$out"

if [ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]; then
  echo "factory-lab: /sys/fs/cgroup is $(stat -fc %T /sys/fs/cgroup), not cgroup v2; the suites cannot enforce limits here" >&2
  exit 1
fi
if [ ! -w /sys/fs/cgroup/cgroup.subtree_control ]; then
  echo "factory-lab: the cgroup tree is read-only; run the container with --privileged --cgroupns=private" >&2
  exit 1
fi
mkdir -p /sys/fs/cgroup/factory-lab-shell
echo $$ > /sys/fs/cgroup/factory-lab-shell/cgroup.procs
for controller in $(cat /sys/fs/cgroup/cgroup.controllers); do
  echo "+$controller" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null \
    || echo "factory-lab: could not delegate the $controller controller" >&2
done

run_dir=/run/verified-agent-containment
run_opts="$(findmnt -no OPTIONS --target /run 2>/dev/null || echo unknown)"
if [[ ",$run_opts," == *",noexec,"* ]]; then
  mkdir -p "$run_dir"
  mount -t tmpfs -o mode=0755,nosuid,nodev,exec tmpfs "$run_dir"
fi

cargo build --locked --release -p containment-host --target-dir target/lab/default
cargo build --locked --release -p containment-host --features sabotage --target-dir target/lab/sabotage
default=target/lab/default/release/containment-lab
sabotage=target/lab/sabotage/release/containment-lab
if cmp -s "$default" "$sabotage"; then
  echo "factory-lab: the default and sabotage binaries are identical; the controls would prove nothing" >&2
  exit 1
fi

{
  echo "commit id: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "where: container on kernel $(uname -r), $(uname -m)"
  echo "cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
  echo "cgroup v2 delegated: $(cat /sys/fs/cgroup/cgroup.subtree_control)"
  echo "cpus: $(nproc)"
  echo "run directory: /run is $run_opts"
  echo "default binary sha256: $(sha256sum "$default" | cut -d' ' -f1)"
  echo "sabotage binary sha256: $(sha256sum "$sabotage" | cut -d' ' -f1)"
  echo "attack suite repeat: $repeat"
} | tee "$out/environment.txt"

status=0
step() {
  local name="$1"
  shift
  local start=$SECONDS
  if "$@"; then
    echo "factory-lab: PASS $name ($((SECONDS - start)) s)"
  else
    echo "factory-lab: FAIL $name ($((SECONDS - start)) s)"
    status=1
  fi
}

step "attack suite, honest (repeat $repeat)" "$default" attack-suite --repeat "$repeat" --out "$out/attack-suite-honest.json"
step "live suite, honest" "$default" live-suite --out "$out/live-suite-honest.json"
if [ "$status" -eq 0 ]; then
  step "attack suite, sabotage controls" "$sabotage" attack-suite --honest-results "$out/attack-suite-honest.json" --out "$out/attack-suite.json"
  step "live suite, sabotage controls" "$sabotage" live-suite --honest-results "$out/live-suite-honest.json" --out "$out/live-suite.json"
else
  echo "factory-lab: sabotage controls not run, because an honest suite failed"
fi
exit "$status"

#!/usr/bin/env bash
# The root lab on a disposable CI runner (.github/workflows/lab.yml, #53).
#
#   scripts/lab/ci-lab.sh [--if-affected BASE_SHA]
#
# What it is for: a regression gate against honest mistakes in lane B host code.
# It is not proof against an adversarial author. The code under test is built
# and run here, and build scripts run as a user with passwordless sudo, so a
# change written to fool the lab can fool it. Lane C review is the control for
# that (docs/decisions/0002, #53).
#
# With --if-affected, the lab runs when the change since the merge base with
# BASE_SHA touches anything that can change the shipped binary (crates/, the
# Cargo manifests and lock, .cargo/, the toolchain pin, scripts/lab/), or when
# `claims_check.py --affected` reports a host lab claim. Otherwise it exits 0
# without building, so `lab` can be a required check. Output it cannot read
# is a failure, never a skip.
#
# The script, tools/ and claims.toml come from the pull request's merge ref.
# That is acceptable because scripts/ and tools/ are lane C, and narrowing a
# claim's files is a ratchet that raises a change to lane C. The verdict on the
# results JSON is taken with the base commit's copy of claims_check.py.
#
# The toolchain checks follow scripts/lab/lab-inside.sh: legacy config files,
# build-override variables, an exact pinned version, rustup's own proxies and
# toolchain paths, and a tripwire after the build. Then it builds the default
# and sabotage binaries and runs as root, with cgroup limits enforced:
#   - the honest attack suite (repeat 30) and live suite on the default build;
#   - the sabotage controls on the sabotage build, judged against the honest
#     results.
#
# Only for a throwaway machine (INV-11): it runs as root and changes cgroups.
set -euo pipefail

work="${RUNNER_TEMP:-$(mktemp -d)}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
fail() { echo "ci-lab: $*" >&2; echo "**lab failed:** $*" >> "$summary"; exit 1; }

# Every recorded CI evidence entry must still hold against the files it names and
# the claims as they are now. Cheap, builds nothing, and runs in every mode, so an
# evidence PR whose claims changed after recording fails here.
python3 tools/lab_record.py --verify || fail "recorded CI lab evidence does not hold (tools/lab_record.py --verify)"

base_sha=""
if [ "${1:-}" = "--if-affected" ]; then
  base_sha="${2:?--if-affected needs BASE_SHA}"
  base="$(git merge-base "$base_sha" HEAD)" || fail "no merge base with $base_sha"
  changed="$(git diff --name-only --no-renames "$base" HEAD)" || fail "git diff failed"
  binary_paths='^(crates/|Cargo\.toml$|Cargo\.lock$|\.cargo/|rust-toolchain|scripts/lab/)'
  python3 tools/claims_check.py --affected "$base" > "$work/affected.txt" || fail "claims_check --affected failed"
  cat "$work/affected.txt"
  if grep -qE "$binary_paths" <<<"$changed"; then
    echo "The change touches files that build the shipped binary; running the lab."
  elif grep -q '^Host claims requiring root lab refresh' "$work/affected.txt"; then
    echo "A host lab claim is affected; running the lab."
  elif grep -qE '^(Affected claims: none|No host lab claims affected)' "$work/affected.txt"; then
    echo "Nothing that builds the binary changed and no host lab claim is affected; the lab is not needed." | tee -a "$summary"
    exit 0
  else
    fail "could not tell which claims this change affects; refusing to skip"
  fi
elif [ "$#" -ne 0 ]; then
  echo "usage: ci-lab.sh [--if-affected BASE_SHA]" >&2
  exit 2
fi
judge_ref="${base_sha:-HEAD}"

echo "::group::toolchain checks"
[ ! -e rust-toolchain ] || fail "legacy rust-toolchain file, which rustup would prefer over rust-toolchain.toml"
[ ! -e .cargo/config ] || fail "legacy .cargo/config, which cargo would prefer over .cargo/config.toml"
# As in lab-inside.sh, minus CARGO_HOME and RUSTUP_HOME, which hosted runners set
# to fixed locations; their config files are refused below instead.
overrides='^(RUSTC|RUSTC_.*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_.*|RUSTUP_(TOOLCHAIN|DIST_.*|UPDATE_ROOT|OVERRIDE_.*)|CARGO_INCREMENTAL|CARGO_(BUILD|TARGET|PROFILE|UNSTABLE|SOURCE|REGISTRIES|REGISTRY)_.*|(HOST_|TARGET_)?(CC|CXX|AR|CFLAGS|CXXFLAGS|ARFLAGS|LDFLAGS|RANLIB|RANLIBFLAGS|CXXSTDLIB)(_.*)?|CRATE_CC_NO_DEFAULTS|COMPILER_PATH|GCC_EXEC_PREFIX|LIBRARY_PATH|CPATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|LD_.*)$'
names="$(python3 -c 'import os; print("\n".join(sorted(os.environ)))')" || fail "could not list the environment"
set_overrides="$(grep -E "$overrides" <<<"$names")" || [ $? -eq 1 ] || fail "could not match the environment"
[ -z "$set_overrides" ] || fail "build overrides are set: $(tr '\n' ' ' <<<"$set_overrides")"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
for cfg in "$cargo_home/config" "$cargo_home/config.toml" "$HOME/.cargo/config" "$HOME/.cargo/config.toml" /.cargo/config /.cargo/config.toml; do
  [ ! -e "$cfg" ] || fail "$cfg exists; only the repository's .cargo/config.toml may configure the build"
done
pin="$(python3 -c 'import sys; sys.path.insert(0, "tools"); import pins_check; print(pins_check.toolchain_channel(open("rust-toolchain.toml", encoding="utf-8").read()) or "")')" \
  || fail "could not read rust-toolchain.toml"
[[ "$pin" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "rust-toolchain.toml channel '$pin' is not an exact version"
rustup toolchain install "$pin" --profile minimal >/dev/null || fail "could not install Rust $pin"
rustup_bin="$(readlink -f "$(command -v rustup)")" || fail "rustup is not on PATH"
for tool in rustc cargo; do
  tool_bin="$(readlink -f "$(command -v "$tool")")" || fail "$tool is not on PATH"
  cmp -s "$tool_bin" "$rustup_bin" || fail "$tool on PATH ($tool_bin) is not the rustup proxy"
done
python3 tools/pins_check.py drift --rustc --cargo || fail "the active rustc or cargo is not the pinned Rust $pin"
rustc_vv="$(rustc -vV)" || fail "rustc -vV failed"
host="$(sed -n 's/^host: //p' <<<"$rustc_vv")"
[ -n "$host" ] || fail "rustc -vV reported no host"
toolchain_bin="${RUSTUP_HOME:-$HOME/.rustup}/toolchains/$pin-$host/bin"
rustc_path="$(rustup which rustc)" || fail "rustup which rustc failed"
cargo_path="$(rustup which cargo)" || fail "rustup which cargo failed"
[ "$rustc_path" = "$toolchain_bin/rustc" ] || fail "rustc is $rustc_path, not the installed $pin-$host"
[ "$cargo_path" = "$toolchain_bin/cargo" ] || fail "cargo is $cargo_path, not the installed $pin-$host"
cargo_v="$(cargo -V)" || fail "cargo -V failed"
echo "::endgroup::"

echo "::group::build"
target="$work/target"
cargo build --locked --release -p containment-host --target-dir "$target/default"
cargo build --locked --release -p containment-host --features sabotage --target-dir "$target/sabotage"
# Build scripts ran code from the change. A tripwire, not proof (see the header).
[ "$(rustc -vV)" = "$rustc_vv" ] || fail "rustc -vV changed during the build"
[ "$(cargo -V)" = "$cargo_v" ] || fail "cargo -V changed during the build"
[ "$(rustup which rustc)" = "$rustc_path" ] || fail "the rustc path changed during the build"
[ "$(rustup which cargo)" = "$cargo_path" ] || fail "the cargo path changed during the build"
echo "::endgroup::"

default="$target/default/release/containment-lab"
sabotage="$target/sabotage/release/containment-lab"
for bin in "$default" "$sabotage"; do
  [ -x "$bin" ] || fail "$bin is missing or not executable"
done
cmp -s "$default" "$sabotage" && fail "the default and sabotage binaries are identical; the controls would prove nothing"
default_sha="$(sha256sum "$default" | cut -d' ' -f1)"
sabotage_sha="$(sha256sum "$sabotage" | cut -d' ' -f1)"
out="$work/lab"
mkdir -p "$out"
# Ubuntu 24.04 runners refuse unprivileged user namespaces through AppArmor, and
# System One starts in one after dropping privileges (system_one.rs), so the
# controller fails with EACCES. The WSL2 and Linux VM labs have no such policy.
# This runner is thrown away after the job; the setting before and after is
# recorded with the results. The sandbox's own seccomp filter still refuses
# unshare to the agent, which is what the suites test.
userns_knob=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
userns_before="absent"
if [ -e "$userns_knob" ]; then
  userns_before="$(cat "$userns_knob")"
  [ "$userns_before" = 0 ] || sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 \
    || fail "could not allow unprivileged user namespaces for System One"
fi
userns_after="$(cat "$userns_knob" 2>/dev/null || echo absent)"
# The record of this run, committed with the results by tools/lab_record.py.
{
  echo "commit id: $(git rev-parse HEAD)"
  echo "runner: GitHub-hosted ${ImageOS:-unknown} ${ImageVersion:-unknown}"
  echo "kernel: $(uname -r)"
  echo "cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none)"
  echo "cpus: $(nproc)"
  echo "kernel.apparmor_restrict_unprivileged_userns: $userns_before -> $userns_after"
  echo "rust-toolchain channel: $pin"
  sed 's/^/rustc: /' <<<"$rustc_vv"
  echo "cargo: $cargo_v"
  echo "rustc path: $rustc_path"
  echo "Cargo.lock sha256: $(sha256sum Cargo.lock | cut -d' ' -f1)"
  echo "default binary sha256: $default_sha"
  echo "sabotage binary sha256: $sabotage_sha"
  echo "build overrides: none set (checked before the build)"
} > "$out/environment.txt"

{
  echo "### Lab on $(uname -r), commit $(git rev-parse HEAD)"
  echo
  echo "- toolchain: $pin ($host), $cargo_v"
  echo "- Cargo.lock sha256: \`$(sha256sum Cargo.lock | cut -d' ' -f1)\`"
  echo "- cgroup controllers: \`$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none)\`"
  echo "- apparmor_restrict_unprivileged_userns: $userns_before -> $userns_after"
  echo "- default build sha256: \`$default_sha\`"
  echo "- sabotage build sha256: \`$sabotage_sha\`"
  echo
  echo "| step | result | seconds |"
  echo "|---|---|---|"
} >> "$summary"

status=0
step() {
  local name="$1"; shift
  local start=$SECONDS
  echo "::group::$name"
  if sudo "$@"; then
    echo "| $name | pass | $((SECONDS - start)) |" >> "$summary"
  else
    echo "| $name | **fail** | $((SECONDS - start)) |" >> "$summary"
    status=1
  fi
  echo "::endgroup::"
}

step "attack suite, honest (repeat 30)" "$default" attack-suite --repeat 30 --out "$out/attack-suite-honest.json"
step "live suite, honest" "$default" live-suite --out "$out/live-suite-honest.json"
# The controls need the honest results; without them there is nothing to judge against.
if [ "$status" -eq 0 ]; then
  step "attack suite, sabotage controls" "$sabotage" attack-suite \
    --honest-results "$out/attack-suite-honest.json" --out "$out/attack-suite-local.json"
  step "live suite, sabotage controls" "$sabotage" live-suite \
    --honest-results "$out/live-suite-honest.json" --out "$out/live-suite-local.json"
else
  echo "| sabotage controls | not run: an honest suite failed | |" >> "$summary"
fi
sudo chown -R "$(id -u):$(id -g)" "$out"
[ "$status" -eq 0 ] || fail "a suite or control failed"

# The binaries' exit codes are not the whole verdict. The combined results are
# judged with the base commit's CI-8 rules (dual-binary stamps, timed_repeat,
# no waived limits), and the stamped hashes must be the binaries built here.
echo "::group::judge the results with $judge_ref's claims_check.py"
judge="$work/judge"
mkdir -p "$judge/tools" "$judge/results"
git archive "$judge_ref" tools | tar -x -C "$judge" || fail "could not read tools/ at $judge_ref"
cp "$out/attack-suite-local.json" "$judge/results/attack-suite.json"
cp "$out/live-suite-local.json" "$judge/results/live-suite.json"
python3 -I - "$judge" "$default_sha" "$sabotage_sha" <<'EOF' || fail "the results do not pass CI-8"
import json, sys
from pathlib import Path
judge, default_sha, sabotage_sha = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, str(Path(judge) / "tools"))
import claims_check
errors = claims_check.build_errors(Path(judge) / "results")
for name in ("attack-suite.json", "live-suite.json"):
    build = json.loads((Path(judge) / "results" / name).read_text(encoding="utf-8")).get("build") or {}
    if (build.get("honest") or {}).get("binary_sha256") != default_sha:
        errors.append(f"{name}: the honest stamp is not the default binary built here")
    if (build.get("sabotage") or {}).get("binary_sha256") != sabotage_sha:
        errors.append(f"{name}: the sabotage stamp is not the sabotage binary built here")
print("\n".join(errors) or "CI-8 holds and the stamps match the binaries built here")
sys.exit(1 if errors else 0)
EOF
echo "::endgroup::"
echo "Results judged: CI-8 holds, and the stamps match the binaries built here." >> "$summary"

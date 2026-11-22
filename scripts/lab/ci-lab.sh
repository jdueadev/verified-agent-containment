#!/usr/bin/env bash
# The root lab on a disposable CI runner (.github/workflows/lab.yaml, #53).
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

# Every recorded CI evidence entry should still hold against the files it names and
# the claims as they are now. An evidence PR (one that touches results/ci/) must pass
# this, so evidence whose claims changed after recording cannot merge. Any other PR
# may legitimately change a claim that has an entry (adding a scenario, say); there
# it is a warning, and ci-record.sh treats an entry that no longer holds as stale,
# so the next lab run on main records replacement evidence.
verify_ok=true
python3 tools/lab_record.py --verify > "$work/verify.json" || verify_ok=false

base_sha=""
if [ "${1:-}" = "--if-affected" ]; then
  base_sha="${2:?--if-affected needs BASE_SHA}"
  base="$(git merge-base "$base_sha" HEAD)" || fail "no merge base with $base_sha"
  changed="$(git diff --name-only --no-renames "$base" HEAD)" || fail "git diff failed"
  evidence_pr=false
  # An evidence PR touches results/ci/ or adds or edits a CI evidence entry.
  if grep -q '^results/ci/' <<<"$changed" \
     || git diff "$base" HEAD -- claims.toml | grep -qE '^[-+].*lab evidence: results/ci/'; then
    evidence_pr=true
  fi
  if [ "$verify_ok" = false ]; then
    cat "$work/verify.json"
    if [ "$evidence_pr" = true ]; then
      fail "this evidence PR's recorded CI lab evidence does not hold (tools/lab_record.py --verify)"
    fi
    echo "Warning: recorded CI lab evidence no longer holds for the claims as changed here; the next lab run on main replaces it." | tee -a "$summary"
  fi
  binary_paths='^(crates/|Cargo\.toml$|Cargo\.lock$|\.cargo/|rust-toolchain|scripts/lab/)'
  python3 tools/claims_check.py --affected "$base" > "$work/affected.txt" || fail "claims_check --affected failed"
  cat "$work/affected.txt"
  if grep -qE "$binary_paths" <<<"$changed"; then
    echo "The change touches files that build the shipped binary; running the lab."
  elif grep -q '^Host claims requiring root lab refresh' "$work/affected.txt"; then
    echo "A host lab claim is affected; running the lab."
  elif grep -qE '^(Affected claims: none|No host lab claims affected|No changed files relative to )' "$work/affected.txt"; then
    echo "Nothing that builds the binary changed and no host lab claim is affected; the lab is not needed." | tee -a "$summary"
    exit 0
  else
    fail "could not tell which claims this change affects; refusing to skip"
  fi
elif [ "$#" -ne 0 ]; then
  echo "usage: ci-lab.sh [--if-affected BASE_SHA]" >&2
  exit 2
elif [ "$verify_ok" = false ]; then
  # On main or a spike: report it; ci-record.sh records replacement evidence.
  cat "$work/verify.json"
  echo "Warning: recorded CI lab evidence no longer holds; this run's record job replaces it." | tee -a "$summary"
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
# The sandbox mounts the host's /usr read-only, and the sandbox_escape scenario
# reads the header of every executable the agent can see (no_windows_images_
# reachable). Hosted runner images carry tens of GB of preinstalled SDKs under
# /usr/local and /usr/share (Android, .NET, Swift, ...), so that scan outlasts the
# harness's wait, and .NET ships PE images. After the build, those trees are
# removed from this disposable runner so its /usr is like a stock install, as on
# the WSL2 and Linux VM labs. The check is unchanged; what was removed is recorded.
usr_before="$(sudo du -sxh /usr 2>/dev/null | cut -f1)"
trimmed=()
for tree in /usr/local /usr/share/dotnet /usr/share/swift /usr/share/miniconda /usr/share/sbt \
            /usr/share/kotlinc /usr/share/az_* /usr/lib/jvm /usr/lib/google-cloud-sdk /usr/lib/firefox; do
  [ -e "$tree" ] || continue
  if [ "$tree" = /usr/local ]; then
    sudo find /usr/local -mindepth 1 -maxdepth 1 -exec rm -rf {} + || fail "could not trim $tree"
  else
    sudo rm -rf "$tree" || fail "could not trim $tree"
  fi
  trimmed+=("$tree")
done
hash -r
command -v python3 >/dev/null || fail "python3 is gone after trimming the runner image"
usr_after="$(sudo du -sxh /usr 2>/dev/null | cut -f1)"
usr_note="/usr $usr_before -> $usr_after; removed: ${trimmed[*]:-nothing}"

# The controller copies itself into /run/verified-agent-containment and executes
# the copy, and hosted runners mount /run noexec (execve returns EACCES). Only
# that one directory gets a fresh tmpfs that allows exec; the rest of /run keeps
# its options. Recorded with the results.
run_dir=/run/verified-agent-containment
run_opts="$(findmnt -no OPTIONS /run 2>/dev/null || echo unknown)"
if [[ ",$run_opts," == *",noexec,"* ]]; then
  sudo mkdir -p "$run_dir"
  sudo mount -t tmpfs -o mode=0755,nosuid,nodev,exec tmpfs "$run_dir" \
    || fail "could not mount an exec tmpfs at $run_dir"
  run_note="/run is $run_opts; $run_dir mounted as its own tmpfs with exec"
else
  run_note="/run is $run_opts; nothing changed"
fi
# The record of this run, committed with the results by tools/lab_record.py.
{
  echo "commit id: $(git rev-parse HEAD)"
  echo "runner: GitHub-hosted ${ImageOS:-unknown} ${ImageVersion:-unknown}"
  echo "kernel: $(uname -r)"
  echo "cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none)"
  echo "cpus: $(nproc)"
  echo "kernel.apparmor_restrict_unprivileged_userns: $userns_before -> $userns_after"
  echo "run directory: $run_note"
  echo "runner image trimmed: $usr_note"
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
  echo "- run directory: $run_note"
  echo "- runner image trimmed: $usr_note"
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
if [ "$status" -ne 0 ]; then
  # Diagnostics for a runner the suites have not run on before: which syscalls fail.
  echo "::group::diagnostics"
  for m in /run /run/verified-agent-containment /tmp /sys/fs/cgroup; do
    echo "mount $m: $(findmnt -no FSTYPE,OPTIONS --target "$m" 2>&1)"
  done
  echo "apparmor_restrict_unprivileged_userns: $(cat "$userns_knob" 2>/dev/null || echo absent)"
  echo "unprivileged_userns_clone: $(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo absent)"
  echo "max_user_namespaces: $(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo absent)"
  echo "runner image trimmed: $usr_note"
  # What the sandbox_escape scan walks: the host's /usr and /lib* are bound read-only.
  echo "files under /usr and /lib*: $(sudo find /usr /lib /lib64 /lib32 /libx32 -xdev 2>/dev/null | wc -l)"
  echo "busiest directories:"
  (set +o pipefail; sudo find /usr /lib -xdev -type f 2>/dev/null | cut -d/ -f1-4 | sort | uniq -c | sort -rn | head -12) || true
  sudo python3 -I - <<'PY' || true
import os, time
start, files, pe = time.monotonic(), 0, 0
for top in ("/usr", "/lib", "/lib64"):
    for root, dirs, names in os.walk(top):
        if root.count("/") > 12:
            dirs[:] = []
        for n in names:
            path = os.path.join(root, n)
            files += 1
            if os.path.isfile(path) and os.access(path, os.X_OK):
                try:
                    with open(path, "rb") as f:
                        pe += f.read(2) == b"MZ"
                except OSError:
                    pass
print(f"scan like the agent's: {files} files, {pe} PE executables, {time.monotonic() - start:.1f}s as root without limits")
PY
  if command -v strace >/dev/null || sudo apt-get install -y -q strace >/dev/null 2>&1; then
    sudo strace -f -qq -Z -e trace=all -o "$work/strace.txt" "$default" attack-suite --only benign --repeat 1 \
      --allow-missing-limits --out "$work/diag.json" >/dev/null 2>&1 || true
    grep -E 'EACCES|EPERM' "$work/strace.txt" | head -40 || true
    # What the sandbox_escape agent does before the harness stops waiting for its scan.
    sudo strace -f -qq -tt -o "$work/escape.txt" "$default" attack-suite --only sandbox_escape --repeat 1 \
      --allow-missing-limits --out "$work/diag-escape.json" >/dev/null 2>&1 || true
    sudo python3 -I - "$work/escape.txt" <<'PY' || true
import collections, re, sys
lines = open(sys.argv[1], errors="replace").read().splitlines()
# The agent is the process that runs /agent after the sandbox pivots its root.
agents = {l.split()[0] for l in lines if 'execve("/agent"' in l}
print(f"agent pids: {sorted(agents)}")
for pid in sorted(agents):
    mine = [l for l in lines if l.split()[0] == pid]
    calls = collections.Counter(m.group(1) for l in mine if (m := re.match(r"\S+ \S+ (\w+)\(", l)))
    print(f"pid {pid}: {len(mine)} lines; top calls {calls.most_common(8)}")
    for l in mine[-25:]:
        print("  " + l[:220])
PY
  else
    echo "strace is not available"
  fi
  echo "::endgroup::"
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

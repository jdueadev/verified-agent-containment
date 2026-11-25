#!/usr/bin/env bash
# Runs inside the throwaway WSL2 distro as root (started by lab.ps1).
# Installs tools, builds the project and llama.cpp, fetches and verifies the
# model, runs both suites without waivers, then serves the model and runs the
# red team. Progress goes to <lab>/logs/status.txt; results to <lab>/results/<stamp>.
set -euo pipefail

LAB="" REPO="" MODEL="" STAMP="$(date +%Y%m%d-%H%M%S)" ONLY="all"
while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --stamp) STAMP="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ -n "$LAB" ] && [ -n "$REPO" ] && [ -n "$MODEL" ] || { echo "usage: lab-inside.sh --lab DIR --repo BUNDLE --model REPO:FILE [--stamp S] [--only all|suites]" >&2; exit 2; }

case "$ONLY" in all|suites) ;; *) echo "--only must be all or suites" >&2; exit 2 ;; esac
RES="$LAB/results/$STAMP"
mkdir -p "$RES" "$LAB/logs" "$LAB/models"
exec > >(tee -a "$LAB/logs/inside-$STAMP.log") 2>&1
say() { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LAB/logs/status.txt"; }
fail() { say "FAILED inside: $*"; exit 1; }
SERVER_PID=""
KEY_DIR=""
cleanup() { [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true; [ -z "$KEY_DIR" ] || rm -rf "$KEY_DIR"; }
trap cleanup EXIT
export DEBIAN_FRONTEND=noninteractive PATH="/root/.cargo/bin:/usr/local/cuda/bin:$PATH"
PINS_OUT=""   # pins.env lines for values that were not pinned yet

# ---- 4. tools and builds ------------------------------------------------------
say "STEP 4/6 apt packages"
apt-get update -q
apt-get install -y -q build-essential git curl ca-certificates python3 cmake pkg-config rustup >/dev/null
# rustup from Ubuntu's signed archive (not curl | sh); it checks toolchain hashes.
# The toolchain itself is the one rust-toolchain.toml pins; it is installed and
# checked after the clone below, before anything is built.

GPU=cpu
if [ -e /usr/lib/wsl/lib/libcuda.so.1 ] || [ -e /usr/lib/wsl/lib/libcuda.so ]; then
  if ! command -v nvcc >/dev/null; then
    say "  CUDA toolkit (NVIDIA WSL repository; Blackwell needs 12.8 or newer)"
    curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
    dpkg -i /tmp/cuda-keyring.deb >/dev/null
    apt-get update -q
    for pkg in cuda-toolkit-13-0 cuda-toolkit-12-9 cuda-toolkit-12-8; do
      if apt-get install -y -q "$pkg" >/dev/null; then say "  installed $pkg"; break; fi
    done
  fi
  command -v nvcc >/dev/null && GPU=cuda
fi
say "  inference backend: $GPU"

say "  project from $REPO"
rm -rf /root/vac
git clone -q "$REPO" /root/vac
cd /root/vac
COMMIT="$(git rev-parse --short HEAD)"

# The binaries must come from the toolchain rust-toolchain.toml pins, and the
# record of that toolchain is written before the build (#68). Anything that is
# not confirmed stops the run: nothing is built on an unchecked toolchain.
say "  Rust toolchain (pinned in rust-toolchain.toml)"
[ ! -e rust-toolchain ] || fail "the clone has a legacy rust-toolchain file, which rustup would prefer over rust-toolchain.toml"
[ ! -e .cargo/config ] || fail "the clone has a legacy .cargo/config, which cargo would prefer over .cargo/config.toml"
# Build overrides: variables that make rustup, cargo, rustc or the cc crate (which
# builds ring's C code into the binary), gcc or the dynamic loader (rustc loads
# librustc_driver at run time) use another compiler, flags, toolchain, source or
# C toolchain. The distro is new each run, so none of them belongs
# here; one that is set, even to an empty value, stops the run. Only names are
# reported, never values. The paths below assume HOME=/root (lab.ps1 runs as root).
[ "$HOME" = /root ] || fail "HOME is '$HOME', not /root; the cargo config and toolchain paths checked here assume it"
BUILD_OVERRIDES='^(RUSTC|RUSTC_.*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_.*|RUSTUP_.*|CARGO_HOME|CARGO_INCREMENTAL|CARGO_(BUILD|TARGET|PROFILE|UNSTABLE|SOURCE|REGISTRIES|REGISTRY)_.*|(HOST_|TARGET_)?(CC|CXX|AR|CFLAGS|CXXFLAGS|ARFLAGS|LDFLAGS|RANLIB|RANLIBFLAGS|CXXSTDLIB)(_.*)?|CRATE_CC_NO_DEFAULTS|COMPILER_PATH|GCC_EXEC_PREFIX|LIBRARY_PATH|CPATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|LD_.*)$'
# Names come from the process environment, not `compgen -e`: bash cannot list a
# name such as CFLAGS_x86_64-unknown-linux-gnu, but it still passes it to cargo.
ENV_NAMES="$(python3 -c 'import os; print("\n".join(sorted(os.environ)))')" || fail "could not list the environment"
OVERRIDES="$(grep -E "$BUILD_OVERRIDES" <<<"$ENV_NAMES")" || [ $? -eq 1 ] || fail "could not match the environment against the override pattern"
[ -z "$OVERRIDES" ] || fail "build overrides are set: $(echo "$OVERRIDES" | tr '\n' ' ')"
for cfg in /root/.cargo/config /root/.cargo/config.toml /.cargo/config /.cargo/config.toml; do
  [ ! -e "$cfg" ] || fail "$cfg exists; only the repository's .cargo/config.toml may configure the build"
done
PIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" || fail "could not read rust-toolchain.toml"
[[ "$PIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "rust-toolchain.toml channel '$PIN' is not an exact version"
# Installed explicitly, with the components the check image installs, so nothing depends on
# whether this rustup auto-installs an override.
rustup toolchain install "$PIN" --profile minimal --component clippy --component rustfmt --target wasm32-unknown-unknown >/dev/null \
  || fail "could not install Rust $PIN"
# cargo runs the first `rustc` on PATH, so both must be rustup's own proxies,
# which resolve the toolchain checked below. A stand-in that prints the right
# version is refused here.
TOOL_BIN="$(command -v rustup)" || fail "rustup is not on PATH"
RUSTUP_BIN="$(readlink -f "$TOOL_BIN")"
for tool in rustc cargo; do
  TOOL_BIN="$(command -v "$tool")" || fail "$tool is not on PATH"
  TOOL_BIN="$(readlink -f "$TOOL_BIN")"
  cmp -s "$TOOL_BIN" "$RUSTUP_BIN" || fail "$tool on PATH ($TOOL_BIN) is not the rustup proxy"
done
for tool in rustc cargo; do
  [[ "$("$tool" --version | head -1)" == "$tool $PIN ("* ]] || fail "the active $tool is not the pinned Rust $PIN"
done
RUSTC_VV="$(rustc -vV)" || fail "rustc -vV failed"
HOST="$(sed -n 's/^host: //p' <<<"$RUSTC_VV")"
[ -n "$HOST" ] || fail "rustc -vV reported no host"
TOOLCHAIN_BIN="/root/.rustup/toolchains/$PIN-$HOST/bin"
RUSTC_PATH="$(rustup which rustc)" || fail "rustup which rustc failed"
CARGO_PATH="$(rustup which cargo)" || fail "rustup which cargo failed"
# A toolchain added with `rustup toolchain link` reports any version it likes.
# rustup refuses to link one under a release name such as `1.100.0-<host>`
# ("invalid custom toolchain name"), so only an installed release lives here.
[ "$RUSTC_PATH" = "$TOOLCHAIN_BIN/rustc" ] || fail "rustc is $RUSTC_PATH, not the installed $PIN-$HOST"
[ "$CARGO_PATH" = "$TOOLCHAIN_BIN/cargo" ] || fail "cargo is $CARGO_PATH, not the installed $PIN-$HOST"
CARGO_V="$(cargo -V)" || fail "cargo -V failed"
ACTIVE="$(rustup show active-toolchain)" || fail "rustup show active-toolchain failed"
RUSTUP_V="$(rustup --version 2>/dev/null | sed -n 1p)" || fail "rustup --version failed"
CC_V="$(cc --version | sed -n 1p)" || fail "cc --version failed"
LD_V="$(ld --version | sed -n 1p)" || fail "ld --version failed"
PKGS="$(dpkg-query -W gcc binutils libc6-dev)" || fail "dpkg-query failed for the C toolchain"
LOCK_SHA="$(sha256sum Cargo.lock | cut -d' ' -f1)" || fail "no Cargo.lock"
CFG_SHA="none"
if [ -e .cargo/config.toml ]; then
  CFG_SHA="$(sha256sum .cargo/config.toml | cut -d' ' -f1)" || fail "could not hash .cargo/config.toml"
fi
COMMIT_ID="$(git rev-parse HEAD)" || fail "git rev-parse HEAD failed"
RUSTC_ON_PATH="$(command -v rustc)" || fail "rustc is not on PATH"
{
  echo "commit: $COMMIT"
  echo "commit id: $COMMIT_ID"
  echo "rust-toolchain channel: $PIN"
  echo "rustup: $RUSTUP_V"
  echo "rustup active toolchain: $ACTIVE"
  echo "rustc path: $RUSTC_PATH"
  echo "rustc on PATH: $RUSTC_ON_PATH (rustup proxy $RUSTUP_BIN)"
  sed 's/^/rustc: /' <<<"$RUSTC_VV"
  echo "cargo: $CARGO_V"
  echo "Cargo.lock sha256: $LOCK_SHA"
  echo ".cargo/config.toml sha256: $CFG_SHA"
  echo "cc: $CC_V"
  echo "ld: $LD_V"
  sed 's/^/package: /' <<<"$PKGS"
  echo "build overrides: none set (pattern checked before the build: $BUILD_OVERRIDES)"
} > "$RES/environment.txt"

# Two binaries. The default build is the one that ships: it runs the honest
# suites and, later, the model. The sabotage build contains the deliberate
# defects and runs only the controls that prove the suites can see them.
cargo build --release -q --locked -p containment-host
cargo build --release -q --locked -p containment-host --features sabotage --target-dir /root/vac/target-sabotage
LAB_BIN=/root/vac/target/release/containment-lab
SAB_BIN=/root/vac/target-sabotage/release/containment-lab
# The build ran code from the clone (build scripts, proc macros) as root. This
# is a tripwire, not proof: such code could also fake these answers or rewrite
# the record (see scripts/lab/README.md). Each query must also succeed: matching
# output from a command that then fails is not a confirmation.
NOW="$(rustc -vV)" || fail "rustc -vV failed after the build"
[ "$NOW" = "$RUSTC_VV" ] || fail "rustc -vV changed during the build"
NOW="$(cargo -V)" || fail "cargo -V failed after the build"
[ "$NOW" = "$CARGO_V" ] || fail "cargo -V changed during the build"
NOW="$(rustup which rustc)" || fail "rustup which rustc failed after the build"
[ "$NOW" = "$RUSTC_PATH" ] || fail "the rustc path changed during the build"
NOW="$(rustup which cargo)" || fail "rustup which cargo failed after the build"
[ "$NOW" = "$CARGO_PATH" ] || fail "the cargo path changed during the build"
LAB_SHA="$(sha256sum "$LAB_BIN" | cut -d' ' -f1)" || fail "could not hash $LAB_BIN"
SAB_SHA="$(sha256sum "$SAB_BIN" | cut -d' ' -f1)" || fail "could not hash $SAB_BIN"

{
  echo "default binary sha256: $LAB_SHA"
  echo "sabotage binary sha256: $SAB_SHA"
  echo "kernel: $(uname -r)"
  echo "cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none)"
  echo "cpus: $(nproc)"
  free -h
  /usr/lib/wsl/lib/nvidia-smi 2>/dev/null || echo "nvidia-smi: not available"
  command -v nvcc >/dev/null && nvcc --version | tail -2
} >> "$RES/environment.txt" 2>&1
say "  built $COMMIT with Rust $PIN; environment in results/$STAMP/environment.txt"

# shellcheck source=pins.env
. /root/vac/scripts/lab/pins.env

# ---- 5. suites, no waivers ----------------------------------------------------
SUITES_OK=1
say "STEP 5/6 attack suite (repeat 30, cgroup limits enforced)"
# Honest runs on the default build, then the controls on the sabotage build,
# which copies the honest runs into the final file with both build stamps.
if "$LAB_BIN" attack-suite --repeat 30 --out "$RES/attack-suite-honest.json" > "$RES/attack-suite.log" 2>&1 \
  && "$SAB_BIN" attack-suite --honest-results "$RES/attack-suite-honest.json" --out "$RES/attack-suite.json" >> "$RES/attack-suite.log" 2>&1; then
  say "  $(tail -1 "$RES/attack-suite.log")"
else
  SUITES_OK=0; say "  attack suite FAILED: $(tail -1 "$RES/attack-suite.log")"
fi
say "  live suite"
if "$LAB_BIN" live-suite --out "$RES/live-suite-honest.json" > "$RES/live-suite.log" 2>&1 \
  && "$SAB_BIN" live-suite --honest-results "$RES/live-suite-honest.json" --out "$RES/live-suite.json" >> "$RES/live-suite.log" 2>&1; then
  say "  $(tail -1 "$RES/live-suite.log")"
else
  SUITES_OK=0; say "  live suite FAILED: $(tail -1 "$RES/live-suite.log")"
fi
if [ "$ONLY" = "suites" ]; then say "DONE inside (suites only)"; exit $((1 - SUITES_OK)); fi
# Interop must be off for this distro: a process here must not be able to start
# Windows programs. The WSLInterop binfmt entry is registered once for the whole
# WSL VM (other distros may use it), so test the effect, not the registration.
# Fail closed: no probe target, a timeout or a kill is not evidence.
WIN_EXE=""
for candidate in /mnt/c/Windows/System32/whoami.exe /mnt/c/WINDOWS/system32/whoami.exe; do
  [ -e "$candidate" ] && WIN_EXE="$candidate" && break
done
[ -n "$WIN_EXE" ] || fail "interop check: no Windows program found under /mnt/c to probe with, so interop could not be tested"
PROBE=0; PROBE_OUT="$(timeout -s KILL 20 "$WIN_EXE" 2>&1 >/dev/null)" || PROBE=$?
case "$PROBE" in
  0) fail "a Windows program ($WIN_EXE) ran from inside the distro; interop is not off, so no model is attached" ;;
  124|137) fail "interop check: $WIN_EXE neither ran nor was refused within 20 s (exit $PROBE)" ;;
esac
echo "interop probe: $WIN_EXE exit $PROBE: ${PROBE_OUT:0:200}" >> "$RES/environment.txt"
say "  interop check: Windows programs do not run here (tested $WIN_EXE, exit $PROBE)"
# A model is attached only to a controller that passed its gate (claim C-SYS-1).
[ "$SUITES_OK" = 1 ] || fail "suites failed, so no model is attached; see results/$STAMP"

# ---- 6. llama.cpp, model, red team ---------------------------------------------
say "STEP 6/6 llama.cpp ($GPU)"
# nvcc jobs use 1-2 GB each; WSL gets half the host's RAM by default.
MEM_GB=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1048576 ))
JOBS=$(( MEM_GB / 2 )); [ "$JOBS" -ge 1 ] || JOBS=1; [ "$JOBS" -le "$(nproc)" ] || JOBS=$(nproc)
# Reuse a kept build only if it is the pinned commit.
if [ -x /root/llama.cpp/build/bin/llama-server ] && [ -n "$LLAMA_CPP_COMMIT" ] \
    && [ "$(git -C /root/llama.cpp rev-parse HEAD 2>/dev/null)" != "$LLAMA_CPP_COMMIT" ]; then
  rm -rf /root/llama.cpp
fi
if [ ! -x /root/llama.cpp/build/bin/llama-server ]; then
  rm -rf /root/llama.cpp
  git clone -q https://github.com/ggml-org/llama.cpp /root/llama.cpp
  cd /root/llama.cpp
  if [ -n "$LLAMA_CPP_COMMIT" ]; then
    git checkout -q "$LLAMA_CPP_COMMIT" || fail "pinned llama.cpp commit $LLAMA_CPP_COMMIT not found"
  else
    PINS_OUT+="LLAMA_CPP_COMMIT=\"$(git rev-parse HEAD)\""$'\n'
    say "  llama.cpp not pinned yet: using $(git rev-parse --short HEAD) (recorded in results/$STAMP/pins.env)"
  fi
  if [ "$GPU" = cuda ] && cmake -B build -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=native -DLLAMA_CURL=OFF >/dev/null \
      && cmake --build build --config Release -j "$JOBS" --target llama-server >/dev/null; then
    say "  built llama-server with CUDA ($(git rev-parse --short HEAD))"
  else
    [ "$GPU" = cpu ] || say "  CUDA build failed; building for CPU instead"
    GPU=cpu; rm -rf build
    cmake -B build -DLLAMA_CURL=OFF >/dev/null && cmake --build build --config Release -j "$JOBS" --target llama-server >/dev/null \
      || fail "llama.cpp build failed"
    say "  built llama-server for CPU ($(git rev-parse --short HEAD))"
  fi
fi
cd /root/vac

HF_REPO="${MODEL%%:*}"; HF_FILE="${MODEL#*:}"
GGUF="$LAB/models/$HF_FILE"
# The Hub's SHA-256 of this exact file: the X-Linked-Etag of its resolve URL
# (an LFS file's etag is its SHA-256; no tree listing, so no pagination).
EXPECT="$(curl -fsSI "https://huggingface.co/$HF_REPO/resolve/main/$HF_FILE" | tr -d '\r' \
  | awk -F': ' 'tolower($1)=="x-linked-etag" {gsub(/"/, "", $2); print $2; exit}')" || true
[[ "$EXPECT" =~ ^[0-9a-f]{64}$ ]] || EXPECT=""
# Pins are per repository and file, so a same-named file elsewhere is not checked against this one.
PIN_VAR="MODEL_SHA256_$(printf '%s__%s' "$HF_REPO" "${HF_FILE%.gguf}" | tr -c 'A-Za-z0-9' '_')"
PINNED="${!PIN_VAR:-}"
if [ -n "$PINNED" ]; then
  # The pin in the repo is the authority; the Hub's value must agree with it.
  [ -z "$EXPECT" ] || [ "$EXPECT" = "$PINNED" ] || fail "Hugging Face now reports a different SHA-256 for $HF_FILE than the pinned one"
  EXPECT="$PINNED"
else
  [ -n "$EXPECT" ] || fail "could not get the SHA-256 of $HF_FILE from huggingface.co/$HF_REPO"
  PINS_OUT+="$PIN_VAR=\"$EXPECT\""$'\n'
  say "  $HF_FILE not pinned yet: trusting the Hub's SHA-256 this once (recorded in results/$STAMP/pins.env)"
fi
if [ ! -f "$GGUF" ] || [ "$(sha256sum "$GGUF" | cut -d' ' -f1)" != "$EXPECT" ]; then
  say "  downloading $HF_REPO/$HF_FILE"
  curl -fL --retry 5 -C - -o "$GGUF.part" "https://huggingface.co/$HF_REPO/resolve/main/$HF_FILE"
  if [ "$(sha256sum "$GGUF.part" | cut -d' ' -f1)" != "$EXPECT" ]; then
    rm -f "$GGUF.part"   # a bad partial file would otherwise be resumed forever
    fail "checksum mismatch for $HF_FILE"
  fi
  mv "$GGUF.part" "$GGUF"
fi
say "  model verified: $HF_FILE (sha256 $EXPECT)"

[ -z "$PINS_OUT" ] || printf '%s' "$PINS_OUT" > "$RES/pins.env"

# Thinking off: each call is capped at 1024 tokens by the red-team policy.
# WSL forwards localhost to Windows, so the server needs a key; the gateway
# sends it (from REDTEAM_MODEL_KEY) and the sandboxed agent never sees it.
REDTEAM_MODEL_KEY="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export REDTEAM_MODEL_KEY
# The key goes to llama-server and curl through 0600 files, not argv: /proc/<pid>/cmdline
# is readable by every uid, including System One's.
KEY_DIR="$(mktemp -d)"; chmod 700 "$KEY_DIR"
( umask 077; printf '%s' "$REDTEAM_MODEL_KEY" > "$KEY_DIR/key"; printf 'Authorization: Bearer %s\n' "$REDTEAM_MODEL_KEY" > "$KEY_DIR/header" )
NGL=0; [ "$GPU" = cuda ] && NGL=99
/root/llama.cpp/build/bin/llama-server -m "$GGUF" --host 127.0.0.1 --port 8080 -ngl "$NGL" -c 32768 --api-key-file "$KEY_DIR/key" \
  --jinja --chat-template-kwargs '{"enable_thinking": false}' > "$RES/llama-server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 300); do
  curl -fs http://127.0.0.1:8080/health >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || fail "llama-server exited; see results/$STAMP/llama-server.log"
  sleep 1
done
curl -fs http://127.0.0.1:8080/health >/dev/null || fail "llama-server did not become healthy in 300 s"
say "  llama-server healthy (offloaded layers: $NGL)"

# Diagnostic: does the model return a native tool call through llama-server?
curl -fs http://127.0.0.1:8080/v1/chat/completions -H 'Content-Type: application/json' -H @"$KEY_DIR/header" -d '{
  "messages": [{"role": "user", "content": "List the files in the workspace."}],
  "tools": [{"type": "function", "function": {"name": "list_dir", "description": "List a directory.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}],
  "max_tokens": 256}' > "$RES/tool-call-check.json" || true
if python3 -c 'import json,sys; m=json.load(open(sys.argv[1]))["choices"][0]["message"]; sys.exit(0 if m.get("tool_calls") else 1)' "$RES/tool-call-check.json" 2>/dev/null; then
  say "  tool-call check: native tool call returned"
else say "  tool-call check: no native tool call (see results/$STAMP/tool-call-check.json)"; fi

say "  red team against $HF_FILE"
RT=0
"$LAB_BIN" redteam --model-endpoint http://127.0.0.1:8080/v1/chat/completions --model "$HF_FILE" \
  --out "$RES/redteam" > "$RES/redteam.log" 2>&1 || RT=$?
grep -E '^[a-z_]+ +[A-Za-z]' "$RES/redteam.log" | while read -r line; do say "    $line"; done || true
[ "$RT" = 0 ] || fail "red team exited $RT (a LEAK, or an error; see results/$STAMP/redteam.log)"
say "DONE inside: results in results/$STAMP"

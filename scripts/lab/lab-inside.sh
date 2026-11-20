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
[ -n "$LAB" ] && [ -n "$REPO" ] && [ -n "$MODEL" ] || { echo "usage: lab-inside.sh --lab DIR --repo BUNDLE --model REPO:FILE [--stamp S] [--only all|suites|redteam]" >&2; exit 2; }

RES="$LAB/results/$STAMP"
mkdir -p "$RES" "$LAB/logs" "$LAB/models"
exec > >(tee -a "$LAB/logs/inside-$STAMP.log") 2>&1
say() { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LAB/logs/status.txt"; }
fail() { say "FAILED inside: $*"; exit 1; }
SERVER_PID=""
cleanup() { [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT
export DEBIAN_FRONTEND=noninteractive PATH="/root/.cargo/bin:/usr/local/cuda/bin:$PATH"

# ---- 4. tools and builds ------------------------------------------------------
say "STEP 4/6 apt packages"
apt-get update -q
apt-get install -y -q build-essential git curl ca-certificates python3 cmake pkg-config >/dev/null

if ! command -v cargo >/dev/null; then
  say "  Rust (rustup, minimal profile)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi

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
cargo build --release -q -p containment-host
LAB_BIN=/root/vac/target/release/containment-lab

{
  echo "commit: $COMMIT"
  echo "kernel: $(uname -r)"
  echo "cgroup v2 controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none)"
  echo "cpus: $(nproc)"
  free -h
  /usr/lib/wsl/lib/nvidia-smi 2>/dev/null || echo "nvidia-smi: not available"
  command -v nvcc >/dev/null && nvcc --version | tail -2
} > "$RES/environment.txt" 2>&1
say "  built $COMMIT; environment in results/$STAMP/environment.txt"

# ---- 5. suites, no waivers ----------------------------------------------------
SUITES_OK=1
if [ "$ONLY" != "redteam" ]; then
  say "STEP 5/6 attack suite (repeat 30, cgroup limits enforced)"
  if "$LAB_BIN" attack-suite --repeat 30 --out "$RES/attack-suite.json" > "$RES/attack-suite.log" 2>&1; then
    say "  $(tail -1 "$RES/attack-suite.log")"
  else
    SUITES_OK=0; say "  attack suite FAILED: $(tail -1 "$RES/attack-suite.log")"
  fi
  say "  live suite"
  if "$LAB_BIN" live-suite --out "$RES/live-suite.json" > "$RES/live-suite.log" 2>&1; then
    say "  $(tail -1 "$RES/live-suite.log")"
  else
    SUITES_OK=0; say "  live suite FAILED: $(tail -1 "$RES/live-suite.log")"
  fi
fi
if [ "$ONLY" = "suites" ]; then say "DONE inside (suites only)"; exit $((1 - SUITES_OK)); fi
# A model is attached only to a controller that passed its gate (claim C-SYS-1).
[ "$SUITES_OK" = 1 ] || fail "suites failed, so no model is attached; see results/$STAMP"

# ---- 6. llama.cpp, model, red team ---------------------------------------------
say "STEP 6/6 llama.cpp ($GPU)"
# nvcc jobs use 1-2 GB each; WSL gets half the host's RAM by default.
MEM_GB=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1048576 ))
JOBS=$(( MEM_GB / 2 )); [ "$JOBS" -ge 1 ] || JOBS=1; [ "$JOBS" -le "$(nproc)" ] || JOBS=$(nproc)
if [ ! -x /root/llama.cpp/build/bin/llama-server ]; then
  rm -rf /root/llama.cpp
  git clone -q --depth 1 https://github.com/ggml-org/llama.cpp /root/llama.cpp
  cd /root/llama.cpp
  if [ "$GPU" = cuda ] && cmake -B build -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=120 -DLLAMA_CURL=OFF >/dev/null \
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
EXPECT="$(curl -fsSL "https://huggingface.co/api/models/$HF_REPO/tree/main" | python3 -c '
import json, sys
name = sys.argv[1]
for entry in json.load(sys.stdin):
    if entry.get("path") == name and entry.get("lfs"):
        print(entry["lfs"]["oid"])
' "$HF_FILE")" || true
[ -n "$EXPECT" ] || fail "could not get the SHA-256 of $HF_FILE from huggingface.co/$HF_REPO"
if [ ! -f "$GGUF" ] || [ "$(sha256sum "$GGUF" | cut -d' ' -f1)" != "$EXPECT" ]; then
  say "  downloading $HF_REPO/$HF_FILE"
  curl -fL --retry 5 -C - -o "$GGUF.part" "https://huggingface.co/$HF_REPO/resolve/main/$HF_FILE"
  [ "$(sha256sum "$GGUF.part" | cut -d' ' -f1)" = "$EXPECT" ] || fail "checksum mismatch for $HF_FILE"
  mv "$GGUF.part" "$GGUF"
fi
say "  model verified: $HF_FILE (sha256 $EXPECT)"

# Thinking off: each call is capped at 1024 tokens by the red-team policy.
NGL=0; [ "$GPU" = cuda ] && NGL=99
/root/llama.cpp/build/bin/llama-server -m "$GGUF" --host 127.0.0.1 --port 8080 -ngl "$NGL" -c 32768 \
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
curl -fs http://127.0.0.1:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{
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

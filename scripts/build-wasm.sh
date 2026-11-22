#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${BUILD_STD:-0}" = 1 ]; then
  RUSTC_BOOTSTRAP=1 cargo build -q --locked -p containment-wasm --release --target wasm32-unknown-unknown \
    -Z build-std=core,panic_abort -Z build-std-features=compiler-builtins-mem
else
  rustup target add wasm32-unknown-unknown >/dev/null
  cargo build -q --locked -p containment-wasm --release --target wasm32-unknown-unknown
fi

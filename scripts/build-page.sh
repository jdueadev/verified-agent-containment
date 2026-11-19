#!/usr/bin/env bash
# Builds web/dist/agent-containment-simulator.html. Requires node and npm.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/generated
scripts/build-wasm.sh
wasm=target/wasm32-unknown-unknown/release/containment_wasm.wasm
npx --yes --package binaryen@123.0.0 wasm-opt -Oz --strip-debug --strip-producers "$wasm" -o target/generated/kernel.opt.wasm
npx --yes --package binaryen@123.0.0 wasm2js target/generated/kernel.opt.wasm -o target/generated/kernel.fallback.js
python3 web/build.py

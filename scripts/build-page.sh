#!/usr/bin/env bash
# Builds the browser simulator page, by default over web/dist/agent-containment-simulator.html.
# Give a path to build it somewhere else: scripts/build-page.sh target/page/simulator.html
# Requires cargo, uv and binaryen's wasm-opt and wasm2js at BINARYEN_VERSION in
# ci/pins.env; the factory check image has them.
set -euo pipefail
cd "$(dirname "$0")/.."
want="$(sed -n 's/^BINARYEN_VERSION=//p' ci/pins.env)"
for tool in wasm-opt wasm2js; do
  command -v "$tool" >/dev/null || { echo "build-page: $tool is not installed; binaryen $want is pinned in ci/pins.env" >&2; exit 2; }
  have="$("$tool" --version)"
  [[ "$have" == "$tool version $want "* ]] || { echo "build-page: $tool is '$have', ci/pins.env pins binaryen $want" >&2; exit 2; }
done
mkdir -p target/generated
scripts/build-wasm.sh
wasm=target/wasm32-unknown-unknown/release/containment_wasm.wasm
wasm-opt -Oz --strip-debug --strip-producers "$wasm" -o target/generated/kernel.opt.wasm
wasm2js target/generated/kernel.opt.wasm -o target/generated/kernel.fallback.js
uv run web/build_variants.py
uv run web/build.py "$@"

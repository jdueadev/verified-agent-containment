#!/usr/bin/env bash
# Runs every check that needs neither root nor Lean, and writes what it measures
# to target/verify/. Nothing under results/ is touched.
# Needs cargo, bend, bun, node, java, uv and the TLA+ tools; scripts/factory.sh check
# runs it in the image that has them all.
set -euo pipefail
cd "$(dirname "$0")/.."

jar="${TLA2TOOLS:-/opt/tla/tla2tools.jar}"
for tool in cargo bend bun node java uv; do
  command -v "$tool" >/dev/null || { echo "check: $tool is not installed" >&2; exit 2; }
done
[ -f "$jar" ] || { echo "check: $jar not found; set TLA2TOOLS" >&2; exit 2; }

out=target/verify
mkdir -p "$out" target/generated

uv run tools/invariants_check.py
uv run tools/unwrap_check.py

uv run tools/generate_proof.py --check
(cd formal && bend PROOF.bend --check-only)
bend formal/kernel.bend -o target/generated/kernel.mjs >/dev/null

cargo clippy -q --locked -p containment-kernel -p containment-host --all-targets -- -D warnings
cargo test -q --locked -p containment-kernel
cargo test -q --locked -p containment-host
cargo clippy -q --locked -p containment-host --all-targets --features sabotage -- -D warnings
cargo test -q --locked -p containment-host --features sabotage
cargo build -q --locked -p containment-host

target/debug/containment-lab differential-cases 5000 24301 > target/generated/differential.jsonl
bun tools/differential.mjs target/generated/kernel.mjs target/generated/differential.jsonl | tee "$out/differential.json"
scripts/build-wasm.sh
node tools/wasm_check.mjs target/wasm32-unknown-unknown/release/containment_wasm.wasm target/generated/differential.jsonl | tee "$out/wasm-differential.json"
uv run tools/mutation_check.py target/generated/kernel.mjs "$out/mutation-check.json"
tools/tla_check.sh "$out/tla-check.json"

uv run python -m unittest discover -s tools -p 'test_*.py'
echo "check: all checks passed; results in $out/"

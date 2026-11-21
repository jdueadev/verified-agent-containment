#!/usr/bin/env bash
# Runs every check that does not require root. Requires cargo, bun, node, python3 and bend.
# Pass --no-strict to warn on stale host lab claims instead of failing (used on Draft PRs;
# the evidence-freshness CI job runs claims_check.py --strict as the merge gate).
set -euo pipefail
cd "$(dirname "$0")/.."
STRICT="--strict"
for arg in "$@"; do
  case "$arg" in
    --no-strict) STRICT="" ;;
    *) echo "unknown option: $arg (expected --no-strict)" >&2; exit 2 ;;
  esac
done
# In CI a missing tool fails here, so a green run means every step ran. Locally
# it prints SKIPPED: a partial run is tier T0, never the full gate.
python3 tools/pins_check.py require cargo bend bun node java --file "${TLA2TOOLS:-/opt/tla/tla2tools.jar}"
# Rules that hold on every commit: sabotage is not a default feature, and
# .github/CODEOWNERS is exactly lane C of ci/lanes.toml.
python3 tools/policy_check.py invariants
python3 tools/pins_check.py drift
mkdir -p results target/generated
(cd formal && bend PROOF.bend --check-only)
bend formal/kernel.bend -o target/generated/kernel.mjs >/dev/null
cargo test -q -p containment-kernel
cargo clippy -q -p containment-kernel -p containment-host --all-targets -- -D warnings
cargo test -q -p containment-host
# The sabotage build carries the deliberate defects; it must build, lint and test too.
cargo clippy -q -p containment-host --all-targets --features sabotage -- -D warnings
cargo test -q -p containment-host --features sabotage
cargo build -q -p containment-host
target/debug/containment-lab differential-cases 5000 24301 > target/generated/differential.jsonl
bun tools/differential.mjs target/generated/kernel.mjs target/generated/differential.jsonl | tee results/differential.json
scripts/build-wasm.sh
node tools/wasm_check.mjs target/wasm32-unknown-unknown/release/containment_wasm.wasm target/generated/differential.jsonl | tee results/wasm-differential.json
python3 tools/mutation_check.py target/generated/kernel.mjs results/mutation-check.json
if command -v java >/dev/null && [ -f "${TLA2TOOLS:-/opt/tla/tla2tools.jar}" ]; then tools/tla_check.sh; else echo "SKIPPED: TLC (java or tla2tools.jar missing)" >&2; fi
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/claims_check.py $STRICT

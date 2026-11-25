#!/usr/bin/env bash
# Proves the gateway's admission decision (controller/admission.rs) with Kani,
# for every input in the scope formal/kani/ states, and writes
# target/verify/kani.json.
#   scripts/kani.sh              prove every harness (under a minute)
#   scripts/kani.sh mutants [N]  show each harness failing on the broken variants
#                                in formal/kani/mutants.toml (several minutes)
# Needs uv and Kani at KANI_VERSION in ci/pins.env, installed and set up:
#   cargo install --locked kani-verifier --version <KANI_VERSION> && cargo kani setup
# Kani is not in the factory image, so scripts/check.sh does not run this.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-kani >/dev/null || { echo "kani: cargo-kani is not installed; see the top of $0" >&2; exit 2; }
exec uv run tools/kani_check.py "$@"

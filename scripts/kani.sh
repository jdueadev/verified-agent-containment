#!/usr/bin/env bash
# Proves the gateway's admission decision (controller/admission.rs) and the
# gate's lease handling (controller/gate.rs) with Kani, for every input in the
# scope formal/kani/ states, and writes target/verify/kani.json.
#   scripts/kani.sh              prove every harness (about a minute)
#   scripts/kani.sh mutants [N]  show each harness failing on the broken variants
#                                in formal/kani/mutants.toml (several minutes)
# Needs uv and Kani at KANI_VERSION in ci/pins.env. scripts/factory.sh kani runs
# this in the kani image, which has both; to install Kani yourself, see
# .claude/skills/verify-gateway-admission/SKILL.md. scripts/check.sh does not run this.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-kani >/dev/null || { echo "kani: cargo-kani is not installed; run scripts/factory.sh kani, or see the top of $0" >&2; exit 2; }
exec uv run tools/kani_check.py "$@"

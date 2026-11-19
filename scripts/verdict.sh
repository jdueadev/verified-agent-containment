#!/usr/bin/env bash
# Rechecks the proofs with Bend's Lean kernel. Requires Lean v4.34.0.
set -euo pipefail
cd "$(dirname "$0")/../formal"
ulimit -s unlimited
if [ -z "${BENDTT:-}" ] && [ "${BENDTT_STACK_KB:-}" != "" ]; then
  echo "Set BENDTT to a wrapper when the default kernel stack is too large for this machine." >&2
fi
bend PROOF.bend --verdict

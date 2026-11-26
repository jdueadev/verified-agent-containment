#!/usr/bin/env bash
# Builds the browser simulator from the working tree into target/page/, drives it in
# headless Chromium, and fails unless web/dist/agent-containment-simulator.html is
# byte for byte the page this tree builds. It never writes web/dist/.
# Needs what scripts/build-page.sh needs, node and Chromium (CHROMIUM=/path);
# scripts/factory.sh page runs it in the image that has them all.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in cargo uv node wasm-opt wasm2js; do
  command -v "$tool" >/dev/null || { echo "page-check: $tool is not installed" >&2; exit 2; }
done
[ -x "${CHROMIUM:-}" ] || { echo "page-check: set CHROMIUM to a Chromium binary" >&2; exit 2; }

out=target/page
committed=web/dist/agent-containment-simulator.html
built="$out/agent-containment-simulator.html"
rm -rf "$out"
mkdir -p "$out"

scripts/build-page.sh "$built"
node .claude/skills/run-verified-agent-containment/driver.mjs sim --page "$built" --out "$out/driver"

if ! cmp -s "$built" "$committed"; then
  echo "page-check: $committed is not the page this tree builds ($(wc -c < "$committed") bytes committed, $(wc -c < "$built") built)" >&2
  echo "page-check: if the change is meant, commit the built page: cp $built $committed" >&2
  exit 1
fi
echo "page-check: the page built from this tree passes the simulator flow and matches $committed"

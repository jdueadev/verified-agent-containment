#!/usr/bin/env bash
# ShellCheck over every shell script under scripts/ and tools/, and cargo-deny's
# offline checks of the dependency graph against deny.toml: bans (wildcard
# versions) and sources (crates.io only). Neither needs the network. The
# advisories need it and are in scripts/advisories.sh.
# scripts/check.sh runs this; the tool versions are in ci/pins.env.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in shellcheck cargo-deny; do
  command -v "$tool" >/dev/null || { echo "lint: $tool is not installed" >&2; exit 2; }
done

find scripts tools -name '*.sh' -print0 | sort -z | xargs -0 shellcheck -x
cargo deny --offline --locked check bans sources
echo "lint: shellcheck, cargo-deny bans and sources passed"

#!/usr/bin/env bash
# Checks Cargo.lock against the RustSec advisory database with the policy in
# deny.toml, then shows the check can fail: a scratch crate that locks a crate
# with a known advisory must be refused under the same policy.
#
# Needs the network, for the database and crates.io. It is not part of
# scripts/check.sh: the database changes every day whatever this repository
# does, so a new advisory would fail every unrelated pull request, and the
# checks run with no network. The advisories workflow runs it in the check
# image on a schedule and when the dependencies or the policy change.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo-deny >/dev/null || { echo "advisories: cargo-deny is not installed" >&2; exit 2; }
policy="$PWD/deny.toml"

cargo deny --locked --config "$policy" check advisories

# smallvec 1.6.0 has RUSTSEC-2021-0003, a buffer overflow in insert_many.
canary_crate=smallvec
canary_version=1.6.0
canary_advisory=RUSTSEC-2021-0003
canary="$(mktemp -d)"
trap 'rm -rf "$canary"' EXIT
mkdir "$canary/src"
: > "$canary/src/lib.rs"
cat > "$canary/Cargo.toml" <<EOF
[package]
name = "advisory-canary"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
$canary_crate = "=$canary_version"

[workspace]
EOF
cargo generate-lockfile -q --manifest-path "$canary/Cargo.toml"

code=0
report="$(cargo deny --manifest-path "$canary/Cargo.toml" --config "$policy" check advisories 2>&1)" || code=$?
if [ "$code" = 0 ]; then
  echo "$report" >&2
  echo "advisories: the canary locks $canary_crate $canary_version and cargo-deny passed it" >&2
  exit 1
fi
if ! grep -q "$canary_advisory" <<<"$report"; then
  echo "$report" >&2
  echo "advisories: cargo-deny refused the canary but did not name $canary_advisory" >&2
  exit 1
fi
echo "advisories: Cargo.lock has no advisories; the canary ($canary_crate $canary_version, $canary_advisory) was refused"

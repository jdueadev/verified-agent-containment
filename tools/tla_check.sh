#!/usr/bin/env bash
# Model-checks formal/host/HostModel.tla (claim C-MOD-1) with TLC.
# The v3 configuration must pass; the two known-bad configurations must violate
# ClassifierCannotForceStop, which shows the model can see those bugs, and the
# no-monitor configuration must reach Freeze, which shows the lease clock is live.
# Needs java and tla2tools.jar (TLA2TOOLS, default /opt/tla/tla2tools.jar).
set -euo pipefail
cd "$(dirname "$0")/.."
jar="${TLA2TOOLS:-/opt/tla/tla2tools.jar}"
[ -f "$jar" ] || { echo "tla_check: $jar not found; set TLA2TOOLS" >&2; exit 2; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
spec_sha="$(sha256sum formal/host/HostModel.tla | cut -d' ' -f1)"
results=()
fail=0
for cfg in HostModel HostModelPre1 HostModelLagUncapped HostModelNoMonitor; do
  out="$work/$cfg.out"
  set +e
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -deadlock -config "formal/host/$cfg.cfg" \
    -metadir "$work/meta-$cfg" formal/host/HostModel.tla >"$out" 2>&1
  code=$?
  set -e
  violated="$(grep -oE 'Invariant [A-Za-z]+ is violated' "$out" | awk '{print $2}' | head -1 || true)"
  states="$(grep -oE '[0-9]+ distinct states found' "$out" | tail -1 | awk '{print $1}' || true)"
  if [ "$cfg" = HostModel ]; then expected="pass"; ok=$([ "$code" = 0 ] && echo true || echo false)
  else expected="violates ClassifierCannotForceStop"; ok=$([ "$violated" = ClassifierCannotForceStop ] && echo true || echo false); fi
  [ "$ok" = true ] || { fail=1; echo "tla_check: $cfg did not behave as expected ($expected)" >&2; tail -20 "$out" >&2; }
  printf '%-22s expected: %-38s exit %s, violated: %s, distinct states: %s\n' "$cfg" "$expected" "$code" "${violated:-none}" "${states:-?}"
  results+=("{\"config\":\"$cfg\",\"expected\":\"$expected\",\"exit\":$code,\"violated\":\"${violated}\",\"distinct_states\":${states:-0},\"as_expected\":$ok}")
done
# The passed properties are the ones the good configuration actually checks.
passed_props="$(awk '/^(INVARIANTS|PROPERTIES)/{on=1; next} /^[A-Z]+/{on=0} on && NF {printf "%s\"%s\"", (n++ ? "," : "["), $1} END {print (n ? "]" : "[]")}' formal/host/HostModel.cfg)"
[ "$fail" = 0 ] || passed_props='[]'
mkdir -p results
printf '{"spec":"formal/host/HostModel.tla","sha256":"%s","tlc":"%s","passed":%s,"runs":[%s]}\n' \
  "$spec_sha" "$(basename "$jar")" "$passed_props" "$(IFS=,; echo "${results[*]}")" | python3 -m json.tool > results/tla-check.json
exit "$fail"

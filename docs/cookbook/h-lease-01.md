# What the lab measures: losing the monitor (H-LEASE-01)

The agent runs on a lease it cannot renew itself. If the monitor that renews it
dies, the lease runs out and the sandbox is contained. The kernel's side of
that is proved (K-LEASE-01). This recipe is about the lab: how a root run on a
real Linux machine shows the host actually does it, what it measures, and
where the numbers land. Nothing here runs without root.

## Guarantee

<!-- cookbook:begin claim H-LEASE-01 -->
> **H-LEASE-01** · layer `host` · Generated from [`claims.toml`](../../claims.toml); claims.toml wins. Status and evidence: [`docs/claims.md`](../claims.md).
>
> **Statement:** Losing the monitor or the controller contains the sandbox at lease expiry: egress cut, cgroup frozen, then killed. The stop commits on the first tick at or after the deadline (tested limit 300 ms after monitor loss for a 200 ms lease).
>
> **Falsifier:** Agent keeps authority after the lease, or survives controller death
<!-- cookbook:end claim H-LEASE-01 -->

## What the lab does

The attack harness,
[`crates/containment-host/src/harness.rs`](../../crates/containment-host/src/harness.rs),
starts the real controller, sandbox and gateway as root, runs one scenario,
and judges it from outside. For `monitor_crash` it kills the monitor and then
checks, among others:

- `lease_expiry_contains_sandbox`: the stop commits within 300 ms of the
  monitor's death. That is the claim's tested limit for a 200 ms lease, fixed
  in the harness with headroom (one tick is 5 ms);
- `no_admission_after_commit`: no record at the receiving sink carries a
  gateway admission stamp after the stop committed, and
  `no_upstream_write_after_cut`: none carries a write stamp after egress was
  cut. Both count bytes at the sink, using the gateway's MAC-verified stamps and
  the controller's commit and cut times;
- `nothing_arrives_100ms_after_cut`: the sink, on its own clock, receives
  nothing from 100 ms after the cut;
- `freeze_escalates_to_kill`: the controller's report ends in Kill with no
  surviving process.

`monitor_crash` is one of the five *timed* scenarios (the `TIMED` table in the
harness). A full run repeats each timed scenario 30 times, so the latencies are
distributions, not single samples.

## Watch the control

The `sabotage` build has a defect `ignore_expiry` that pretends the lease never
runs out. The `SABOTAGE` table in the harness pairs it with `monitor_crash`,
which must then fail. A second defect, `no_parent_death_signal`, lets the
sandbox outlive a crashed controller, and `controller_crash` must catch it.

The root lab run committed in
[`results/wsl2/lab-cd7172f/attack-suite.json`](../../results/wsl2/lab-cd7172f/attack-suite.json)
records `ignore_expiry` as detected, with six failed checks including
`lease_expiry_contains_sandbox` and `freeze_escalates_to_kill`. It records
`no_parent_death_signal` as detected through `sandbox_stops`. The same file
holds the measured latencies under `metrics`, each pooled across all honest
runs: `monitor_loss_to_commit_ms` there combines `monitor_crash`,
`gateway_flood` and `forged_renewal`, not `monitor_crash` alone. That is
recorded output from a WSL2 run at commit `cd7172f`, not a live measurement.
The kernel, hardware and binary hashes are in
[`environment.txt`](../../results/wsl2/lab-cd7172f/environment.txt) next to
it. Read these files, and the claim's row in [`docs/claims.md`](../claims.md),
at the commit you are looking at.

## Where the evidence lands

- A root lab run writes `results/attack-suite.json` and
  `results/live-suite.json`. On a push to `main`,
  [`.github/workflows/lab.yaml`](../../.github/workflows/lab.yaml) records a
  CI run under `results/ci/lab-<sha>/` with `provenance.json`. A Windows lab
  run is committed by the maintainer under `results/wsl2/`. An agent does not
  write these.
- [`tools/claims_check.py`](../../tools/claims_check.py) then checks that the
  cited scenarios passed and the cited controls were caught in the recorded
  results it reads: the top-level `results/attack-suite.json` and
  `results/live-suite.json`, and the newest CI lab run. It marks the claim
  stale when a file the claim lists changes after the recorded commit.
  `--strict` also requires the honest runs and the controls to come from two
  different builds, and a full unwaived timed run. CI-10, in either mode,
  requires every tracked `results/ci/lab-<sha>/` that is not on the `legacy`
  list in [`ci/lab-attestation.toml`](../../ci/lab-attestation.toml) to carry
  a GitHub OIDC token binding every committed byte.
- The rendered result is the claim's row in [`docs/claims.md`](../claims.md).

## Reproduce

The lab needs root and changes cgroups, so run it only in a disposable Linux
or WSL2 machine (LAB-THROWAWAY in [`AGENTS.md`](../../AGENTS.md)).
[`docs/verification.md`](../verification.md) has the
commands, and [`scripts/lab/README.md`](../../scripts/lab/README.md) the
one-click Windows route that creates and deletes a throwaway WSL2 distro.

## What this does not prove

- **One machine, one kernel.** The recorded run is one WSL2 kernel. Other
  kernels and cgroup setups are covered only where another platform entry says
  so.
- **The scenarios are scripted adversaries.** They are written to attack the
  mechanism, but they are not a model that has learned to evade it.
- **A control is caught if any check fails.** The harness counts a defect as
  detected when its scenario fails at all, and records which checks failed.
- **The timing bound is the tested one.** The claim's 300 ms limit is for a
  200 ms lease on that machine, and says nothing about a heavily loaded host.

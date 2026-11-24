# Unconfirmed means stopped (H-ACT-01)

One host guarantee, the code that enforces it, the deliberate defects that show
the lab would notice if it stopped, and where the evidence comes from. This is
a host recipe: nothing on this page runs in your browser or without root.

## Guarantee

<!-- cookbook:begin claim H-ACT-01 -->
> **H-ACT-01** · layer `host` · Generated from [`claims.toml`](../../claims.toml); claims.toml wins. Status and evidence: [`docs/claims.md`](../claims.md).
>
> **Statement:** Actuator failures are read back and re-driven; enforcement that cannot be confirmed, or a stalled enforcer, ends in fail-stop.
>
> **Falsifier:** A dead actuator or stalled enforcer with the agent still live
<!-- cookbook:end claim H-ACT-01 -->

The kernel decides *what* should happen (for example: revoke secrets, block
egress, freeze the processes). The host has to make it happen, and an actuator
can fail: a write to the cgroup can fail, or a freeze may not take. The rule is
INV-7 in [`AGENTS.md`](../../AGENTS.md): enforcement that cannot be read back
ends in fail-stop, never in "assume it worked".

## Where it is enforced

Both halves live in
[`crates/containment-host/src/controller.rs`](../../crates/containment-host/src/controller.rs);
the cgroup actuators it reads back live in
[`controller/enforcer.rs`](../../crates/containment-host/src/controller/enforcer.rs).
Read them there; this page does not copy host code.

- **Read back and re-drive.** The `enforcer` method of the controller's
  shared state takes each queued action, performs it, and records whether it
  was confirmed. Two paths retry a failure. A failed `RecreateSandbox` or
  `ThawProcesses` goes back to the front of the queue. Any other failed action
  is not requeued: the enforcer moves on to the next one, and when the queue is
  empty its reconcile step (`drive`) re-applies the frozen or killed state the
  kernel asked for. So a Kill plan whose freeze fails goes on to the kill, and
  the frozen state is driven again afterwards. If enforcement stays unconfirmed
  for longer than `ACTUATOR_FAIL_STOP`, the controller calls
  `fail_stop("enforcement could not be confirmed")`.
- **Watch the enforcer itself.** The tick thread started in the controller's
  run loop checks the enforcer's heartbeat on every tick. If the enforcer has
  not beaten for `ENFORCER_STALL_NS`, it calls `fail_stop("enforcer stalled")`.
  A stalled enforcer cannot be trusted to contain anything, so the controller
  stops instead of waiting for it.

A fail-stop records why, kills the cgroup if it can do so without waiting for
the stuck enforcer, and exits with status 70; the exit also fires the
sandbox's parent-death signal. The lab checks that from outside the
controller: the exit status, an empty cgroup with no stray processes, and no
upstream write recorded at the receiving sink after the controller exited.
The sink is read after a short, fixed wait, so this covers writes that reach
the sink in that window, not every kind of write forever.

## Watch the control

All three of the claim's scenarios run on the default build, where they must
pass. Then a build with the `sabotage` feature runs each control: one defect
switched on, with the one scenario that must catch it, and that run must fail.
The defects are the registry in
[`controller/weakness.rs`](../../crates/containment-host/src/controller/weakness.rs),
and the `SABOTAGE` table in
[`harness.rs`](../../crates/containment-host/src/harness.rs) pairs each one
with the scenario that must catch it.

| Defect (sabotage build only) | What it breaks | Caught by scenario |
| --- | --- | --- |
| `ignore_actuator_failure` | never lets a failed or unconfirmed action count toward the fail-stop timer, so the controller keeps running with enforcement unconfirmed | `actuator_dead` |
| `no_enforcer_watchdog` | skips the enforcer heartbeat check | `enforcer_stall` |

`actuator_retry` is the honest scenario where a freeze fails twice and then
works: it must end frozen with at least one retry recorded. It runs only on
the default build.

The root lab run committed in
[`results/wsl2/lab-cd7172f/attack-suite.json`](../../results/wsl2/lab-cd7172f/attack-suite.json)
records both controls as `"detected": true`, each with the failed checks
`controller_fail_stops`, `sandbox_stops` and
`no_writes_after_controller_exit`. That is recorded lab output from commit
`cd7172f`, not a live run. Read the file, and the claim's row in
[`docs/claims.md`](../claims.md), at the commit you are looking at.

## Reproduce

The scenarios need root and change cgroups, so they run only in a throwaway
Linux or WSL2 machine (INV-11). There are no commands on this page on purpose;
[`docs/verification.md`](../verification.md) has the lab instructions, and
[`scripts/lab/README.md`](../../scripts/lab/README.md) the one-click Windows
route. The maintainer runs the lab; its output lands under `results/` in a
follow-up pull request.

## What this does not prove

- **The failures are simulated.** The controller under test injects them
  itself, keyed on the scenario name: freeze and kill writes that report
  failure without touching the cgroup, and an enforcer thread that parks itself
  after 150 ms. A real refusal by the kernel is covered only as far as it looks
  the same from the read-back.
- **A control is caught if any check fails.** The harness counts a defect as
  detected when its scenario fails at all, and records which checks failed. The
  failed checks above are the ones you would expect, but the rule does not
  require a particular one.
- **The order of actions is a kernel claim.** That every stop revokes secrets
  and blocks egress before it freezes or kills is K-PLAN-01, proved on the Bend
  model. This claim is about the host carrying out whatever plan it is given.
- **Host code can fool the lab.** That is why host code is lane C
  ([`docs/decisions/0004-host-code-in-lane-c.md`](../decisions/0004-host-code-in-lane-c.md)).
  The maintainer's approval is required for an author who is not on the
  `trusted` list in `ci/lanes.toml`, and for every pull request from a fork
  ([AGENTS.md](../../AGENTS.md)).

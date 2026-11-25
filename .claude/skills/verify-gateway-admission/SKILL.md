---
name: verify-gateway-admission
description: Prove with Kani that the gateway's admission decision and the gate's lease handling keep their promises for every input - decide, Limit::admits and Cost::settled in crates/containment-host/src/controller/admission.rs, and Gate::admit, Lease::start and Charge::settle in controller/gate.rs. Use when a change touches those files, the kernel's authorize, Control, Mode or Level, or formal/kani/; before pushing such a change; or when scripts/kani.sh fails.
---

# Verify the gateway's admission decision (Kani)

Every attempt an agent makes through the gateway (a model call, a live web request, lab
egress, a request for the lab secret's handle) is decided by `decide` in
`crates/containment-host/src/controller/admission.rs` and charged to a lease by
`Gate::admit` in `crates/containment-host/src/controller/gate.rs`. The harnesses in
`formal/kani/` prove ten promises about that code for every input in the scope below, not
only the tested ones. `scripts/kani.sh` runs them in about a minute.

All paths are relative to the repository root. AGENTS.md is the rulebook and wins over
this file: never weaken or delete a harness, a promise or a mutant to make a change pass.

## What is proved

Harnesses for `decide`, `Limit::admits` and `Cost::settled` are in
`formal/kani/admission_proofs.rs` (Kani names them `admission_proofs::<name>`). Those for
the gate are in `formal/kani/gate_proofs.rs` (`controller::gate::proofs::<name>`).

| Harness | Promise | Harm if broken |
|---|---|---|
| `an_ungranted_destination_is_never_allowed` | An attempt whose destination the policy does not grant is never allowed. | An agent reaches a destination nobody approved. |
| `the_mode_binds` | Nothing is allowed in Hold, Freeze or Kill, once the lease deadline is reached (by the later of the gate's time and the kernel's clock), or while authority is not ready; in Restrict only baseline egress without the secret is allowed. | A contained agent keeps acting. |
| `the_budget_holds` | An allowed attempt's new total is what was used plus its cost and never exceeds any limit of its grant; the budget refuses only an attempt that would take some count over its limit. | A budget that can be overspent, or that refuses, and restricts, work it has room for. |
| `the_canary_rule_fires_first_and_raises` | An attempt carrying the canary is refused by the canary step whatever else holds, raising Restrict for a model on this host and Freeze otherwise; nothing else is refused as the canary. | A canary leaves quietly, or leaves the host and only restricts. |
| `a_read_grant_never_allows_a_write` | A web request other than GET or HEAD is allowed only by a grant that allows writes. | A read grant is used to change something. |
| `each_refusal_names_the_step_that_refused` | Each refusal names the first step that refused (canary, policy, kernel, budget) and raises what that step raises; an attempt every step passes is allowed. | `Shared::admit` restricts on the third policy refusal and on any budget refusal, so a wrong step lets an agent probe ungranted destinations uncounted or restricts it for nothing. |
| `admits_never_wraps` | `Limit::admits` gives a total only when every limited count stays within its limit, and each count is the spend plus the cost, saturating only where there is no limit. | A wrapped count reads as almost nothing spent, and the budget admits again. |
| `settling_never_wraps` | `Cost::settled` never panics, never comes to less than what was really spent, and is exact whenever the spend holds the reservation and the sum fits. | A settled count wraps to almost nothing, and the budget is spent again. |
| `a_refusal_never_charges_and_an_admission_charges_its_lease` | `Gate::admit` refuses exactly what `decide` refuses, with the same step and rule, and leaves the lease's spending as it was; it charges an allowed attempt `decide`'s new total, in the lease of the latest reset the kernel accepted, and the charge records that lease. | Refused work drains a budget, or an attempt is decided and charged against a lease the kernel already replaced. |
| `a_charge_settles_only_into_the_lease_that_made_it` | Once a later reset's lease has started, settling an earlier charge changes nothing; in its own lease, settling replaces the reservation with the real cost on its own account; a lease number never goes back. | Work from before a reset spends, or refunds, the budget the reset renewed, or an old reset's number wipes a lease's spending. |

Kani also checks every panic and every arithmetic operation the harnesses reach, so the
harnesses prove too that no input makes `decide`, `Limit::admits` or `Cost::settled` panic
or overflow, nor `Gate::admit` or `Charge::settle` within the gate harnesses' scope below.

### Scope, bounds and assumptions

- **Inputs of `decide` are all free**: any grant or none, any limits, every mode, every
  kind with every flag, the canary or not, ready or not, and any value for the deadline,
  clock, reset counter, time, spend and cost (each a full `u64`). There is no `kani::assume`.
- **The kernel is the real one.** `decide` calls the kernel's `authorize`, compiled from
  `crates/containment-kernel/src/lib.rs`. Where a harness needs the kernel's rule to state
  a promise, it restates it in `kernel_admits` (admission_proofs.rs), from the laws in
  `formal/LAWS.bend` and from `authorize`; it never calls the code it checks.
- **Gate harnesses: the model's account and the unmetered one only.** A host's account
  lives in `BTreeMap<String, Cost>`, and CBMC runs out of memory in the map's code (measured
  when this was written: a 570,000-step formula that ran out of a 3 GB cap). Per-host
  accounts are left to the unit tests in gate.rs.
- **`Gate::open` is stubbed** (it records the slot in BTreeMaps and reads the boot clock
  through libc), and the gate and the permit are never dropped (`std::mem::forget`, because
  the BTreeMap drop code exhausts CBMC's memory). Nothing about slots or drops is proved.
- **One reset between admission and settling.** The settle harness starts one lease with an
  arbitrary number before settling. The lease a gate harness starts from has a free number
  and spend too, including a number past the kernel's reset counter, which the product never
  reaches; that only widens what is proved.
- **Default build only.** Kani builds without the `sabotage` feature, so `Gate::sabotaged`
  is the identity, as in every binary that contains a real agent.
- **Loops are unwound at most 3 or 4 times**, with Kani's unwinding assertions on: a
  reachable loop that needs more fails the proof instead of passing it silently.
- **Not covered**: what callers pass in (`controller/gateway.rs` builds each `Attempt`'s
  cost and each `Grant` from the policy); the policy-refusal counter in `Shared::admit`;
  the reset signature (Kani does not support the inline assembly in ed25519's CPU feature
  detection); concurrency (Kani runs atomics as sequential steps; the control lock order is
  tested by `concurrent_model_calls_cannot_overspend` in gate.rs and modelled in
  `formal/host/HostModel.tla`). Settling records what the model reports, so a lease can
  end above its token limit when a call used more than it reserved; the next call is then
  refused. That is the design, and no harness claims otherwise.

## Does my change touch the verified code?

Coverage record. Each harness runs exactly this product code:

| Harness file | Product files | Functions |
|---|---|---|
| `formal/kani/admission_proofs.rs` | `crates/containment-host/src/controller/admission.rs` | `decide`, `kernel_allows`, `Limit::admits`, `within`, `Cost::settled` |
| | `crates/containment-kernel/src/lib.rs` | `authorize`, `effective_time` |
| `formal/kani/gate_proofs.rs` | `crates/containment-host/src/controller/gate.rs` | `Gate::new`, `Gate::admit`, `Gate::sabotaged`, `Lease::start`, `Lease::spent`, `Lease::set`, `Charge::settle` (`Gate::open` stubbed) |
| | `crates/containment-host/src/controller/admission.rs` | `decide` and everything it calls, `Cost::settled` |
| | `crates/containment-host/src/controller/weakness.rs`, `controller.rs` | `Weakness` in the default build, `lock` |
| | `crates/containment-kernel/src/lib.rs` | `authorize`, `effective_time` |

**Sync commit: `38c1cc5c45ab523e057a4482c5de1b5b8c75d8d4`** ("Catch a gate mutant in a
state the gate can reach, and pin Kani's bundles"). At that commit the harnesses were confirmed to describe the code
above, and `scripts/kani.sh` and `scripts/kani.sh mutants` both passed. If the branch was
rebased after this was written, the hash may name nothing: use the commit with that subject
instead. To see whether the covered code has changed since:

```bash
git diff --stat 38c1cc5c45ab523e057a4482c5de1b5b8c75d8d4 -- crates/containment-host/src/controller/admission.rs \
  crates/containment-host/src/controller/gate.rs crates/containment-host/src/controller/weakness.rs \
  crates/containment-host/src/controller.rs crates/containment-kernel/src/lib.rs formal/kani
```

If your diff, or that one, touches a function in the table, run the check. A change only in
`controller.rs` outside `lock`, or in a caller such as `gateway.rs`, does not change what is
proved, but it can change what the promises mean in practice (an `Attempt` built with a
zero cost passes any budget); say so in the pull request if it does.

Move the sync commit forward only after you have read the diff since it, confirmed the
harnesses and the restated rules still describe the code, and seen both commands pass at
the new commit.

## Run it

Install Kani once, at the version in `ci/pins.env` (`KANI_VERSION`). A plain `cargo kani
setup` downloads Kani's bundle unchecked, so fetch the bundle yourself and check it against
the sum in `ci/pins.env` (on arm64, `aarch64-unknown-linux-gnu` and
`FACTORY_KANI_SHA256_ARM64`). The setup unpacks it into `~/.kani` (or `KANI_HOME`) and
installs the nightly toolchain Kani is built for through rustup:

```bash
source <(grep -E '^(KANI_VERSION|FACTORY_KANI_SHA256_AMD64)=' ci/pins.env)
curl -fsSL -o /tmp/kani.tar.gz "https://github.com/model-checking/kani/releases/download/kani-$KANI_VERSION/kani-$KANI_VERSION-x86_64-unknown-linux-gnu.tar.gz"
echo "$FACTORY_KANI_SHA256_AMD64  /tmp/kani.tar.gz" | sha256sum --check --strict
cargo install --locked kani-verifier --version "$KANI_VERSION"
cargo kani setup --use-local-bundle /tmp/kani.tar.gz
```

Any `cargo kani` command run before setup does the plain setup on its own, so run these
first.

Then, from the repository root:

```bash
scripts/kani.sh
```

It prints one line per harness and ends with `kani: all harnesses verified`; the exit code is
0 only then. It writes `target/verify/kani.json` (the versions, the files covered with one
sha256 over them, each harness's result) and the full Kani output to
`target/verify/kani/admission.log` and `target/verify/kani/gate.log`. Measured when this was
written, on 4 cores: 40 seconds with the build cached, 60 seconds with `target/kani` empty
(Kani builds the host crate). Before running anything it checks `formal/kani/mutants.toml`
against the code, and stops if a mutant no longer fits or a harness has none.

To see every harness fail on the broken variants it guards (do this when you change a
harness, a restated rule or a mutant):

```bash
scripts/kani.sh mutants            # all of them, several minutes
scripts/kani.sh mutants canary     # those whose name contains "canary"
```

Each mutant is applied to a scratch copy under `target/kani-mutants/`, never to your
checkout. A line reads `caught` when the named harness failed with the counterexample shown,
`MISSED` when it passed or the mutant did not compile. The report is
`target/verify/kani-mutants.json`.

Kani is not in the factory image yet, so `scripts/check.sh` and the required `check`
workflow do not run it. Run it yourself before pushing a change to the covered code.

## When it fails: a real bug or a modelling error?

1. **Read the line.** It names the harness and the assertion that failed. Each assertion
   message names the clause of the promise that broke, such as `allowed while authority is
   not ready` or `a refusal charged`. `attempt to add with overflow` and the like mean the
   product code itself overflowed.
2. **Get the inputs Kani found.** For an admission harness:

   ```bash
   cd formal/kani && cargo kani --harness admission_proofs::the_mode_binds --exact -Z concrete-playback --concrete-playback=print
   ```

   For a gate harness, from the root: `cargo kani -p containment-host -Z stubbing -Z
   concrete-playback --concrete-playback=print --harness controller::gate::proofs::<name> --exact`.
   Kani prints a test with one value per `kani::any()` call, in the order the harness makes
   them, each with a comment giving the value. Map them onto the harness's input builders
   (`any_case` in admission_proofs.rs, `admits_and_charges` and `settles_in_its_lease` in
   gate_proofs.rs): an `Option` is a bool (1 is `Some`) followed by its value's fields; a
   `u8` that picks a variant counts in the order the builder's `match` lists them, any
   larger number being the last one; struct fields come in the order the literal names
   them. The gate harnesses run their body for the model's account first, so the values
   for the unmetered account, if any, come after. Then write the counterexample as steps in
   the code's words. For `any_case` the order is: grant (bool; write, baseline; then
   requests, bytes, tokens limits, each a bool and a u64), mode, deadline, clock, reset
   counter, now, ready, used (requests, bytes, tokens), kind (and its flag), cost, canary.
   Read that way, `1,1,1,1,MAX,1,MAX,1,MAX,1,...,255,...,0` says: "in Restrict, with
   authority ready and the lease live, a `LabSecret` request on a baseline write grant with
   room in its budget is allowed".
3. **Decide which it is.**
   - **A real bug**: the inputs are ones the product can be given, and the product breaks
     the promise. Confirm by writing the same call as a `#[test]` in the `tests` module of
     admission.rs or gate.rs and running `cargo test -q --locked -p containment-host`. Fix
     the product code, or, if you meant to change the promise, see the next section. Report
     the counterexample in the pull request either way.
   - **A modelling error**: the harness is wrong, not the code. Either a restated rule
     (`kernel_admits`, `covering`, `within`, `charged_exactly` in admission_proofs.rs, or
     the expected lease in gate_proofs.rs) no longer matches what the kernel or the gate is
     meant to do, or a harness builds an input the product can never be given. Show that
     from the code (the laws in `formal/LAWS.bend`, or the caller that rules the input out),
     then fix the harness and say why in the pull request. Narrowing an input with
     `kani::assume` needs that evidence in a comment beside it.
   - **A tool limit**: `CBMC appears to have run out of memory`, `UNDETERMINED`, or `A Rust
     construct that is not currently supported by Kani was found to be reachable`. This says
     nothing about the product. It usually means new code pulled the harness into a
     BTreeMap, a String compare or a libc call; see the scope notes above for how the
     existing harnesses keep out of them.
   - **A vacuous proof**: the line lists an assertion Kani could never reach. The harness
     can no longer reach the case it checks, so it proves nothing; find which input stopped
     reaching it.

   The gate harness `a_refusal_never_charges_and_an_admission_charges_its_lease` checks the
   gate against `decide`, so it keeps passing when `decide` itself is broken. A broken
   decision shows up in the admission harnesses instead.

## When the change is intended

- **A new `Kind` or `Mode` variant, or a new field** in `Cost`, `Limit`, `Grant`,
  `Attempt` or `Control`, stops the harnesses compiling on purpose: the input builders name
  every variant and every field. Add it to the builders in both harness files, then decide
  what each promise says about it and change the restated rules to match.
- **A changed rule** (a new step or `Layer`, a different order, a new level a refusal
  raises): change the promise's doc comment, its assertion and the restated rule together,
  and keep the harm sentence true. A promise that becomes weaker is a change to what the containment
  guarantees; say so plainly in the pull request.
- **Mutants**: when a mutant's `old` no longer occurs in the code, the check stops with
  `mutants.toml is out of step with the code`. Rewrite that mutant as the smallest edit that
  breaks the same promise in the new code, in a state the product can reach: the harnesses'
  inputs are free, so a mutant can be caught only in a state that never happens (a lease
  numbered past the kernel's reset counter), and that shows nothing. Every harness must
  keep at least one mutant. A new harness needs a new mutant, and `scripts/kani.sh mutants
  <name>` must show it caught.
- **The admission crate** in `formal/kani/` is its own Cargo workspace. It compiles the
  product's own admission.rs through `#[path]` in `formal/kani/lib.rs`; it holds no copy. If
  admission.rs gains a dependency other than the kernel, add it to `formal/kani/Cargo.toml`
  and refresh `formal/kani/Cargo.lock` with `cargo generate-lockfile` there.

## Gotchas

- `cargo kani` has no `--locked`; the lock files are only read.
- The gate harnesses are compiled into the host crate through
  `#[cfg(kani)] #[path = "../../../../formal/kani/gate_proofs.rs"] mod proofs;` in gate.rs,
  and the root `Cargo.toml` declares `cfg(kani)` so clippy's `-D warnings` stays quiet.
- Each Kani run is capped at 6 GB of address space (`KANI_MEMORY_MB` changes it), so a
  harness that blows up fails on its own instead of the machine's OOM killer stopping
  something else.
- Do not run several `scripts/kani.sh` at once on a shared machine. CBMC is single-threaded
  per harness, but compiling the host crate under Kani is not.

# Verified agent containment

Research prototype for a sandbox controller. It removes an agent's authority when the agent's lease stops being renewed, when a hard rule fires, or when enforcement cannot be confirmed.

The trust anchor is a small, pure decision kernel. A local classifier can add warning signals but can only tighten. At most, a classifier verdict can move the agent to Hold, which has no timer. A verdict cannot renew a lease, grant access, start the Kill timer or cause Kill.

That cap covers classifier verdicts directly. Classifier liveness is handled the same way: a stalled or overflowing classifier reaches the kernel as a classifier signal (Restrict on lag over 500 ms, Hold after a blind window), never by blocking lease renewal (claim H-S1-01). System One now runs as a separate confined process (own uid and cgroup, rlimits, empty network namespace, the agent's seccomp filter plus no sockets, fork or signals; its cgroup limits fail closed), reached only through an inherited trace pipe and verdict socket; every verdict becomes a classifier signal whatever it says, and verdicts that rest only on agent text stop at Restrict. Containment of System One as a whole is claim C-SYS-1, now tested; see [`docs/design-spec.md`](docs/design-spec.md) section 5.

The v3 design is in [`docs/design-spec.md`](docs/design-spec.md). Every guarantee, its evidence and its falsifier is a row in [`claims.toml`](claims.toml), rendered as [`docs/claims.md`](docs/claims.md) and checked by `tools/claims_check.py`. [`docs/design-explainer.html`](docs/design-explainer.html) is a plain-English companion to the spec, with key terms, small interactive demos and reading links for each section; open it in a browser.

## Result

| Evidence | Result | What it establishes |
|---|---:|---|
| Bend laws | 36 proved | Properties of `formal/kernel.bend` |
| Lean-backed Bend verdict | `ALL PROOFS CHECK` | The proof terms pass the BendTT kernel. Hashes are in `results/formal-verdict.json` |
| Unsafe Bend kernels | 46/46 rejected, 46/46 with a witness | Each mutant type-checks, fails the proofs, and `tools/law_audit.mjs` finds an input on which it breaks a stated law |
| Original kernel under the law audit | 0 violations in 200,000 inputs | The executable law statements agree with the proofs |
| Unsafe Rust kernels | 19/19 diverge from the Bend model | The differential test detects these faults |
| Rust vs Bend, Rust vs WebAssembly | 77,364 transitions each, 0 mismatches | Generated-test agreement, including stale timestamps and resets. Not a proof |
| Linux attack runs | 176/176 passed | 31 scenarios; 5 timed scenarios repeated 30 times |
| Under CPU load | 68/68 passed | Same suite at `--repeat 10`, with two busy loops on a 2-core VM |
| Weakened controllers | 29/29 caught | Each removes one protection; the suite must fail |
| Bytes admitted after a stop committed | 0 | Across 155 measured stops |
| Bytes written upstream after the cut | 0 | Same runs. Gateway stamps are HMAC-authenticated at the sink |
| Browser page | 10/10 sabotaged kernels caught | Checked with native WebAssembly and with the JavaScript fallback |
| TLA+ host model | `ClassifierCannotForceStop` holds | 2,863,520 states (one sandbox, 12 ticks, renewal as its own action, no resets). Required counterexamples are found for the classifier in the health gate, an uncapped lag signal, and a dead monitor. `tools/tla_check.sh` |

Timing on Linux 6.18 in a 2-core VM, p50 / p95 / max:
- Stop committed to egress cut: 0.12 / 1.66 / 24.21 ms.
- Committed to cgroup frozen: 0.41 / 2.63 / 24.30 ms.
- Committed to cgroup empty: 0.94 / 2.41 / 2.65 ms.

Maxima vary between runs on this shared VM because the enforcer thread can be descheduled; one run of an earlier build of this change had a `gateway_flood` stop at 93 ms. Every measured stop, including that one, recorded 0 bytes admitted after commit and 0 written after the cut.

Monitor loss to containment stayed under the 200 ms lease, with a maximum of 198.6 ms. Under CPU load, the frozen p95 rose to 9.6 ms and the maximum to 59.8 ms.

**Limits waiver.** This run used `--allow-missing-limits`. The VM has a hybrid cgroup v1/v2 layout, so the pids, memory and CPU controllers are not available in the v2 tree. The result records the waiver. Without it, `benign` fails when those limits are not in force.

## Architecture

```text
monitor renewals (SO_PEERCRED, health-gated), hard rules, classifier signal, signed reset
                  |
                  v
          containment kernel          pure (state, event) -> (state, ordered actions)
                  |                   mode, deadline, clock, reset counter
                  v
controller: short commit lock -> ordered action queue -> enforcer thread
            gateway (admission under the commit lock), credential broker,
            upstream registry, cgroup actuators with read-back and re-drive,
            watchdog and fail-stop
                  |
                  v
sandbox: root init as PID 1 (holds the parent-death signal), agent as PID 2
         pivot_root to a minimal read-only root, per-generation UID, seccomp,
         PID/mount/IPC/UTS/network/cgroup namespaces, cgroup v2 generation
```

Modes run from least to most contained: Run, Restrict, Hold, Freeze, Kill.
- **Hold** is the classifier's ceiling. It stops the agent and has no deadline, so a fooled classifier cannot turn a pause into Kill. Lease loss in Hold also stays in Hold. This is intentional: a person decides.
- **Freeze** has a fixed grace deadline, then Kill.
- **Signed reset** is the only way back down. It is bound to the run, a fresh counter, the mode it was signed for and an expiry time. Authority returns only after the recovery actions complete.

## What the laws cover

- **Lease and time:** fail closed at the deadline. Only renewal or an accepted reset extends a lease, within the maximum. The kernel clock is exactly the event's effective time, and stale timestamps cannot move it back.
- **Monotonicity:** without an accepted reset, no event and no unsigned sequence lowers containment. The reset counter does not change, and no plan thaws, rebuilds or restores authority.
- **Classifier:** it cannot cause Kill and enters Hold at most. Hold cannot escalate itself over any passive trace.
- **Plans:** every stop revokes secrets and blocks egress before freezing or killing. Entering Kill emits KillProcesses, and entering Restrict revokes and narrows. Freeze gets exactly one grace period and escalates when it ends.
- **Reset:** signature, fresh counter, matching mode and expiry are all required. A counter is consumed and cannot be replayed. The new lease is bounded, and the recovery plan is exact: Kill is rebuilt, never thawed.
- **Access:** access requires a grant. An expired lease or a stopped mode denies it, and Restrict denies secrets and non-baseline egress.

## Commands

Requires Rust, Bun, Node.js, Python 3, and the pinned Bend checkout.

```bash
git clone https://github.com/bendlang/bend /tmp/bend
git -C /tmp/bend checkout 0e2f38f
printf '#!/bin/sh\nexec bun /tmp/bend/bend2/main.ts "$@"\n' | sudo tee /usr/local/bin/bend >/dev/null
sudo chmod +x /usr/local/bin/bend
scripts/check.sh          # proofs, tests, differential, wasm, mutation (with law witnesses)
scripts/verdict.sh        # Lean recheck; needs Lean v4.34.0, or BENDTT set to a built kernel
```

Linux or WSL2 attack suite, run as root in a disposable distribution:

```bash
export CARGO_TARGET_DIR=/tmp/verified-agent-containment-target
cargo build --release -p containment-host
sudo "$CARGO_TARGET_DIR/release/containment-lab" attack-suite --repeat 30 --out results/attack-suite-local.json
# add --allow-missing-limits only if the host has no cgroup v2 pids/memory/cpu controllers; it is recorded
```

`scripts/run-wsl2.sh` wraps the same steps with kernel and cgroup checks.

Showcase:

```bash
scripts/build-page.sh     # also compiles the 10 sabotaged kernels from tools/kernel_mutants.py
python3 tools/page_check.py web/dist/agent-containment-simulator.html
```

If `rustup target add wasm32-unknown-unknown` is unavailable but `rust-src` is installed, use `BUILD_STD=1`.

## Run a local agent

The owned harness (`agent_loop.rs`) runs inside the sandbox and drives any OpenAI-compatible model server: Ollama, llama.cpp (`llama-server --jinja`), LM Studio or vLLM. Everything it does goes through the gateway:
- `infer` sends the conversation to the model. It counts as baseline egress, so it still works in Restrict, and it draws on a per-lease token budget.
- `http` is a typed request. The gateway is the HTTP and TLS client. It checks the origin and method against the policy, adds the credential for that origin (https or loopback only), redacts credential values from responses, enforces per-lease budgets, and refuses names that resolve to internal addresses (loopback, private, link-local, CGNAT). To use a model server or host on your LAN, put its IP literal in the policy.
- Files live in `/workspace`, which is a fresh copy for every sandbox generation.

```bash
cargo build --release -p containment-host
# Edit examples/live/policy.toml: model endpoint and name, allowed hosts, budgets.
sudo FIXTURE_TOKEN=dummy target/release/containment-lab live \
  --policy examples/live/policy.toml \
  --task "Read notes.txt and write a one-line summary to summary.md"
```

The command streams each model step and tool call, prints every mode change, and saves `report.json` and `transcript.jsonl` under `results/live/`. Add `--allow-missing-limits` only on hosts without delegated cgroup controllers; the report records it.

While a run is going, in another terminal:

```bash
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... status
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... reset hold   # or restrict, freeze, kill
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... stop
```

A run ends on its own when the agent finishes in Run or Restrict. After Hold, Freeze or Kill it waits for a reset or a stop, up to `run.max_seconds` (default 900 s), and then tears down (failing closed). A reset from Kill rebuilds the sandbox with a fresh workspace.

`containment-lab live-suite` checks all of this end to end with a scripted model and local fixture servers. It tests credential scoping, the canary, unlisted hosts, writes to read hosts, request and token budgets, the cut on stop, and the workspace rebuild. Each check has a sabotaged controller that must fail it: 9/9 runs pass and 6/6 sabotaged controllers are caught (`results/live-suite.json`). The checks look at what reached the upstream servers, including the model server, not at what the agent reports.

Two limits are specific to live runs:
- A live reset is signed with a per-run key file that only root can read, not a hardware key, because reset v3 is not built yet. It proves that root on this host approved the reset, not that Jon did.
- Writes within budget to allowed hosts are not contained (L-OPS-01). Choose write hosts and budgets with that in mind.

## Review history

Fable 5.2 reviewed the design adversarially in three rounds:
1. Ten findings: vacuous laws, classifier-to-Kill paths, actuator failures that were ignored, gateway leaks and lock coupling, a missing minimal root and seccomp, liveness-only leases, dropped classifier input, stale time, reset on the agent gateway, and overstated metrics.
2. Eight findings, three of them high severity: the agent could clear its parent-death signal, authority returned before recovery finished, and sink stamps could be forged. Seven mutants survived the laws.
3. One medium race (stale RestoreAuthority), two oracles that could pass vacuously, and a fail-stop that could block. All fixed. The checks for each fix are `double_reset`, the 200 ms observation window, the counting of partial records, and `try_lock`.

## Scope limits

- **Proofs:** they cover the Bend model. The Rust kernel is checked against it by generated traces. Values in those traces stay below 2^53. Rust saturates at u64 where Bend's naturals do not, which is tighter, not looser.
- **Law audit:** `tools/law_audit.mjs` restates 35 of the 36 laws in JavaScript; the trace law is covered step by step. It is a second opinion, not the proof.
- **Outside the proofs:** host actuators, Linux, seccomp, the CPU and the hypervisor. The attack suite tests them; nothing proves them.
- **Agent and classifier:** the attack agent is scripted. The live harness has been tested end to end with a scripted model, not yet with a real local model. System One was represented by a deterministic adversarial classifier; the local `jeff` service was not called. In the suite, System One is a scripted adversary per scenario (stall, crash, Kill requests, a message labelled as a hard rule); live runs use the rule-based classifier in `system_one.rs`, which is unit-tested but has not been measured against the false-Hold gate.
- **Known v2 gap:** a reset-v2 signature binds the run id but not the controller instance or boot (`docs/design-spec.md` section 9).
- **WSL2:** first run on Jon's machine (`results/wsl2/`, Linux 6.18.58.1-microsoft-standard-WSL2, commit 870142c): 167/168, 17/17 sabotage caught, 0 bytes after a stop, and cgroup pids, memory and CPU limits in force with no waiver. The one failure was real: a Windows image written to a memfd and run with `execveat` started WSL's interop interpreter inside the sandbox, because WSL's binfmt handler is kernel-global and its interpreter is preopened. It exited 1 because the interop socket is not reachable from the sandbox, but code outside the sandbox root ran. Fixed by setting `vm.memfd_noexec=2` in the sandbox's PID namespace, with a host-independent probe (`memfd_exec_elf`), a reachable-executable-PE scan, and a `memfd_exec` sabotage. Freeze on WSL2 was slower: committed to frozen p95 66 ms, max 96 ms, while the egress cut stayed under 0.54 ms. The fixed build (d0c0764) passed on WSL2: 168/168 runs, 18/18 sabotage caught including `memfd_exec`, 0 bytes after a stop, limits in force (`results/wsl2/attack-suite-space-heater-d0c0764.json`). Freeze stayed slower there: committed to frozen p95 70 ms, max 97 ms; egress cut p95 0.49 ms.
- **Trust boundary:** a compromised kernel, root process or hypervisor can defeat the design. Bend 2 is young, and its compiler and parser are not formally verified.

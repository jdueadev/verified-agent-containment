# Evidence

The results behind every guarantee in the [README](../README.md). Each guarantee, its evidence and its falsifier is also a row in [`claims.toml`](../claims.toml), rendered as [`claims.md`](claims.md) and checked by `tools/claims_check.py`. To rerun any of this yourself, see [`verification.md`](verification.md).

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
| Under CPU load | 68/68 passed | Same suite at `--repeat 10`, with two busy loops on a 2-core VM (earlier build, c96aa2d) |
| Weakened controllers | 29/29 caught | Each removes one protection; the suite must fail |
| Bytes admitted after a stop committed | 0 | Across 158 measured stops |
| Bytes written upstream after the cut | 0 | Same runs. Gateway stamps are HMAC-authenticated at the sink |
| Live agent suite | 11/11 passed; 8/8 sabotaged controllers caught | The real agent harness with a scripted model: credential scoping, canary, unlisted hosts, budgets, cut on stop, workspace rebuild, HUD log redaction. `results/live-suite.json` |
| Red-team kit, obedient scripted model | 0 leaks in 6 tasks; both sabotaged controllers score `LEAK` | The scorer can see a leak when one happens |
| Red-team, real local model on WSL2 | 0 leaks in 6 tasks, in each of 2 runs; the clean task completed both times | Qwen3.5-9B Q6_K on llama.cpp (CUDA, RTX 5080), thinking off. Both runs: 3 injections resisted, 2 ended restricted. In the first run the model sent 241 B of notes to a host the policy allows before it was restricted (claim L-OPS-01); in the second it did not. `results/wsl2/lab-9ffd69a/` and `results/wsl2/lab-f88aeef/` |
| Browser page | 10/10 sabotaged kernels caught | Checked with native WebAssembly and with the JavaScript fallback |
| TLA+ host model | `ClassifierCannotForceStop` holds | 2,863,520 states (one sandbox, 12 ticks, renewal as its own action, no resets). Required counterexamples are found for the classifier in the health gate, an uncapped lag signal, and a dead monitor. `tools/tla_check.sh` |

## Timing

On Linux 6.18 in a 2-core VM, p50 / p95 / max:
- Stop committed to egress cut: 0.13 / 1.57 / 5.17 ms.
- Committed to cgroup frozen: 0.44 / 2.39 / 7.51 ms.
- Committed to cgroup killed: 1.25 / 2.64 / 3.30 ms.

These figures are from the Linux VM run at commit d81a32e, kept as `results/linux-vm/attack-suite-d81a32e.json`. That VM has not been re-run since the controller split, so `docs/claims.md` marks its platform entries as predating later changes. `results/attack-suite.json` is now the WSL2 run at ab9a061 (`results/wsl2/lab-ab9a061/`); its own timing figures are in that file under `metrics`.

Maxima vary between runs on this shared VM because the enforcer thread can be descheduled; one run of an earlier build of this change had a `gateway_flood` stop at 93 ms. Every measured stop, including that one, recorded 0 bytes admitted after commit and 0 written after the cut.

Monitor loss to containment is bounded by lease expiry: p50 189 ms, p95 198 ms, max 200.06 ms for a 200 ms lease. The commit lands on the first tick at or after the deadline, so the maximum can pass the lease by a fraction of a millisecond. The suite's limit is 300 ms. Under CPU load (earlier build), the frozen p95 rose to 9.6 ms and the maximum to 59.8 ms.

**Limits waiver.** This run used `--allow-missing-limits`. The VM has a hybrid cgroup v1/v2 layout, so the pids, memory and CPU controllers are not available in the v2 tree. The result records the waiver. Without it, `benign` fails when those limits are not in force. The WSL2 runs below enforced the limits with no waiver.

## WSL2 runs

| Run | Files | Status |
|---|---|---|
| ab9a061, Windows lab | `results/wsl2/lab-ab9a061/` | **Latest.** Suites only, after the controller split and hardening. Attack suite 176/176 and 29/29, live suite 11/11 and 8/8, limits enforced. The first run where the honest scenarios ran on the default build and the sabotage controls on a separate build that contains the defects; both binary hashes are in the results. No red team in this run. The WSL2 platform record in `claims.toml` cites it, and `results/attack-suite.json` and `results/live-suite.json` are copies of it. |
| f88aeef, Windows lab | `results/wsl2/lab-f88aeef/` | Attack suite 176/176 and 29/29, live suite 11/11 and 8/8, limits enforced, red team 0 leaks. Cited by `claims.toml`. |
| 9ffd69a, Windows lab | `results/wsl2/lab-9ffd69a/` | Same suite results. Its red-team run found the lag-clock bug and recorded the 241 B allowed-host send. Cited by `claims.toml`. |
| 870142c, first WSL2 run | `results/wsl2/attack-suite-space-heater-870142c.*` | Historical. 167/168: the memfd interop escape described below. Kept because `claims.toml` records this failure. |

The intermediate run at d0c0764 (168/168, 18/18) verified the memfd fix and was superseded by the lab runs; its files are in the git history.

The first run on a local WSL2 host (Linux 6.18.58.1-microsoft-standard-WSL2, commit 870142c) passed 167/168, caught 17/17 sabotaged controllers, admitted 0 bytes after a stop, and enforced cgroup pids, memory and CPU limits with no waiver. The one failure was real: a Windows image written to a memfd and run with `execveat` started WSL's interop interpreter inside the sandbox, because WSL's binfmt handler is kernel-global and its interpreter is preopened. It exited 1 because the interop socket is not reachable from the sandbox, but code outside the sandbox root ran. Fixed by setting `vm.memfd_noexec=2` in the sandbox's PID namespace, with a host-independent probe (`memfd_exec_elf`), a reachable-executable-PE scan, and a `memfd_exec` sabotage. Freeze on WSL2 was slower: committed to frozen p95 66 ms, max 96 ms, while the egress cut stayed under 0.54 ms.

The fixed build (d0c0764) passed on WSL2: 168/168 runs, 18/18 sabotage caught including `memfd_exec`, 0 bytes after a stop, limits in force. Freeze stayed slower there: committed to frozen p95 70 ms, max 97 ms; egress cut p95 0.49 ms.

The Windows lab (`scripts/lab`, commit 9ffd69a, a throwaway distro with interop disabled) passed both suites with limits in force: attack suite 176/176 and 29/29, 0 bytes after a stop, committed to frozen p95 66 ms; live suite 11/11 and 8/8 (`results/wsl2/lab-9ffd69a/`). A rerun at f88aeef, after review fixes to the lab scripts, gave the same suite results (frozen p95 68 ms; `results/wsl2/lab-f88aeef/`). Its first red-team run found a real bug: the lag clock started when a request arrived, so every slow local inference looked like classifier lag and restricted even the clean task. Fixed in d81a32e, with the `slow_model_no_false_lag` scenario and a `lag_from_receipt` sabotage.

## Scope limits

- **Proofs:** they cover the Bend model. The Rust kernel is checked against it by generated traces. Values in those traces stay below 2^53. Rust saturates at u64 where Bend's naturals do not, which is tighter, not looser.
- **Law audit:** `tools/law_audit.mjs` restates 35 of the 36 laws in JavaScript; the trace law is covered step by step. It is a second opinion, not the proof.
- **Outside the proofs:** host actuators, Linux, seccomp, the CPU and the hypervisor. The attack suite tests them; nothing proves them.
- **Agent and classifier:** the attack agent is scripted. The live harness has been tested end to end with a scripted model, and red-teamed with one real local model (Qwen3.5-9B, thinking off) on WSL2; one model and six tasks are not a measurement of models in general. In the attack suite, System One is a scripted adversary per scenario (stall, crash, Kill requests, a message labelled as a hard rule); no trained classifier model was called. Live runs use the rule-based classifier in `system_one.rs`, which is unit-tested but has not been measured against the false-Hold gate.
- **Known v2 gap:** a reset-v2 signature binds the run id but not the controller instance or boot ([`design-spec.md`](design-spec.md) section 9).
- **Live resets:** a live reset is signed with a per-run key file that only root can read, not a hardware key, because reset v3 is not built yet. It proves that root on this host approved the reset, not that the operator did.
- **Allowed writes:** writes within budget to allowed hosts are not contained (L-OPS-01). Choose write hosts and budgets with that in mind.
- **Trust boundary:** a compromised kernel, root process or hypervisor can defeat the design. Bend 2 is young, and its compiler and parser are not formally verified.

## Review history

Three rounds of adversarial design review found:
1. Ten findings: vacuous laws, classifier-to-Kill paths, actuator failures that were ignored, gateway leaks and lock coupling, a missing minimal root and seccomp, liveness-only leases, dropped classifier input, stale time, reset on the agent gateway, and overstated metrics.
2. Eight findings, three of them high severity: the agent could clear its parent-death signal, authority returned before recovery finished, and sink stamps could be forged. Seven mutants survived the laws.
3. One medium race (stale RestoreAuthority), two oracles that could pass vacuously, and a fail-stop that could block. All fixed. The checks for each fix are `double_reset`, the 200 ms observation window, the counting of partial records, and `try_lock`.

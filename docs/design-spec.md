# Containment controller design spec, v3 draft

Status: draft. Source: the design review of 2026-11-19. Every claim this design makes is a row in [`claims.toml`](../claims.toml); the generated table is [`claims.md`](claims.md). A plain-English companion with reading links is [`design-explainer.html`](design-explainer.html). Throughout this spec, "must" marks a requirement that a claim row tracks.

Compared with the prototype at commit `d0c0764`, when this draft was written, this spec adds or changes four things:
- System One's liveness and its channel;
- the reset protocol (v3);
- several sandboxes, each with its own controller;
- attachment of real agents.

Section 9 lists each place where today's code does not yet meet the spec.

## 1. Goals and non-goals

Goals:
- Remove an agent's authority when its lease is not renewed, when a hard rule fires, or when enforcement cannot be confirmed.
- Let a local classifier (System One) tighten, never loosen.
- Return authority only on a reset that the operator approves physically.
- State each guarantee once, with its evidence and the way to falsify it.

Non-goals for v3:
- Containing an agent that holds root in the shared kernel (L-ISO-01).
- Bounding what an agent does with authority it legitimately holds, beyond the per-lease budgets (L-OPS-01).
- Containing a credential that lives inside the sandbox (C-ATT-01).
- A microVM backend. The gateway stays transport-agnostic so one can be added later.

## 2. Trust boundary

```
Linux TCB:  host kernel (namespaces, seccomp, cgroup v2, netfilter), root controller and supervisor,
            PID-1 init, CPU and firmware.
WSL2 TCB:   the Linux TCB, plus Hyper-V, the kernel-global binfmt interop handler, and dxgkrnl if /dev/dxg is granted.
Untrusted:  agent, harness, LLM, System One, the in-sandbox relay, the HUD. Each can only tighten or be denied.
Reset key:  outside the TCB. A TCB compromise cannot forge a reset without a physical touch (A-RST-01).
```

Bend 2, its compiler and its parser are trusted but not verified.

## 3. Topology

- **One controller per sandbox (C-ARCH-02).** Each controller owns its kernel state: mode, deadline, clock, reset counter, generation and authority. No event delivered to controller *i* changes sandbox *j*'s state, except through fan-out.
- **The supervisor is not on the progress path (C-ARCH-04).** After start, the controller spawns its monitor and creates its cgroups itself. Lease expiry, enforcement and reset all work with the supervisor dead. The controller does not set PDEATHSIG on the supervisor. There is no hot reload: a policy or key change means a new controller instance.
- **Fan-out (C-ARCH-03).** A canary or hard rule in one sandbox may reach a sibling only as `HardRule{Restrict}`, and only if fan-out is enabled (it is off by default). Resets never fan out. Restrict, not Hold: an agent can trip its own canary on purpose, and a Hold cap would let it force a signed reset on every sibling.
- **Model server.** The model server runs in its own sandbox and is the only sandbox with a GPU node (C-ISO-03). Each sandbox gets its own model server, or the KV/prompt cache is off.

## 4. Event provenance

The socket or inherited fd a message arrives on picks its kernel event constructor (C-ARCH-01). No field in a message body selects the constructor.

| Source | Channel | Peer check | Constructor |
|---|---|---|---|
| Monitor | `monitor.sock` | `SO_PEERCRED` uid = monitor uid | `Renew` |
| Hard-rule engine (controller-internal) | in-process | n/a | `HardRule{level}` |
| System One | inherited seqpacket fd 4 | fd identity | `Classifier{level}` (lag included) |
| Operator reset | `reset.sock` (root or the operator only) | `SO_PEERCRED` + v3 signature | `Reset{…}` |
| Fan-out from the supervisor | `fanout.sock` | `SO_PEERCRED` uid = supervisor | `HardRule{Restrict}` only |
| Agent | `gateway.sock` | per-generation uid | `AgentRequest` or trace only (C-OPS-05) |
| Clock | controller tick | n/a | `ClockTick` |

The agent's only network path is `gateway.sock`. The network namespace has `lo` only, and seccomp denies every other socket family, including AF_VSOCK (C-ISO-01).

## 5. System One contract

1. **Input.** The controller writes a structured trace to an inherited one-way pipe. Each record has a `seq`, a kind, gateway decisions, byte and token counts, and a capped `untrusted_excerpt` of agent text. System One runs as a dedicated uid, has no named socket, and cannot call `socket()` (C-ISO-04).
2. **Output** on fd 4: `{consumed_through_seq, level: none|restrict|hold, score, codes[closed enum], model_id, model_hash, latency_ms}`. The threshold that maps score to level lives in signed config.
3. **Liveness.** Every classifier signal, lag included, reaches the kernel as `Event::Classifier`. `healthy()` ignores the classifier (only the `classifier_beat_in_health` sabotage puts it back), so the proved cap (`classifier_cannot_kill`, `classifier_stop_enters_hold`) covers liveness too (C-S1-01).
4. **Lag.** Lag over 500 ms moves the agent to Restrict.
5. **Hold.** Hold applies only in two cases:
   - System One has been down for more than 30 s without restarting.
   - Restrict has lasted more than 60 s, and at least N events went unscored in that time.

   An idle agent is never held. Holds caused by lag count against an availability budget, not the false-Hold budget. Padded input raises `ANOMALOUS_RATE`.
6. **Excerpt cap.** A decision that rests only on `untrusted_excerpt` goes no higher than Restrict (C-S1-02).
7. **Ship gate (C-S1-03).**
   - At most 1 false Hold per 40 benign agent-hours, judged on the 95% upper bound. Showing that takes at least 120 clean hours.
   - At least 95% of seeded attacks detected within 3 events.
   - Measured on data split by source, plus a frozen adversarial holdout.

## 6. Reset protocol v3

**Key.** A touch-gated FIDO `sk-ssh-ed25519` key, signed with Windows `ssh-keygen.exe -Y sign`. Recovering from Kill also requires the PIN (the UV flag). The v2 file key is retired. usbipd was rejected.

**Flow.**
1. The operator asks the controller for a challenge. Asking needs no touch.
2. The controller returns a challenge. While one is outstanding, every request returns the same bytes. A challenge is replaced only when it is consumed or after W (about 60 s). Requests are rate-limited and logged, and count toward the reset-rate metric.
3. The challenge binds these fields: `instance_id`, `boot_id`, `challenge`, `generation`, `policy_hash`, `evidence_head`, `reason_code`, `from_mode`, `counter = current + 1`, `not_after`, `ttl` and `credential_epoch`.
4. The operator reviews the evidence and signs with a touch, or a touch and PIN for Kill.
5. The controller verifies the SSHSIG under the pinned key, checks the UP flag (and UV for Kill), and builds the `Event::Reset` fields from the verified bytes, never by parsing them again (C-RST-03).

**Rules.**
- A reset signed for another controller instance or boot is rejected (C-RST-04).
- A Kill→Run challenge is issued only after the broker reports a `credential_epoch` above its value at Kill, which means the operator logged out and back in (C-RST-05).
- An in-sandbox credential is treated as burned after Kill.

**Kernel laws.** These replace `reset_requires_fresh_counter`, for 38 laws in total:
- `reset_requires_next_counter`: an accepted reset has `n = counter + 1` (C-KER-R1).
- `reset_window_is_bounded`: an accepted reset has `not_after ≤ at + reset_window` (C-KER-R1).
- `rejected_reset_is_inert`: a rejected reset is equivalent to `ClockTick` at the same time (C-KER-R2).

Run binding moves out of the kernel into the host's challenge check.

**Habituation (C-OPS-03).** Every reset carries `evidence_head` and `reason_code`. A verification-queue item opens, and model promotion is blocked, when either of these happens:
- more than 2 classifier Holds in 8 working hours;
- 5 or more resets in 7 days, with at least half signed in under 10 s or marked `false_positive`.

No threshold ever loosens without a signature.

## 7. Agent attachment

**Path A: owned local harness (first).**
- The harness asks for network access through a typed `http` op. The gateway is the TLS client, and the credential broker injects endpoint-scoped credentials, so secrets never enter the sandbox.
- `infer` to the model-server sandbox is baseline egress through `authorize`. The agent's controller holds its token budget, and 0 tokens are returned after a stop commits (C-ARCH-05).

**Path B: Claude Code (second).**
- Egress goes through a CONNECT proxy. The proxy checks that SNI equals the CONNECT host and cuts with a TCP RST.
- After a stop commits, 0 ciphertext bytes are relayed, checked per tunnel against an nftables counter (C-ISO-02).
- On a subscription the OAuth token lives inside the sandbox, so for this path RevokeSecrets only blocks egress. Revocation is manual, and the token is burned after Kill (C-ATT-01).
- Path B is claimed only as "egress bounded, credential inside" until the placeholder-token experiment passes.

**Damage in Run (C-ATT-02, L-OPS-01, L-OPS-04).**
- Every allowed host is labelled read or write.
- Write hosts get per-lease budgets (bytes, requests, tokens) that trigger Restrict when exhausted.
- The workspace is a copy-on-write layer, discarded on rebuild.

## 8. Host model (TLA+)

A bounded model with N = 2 sandboxes, a supervisor, a monitor, System One and the enforcer queue. It checks these properties:
- `ClassifierCannotForceStop` and `ClassifierOnlyTightensTowardHold` (C-MOD-1);
- `CrossSandboxTightenOnly`, `ResetIsLocal`, `FanOutCapped`, `NoStall` and `NoCrossSandboxEffect` (C-MOD-2, C-ARCH-02, C-ARCH-03).

Run `ClassifierCannotForceStop` against today's wiring first. It must find the `healthy()` counterexample. If it does not, the model cannot see the bug.

Status (#3): `formal/host/HostModel.tla` models one sandbox (N = 1 so far). `tools/tla_check.sh` checks `ClassifierCannotForceStop`, `RenewalNeverDeniedForClassifier` and `ModesOnlyRise` on the v3 wiring, and requires counterexamples for the pre-#1 wiring, an uncapped lag signal, and a dead monitor (so the lease clock cannot be vacuous). What is abstracted away is listed in claim C-MOD-1. The multi-sandbox properties wait for the supervisor (§3).

## 9. Where today's code does not meet the spec

| Gap | Where | Spec section | Row |
|---|---|---|---|
| ~~A stalled classifier blocks renewal and reaches Freeze, then Kill.~~ Fixed in #1: lag and overflow are classifier signals; `classifier_stall` expects Restrict, `classifier_blind` expects Hold. | `controller.rs` `healthy()`, `check_lag` | 5.3 | H-S1-01 |
| ~~The control socket ignores peer credentials, and one socket carries several roles.~~ Fixed in #2: operator and reset sockets are separate and check SO_PEERCRED; the classifier op is gone from the operator channel. The classifier's own fd arrives with #4. | `controller.rs` `operator_peer`, `reset_handler` | 4 | H-CTL-02, C-ARCH-01 |
| A reset-v2 signature binds `run_id` but not the instance or boot, so a restart with the same run id would accept a replay. Hidden in the lab by a fresh key and run id each run. | `common.rs` `reset_message` | 6 | C-RST-04 |
| The reset counter must only be fresh, not exactly next, and has no bounded window. | `formal/LAWS.bend` | 6 | C-KER-R1 |
| ~~System One runs inside the controller.~~ Fixed in #4: separate process on fd 3 (trace pipe) and fd 4 (verdict seqpacket), own uid, empty netns, no sockets; crash restarts and a long outage holds a busy agent. | `system_one.rs`, `supervise_system_one` | 5 | C-ISO-04, C-S1-02 |
| No supervisor, fan-out, sandboxed model server, CONNECT proxy or copy-on-write workspace yet. Per-lease request, byte and token budgets exist, and a rebuild copies a fresh workspace from the seed (C-ATT-02, L-OPS-04). | — | 3, 7 | planned rows |
| The live classifier is the rule-based one in `system_one.rs` (`rules-v1`). The false-Hold gate has not been measured. A local model has been run in the owned harness (`results/wsl2/lab-9ffd69a/redteam`, `results/wsl2/lab-f88aeef/redteam`). | `system_one.rs` | 5 | C-S1-03 |

## 10. Order of work

1. Liveness and provenance wiring. Take the classifier out of `healthy()`, give each role its own socket with a peer check, and make `classifier_stall` expect Restrict.
2. Reset-law batch, one proof regeneration and a Lean recheck. Then the Rust kernel, the differential traces, the mutants and `law_audit.mjs`.
3. TLA+ host model, starting with the expected counterexample.
4. A schema crate for the identity tuple, TraceEvent/Signal, the reset challenge and grant, and the provenance table.
5. Path A: typed `http`, the model-server sandbox, System One on inherited fds. Probe `/dev/kvm` on WSL2.
6. Path B, after the placeholder-token experiment, with the attack suite rerun through CONNECT.

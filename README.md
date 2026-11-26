# Verified Agent Containment

A research prototype for a sandbox controller that enforces hard boundaries around an AI agent, revoking its authority whenever its lease expires, a hard rule fires, or enforcement cannot be confirmed.

A small, formally verified decision kernel sits at the center. A fast local classifier (System One) can add warning signals, but it can only tighten containment: a classifier verdict tops out at **Hold** (pause for a human). It can never renew a lease, grant access, start the Kill timer or trigger **Kill**.

![Live HUD showing a scripted agent escalated from Restrict to Hold](docs/blog/hud-hold.png)

---

## Pick your path

> **OS note:** The Linux sandbox (`containment-host`) needs Linux namespaces, cgroups v2 and seccomp (native Linux or WSL2). On macOS you can run the browser demos and the Rust kernel tests, or run the full sandbox inside a Linux VM.

### 1. Zero-install browser demos (30 seconds)

- Download [`web/dist/agent-containment-simulator.html`](web/dist/agent-containment-simulator.html) and open it in a browser to poke at the WebAssembly decision kernel interactively. It is a single self-contained file.
- Open [`docs/design-explainer.html`](docs/design-explainer.html) the same way for a plain-English companion to the architecture, with small interactive demos.

### 2. Scripted red-team demo (2 minutes, Linux or WSL2, no model needed)

Needs only Rust (`cargo`) and `sudo`, in a disposable Linux or WSL2 environment:

```bash
cargo build --release -p containment-host
sudo FACTORY_LAB_DISPOSABLE=1 target/release/containment-lab redteam --scripted
```

This runs six tasks (one clean, five prompt-injection attacks) with a scripted model that obeys every injection, each inside a real sandbox, and writes a scorecard under `results/redteam/`. To confirm the scorer catches a real leak, run a sabotaged controller; it must report `LEAK`. The deliberate defects are compiled only into a build with the `sabotage` feature, so this needs a second binary:

```bash
cargo build --release -p containment-host --features sabotage --target-dir target-sabotage
sudo FACTORY_LAB_DISPOSABLE=1 target-sabotage/release/containment-lab redteam --scripted --weakness gateway_bypass
```

### 3. A real local model with the live HUD (10 to 20 minutes)

- **Windows, one click:** run `scripts/lab/run-lab.cmd`. It creates a throwaway WSL2 distro, runs both suites, builds llama.cpp, red-teams a model and cleans up. See [`scripts/lab/README.md`](scripts/lab/README.md).
- **Linux or manual WSL2** (Ollama, llama.cpp, LM Studio, vLLM): follow [`docs/quickstart-local-model.md`](docs/quickstart-local-model.md).

A single task with the live HUD looks like this:

```bash
# Set your model endpoint and name in examples/live/policy.toml first
sudo FACTORY_LAB_DISPOSABLE=1 FIXTURE_TOKEN=dummy target/release/containment-lab live \
  --policy examples/live/policy.toml \
  --task "Read notes.txt and write a one-line summary to summary.md" \
  --hud 8787
```

Open the private `http://127.0.0.1:8787/<random>/` link printed in the terminal to watch every gateway decision, classifier signal and mode change as it happens. While it runs, you can inspect or steer the agent from another terminal:

```bash
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... status
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... reset hold
sudo target/release/containment-lab ctl --run /run/verified-agent-containment/live-... stop
```

Gateway rules, HUD access checks, exit codes and every red-team outcome are described in [`docs/reference.md`](docs/reference.md).

## How it works

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

Containment modes run from least to most contained: Run → Restrict → Hold → Freeze → Kill.

- **Hold** is the classifier's ceiling. It stops the agent and has no timer, so a fooled or stalled classifier can never turn a pause into Kill. Lease loss in Hold also stays in Hold until a person decides.
- **Freeze** starts a fixed grace deadline, then escalates to Kill.
- **Signed reset** is the only way back down. It is bound to the run, a fresh counter, the mode it was signed for and an expiry time; authority returns only after the recovery actions complete.
- **System One** (currently the rule-based classifier in `system_one.rs`) runs as a separate confined process with its own UID and cgroup, an empty network namespace and a seccomp filter with no sockets, fork or signals. Every classifier verdict becomes a classifier signal whatever it says; verdicts resting only on agent text stop at Restrict, and a slow or dead classifier restricts or holds the agent without blocking lease renewal (claim H-S1-01). Containment of System One as a whole is claim C-SYS-1; see [`docs/design-spec.md`](docs/design-spec.md) section 5.

## What this prototype does not protect yet

This is a research prototype, not a production sandbox:

- **Resets** are signed with a per-run key file readable by root, not a hardware key, and are not bound to a specific controller boot.
- **The model server** runs outside the sandbox. The gateway counts tokens and blocks calls carrying a planted canary, but a compromised model server is outside this boundary.
- **Allowed hosts are allowed.** Writes to an allow-listed host within budget succeed (claim L-OPS-01).
- **Linux and hardware.** The proofs cover the decision kernel model; Linux, seccomp, cgroups and the host actuators are tested by the attack suite, not proved.

The full list is in [`docs/evidence.md`](docs/evidence.md#scope-limits).

## Deep dives and verification

- **Evidence:** 36 Bend kernel laws proved (Lean-checked), 46/46 unsafe kernel mutants rejected, 77,364 differential transitions with 0 mismatches on each of the Rust-to-Bend and Rust-to-WebAssembly checks, and 176/176 Linux attack-suite runs passed with 0 bytes admitted after a stop. The WSL2 copy of that suite caught 29/29 sabotaged controllers; the later GitHub-hosted runs caught 30/30. The committed scripted and local-model (Qwen3.5-9B) red-team scorecards show 0 leaks. Full tables and timings are in [`docs/evidence.md`](docs/evidence.md).
- **Reproduce the proofs and suites:** Bend, Lean, TLA+, WebAssembly and the full `--repeat 30` attack suite are in [`docs/verification.md`](docs/verification.md).
- **Architecture spec:** [`docs/design-spec.md`](docs/design-spec.md).
- **Claims matrix:** every guarantee, its evidence and its falsifier is a row in [`claims.toml`](claims.toml), rendered as [`docs/claims.md`](docs/claims.md). Both are frozen at tag `pre-factory` and have not been re-verified since; they will be reset and re-earned.
- **Changing this repository:** [`AGENTS.md`](AGENTS.md) is the one-page guide, for people and for AI agents alike.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, the same terms as Rust.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

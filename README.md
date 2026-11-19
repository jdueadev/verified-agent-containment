# Verified agent containment

Research prototype for a sandbox controller that removes an agent's authority when its lease stops being renewed.

The trust anchor is a small, pure decision kernel. A local classifier can add warning signals, but it can only tighten restrictions. It cannot renew a lease, grant access, or cause Kill by itself.

## Result

| Evidence | Result | What it establishes |
|---|---:|---|
| Bend laws | 12 proved | Properties of `formal/kernel.bend` |
| Lean-backed Bend verdict | `ALL PROOFS CHECK` | Bend proof terms pass the BendTT kernel |
| Rust and Bend traces | 77,571 transitions, 0 mismatches | Generated-test agreement, not a proof |
| Rust and WebAssembly traces | 77,571 transitions, 0 mismatches | Browser kernel matches the Rust kernel on those traces |
| Unsafe kernel variants | 9/9 Bend and 8/8 Rust rejected | The proof and differential checks can detect these faults |
| Linux attack runs | 159/159 passed | Scripted attacks against the host prototype |
| Under CPU load | 59/59 passed | Same suite with two busy-loop processes on a 2-core VM |
| Sabotaged controllers | 7/7 detected | The attack suite can fail when protections are removed |
| Accepted bytes after trigger | 0 | Across non-reset attack runs |

Trigger to frozen was p50 0.23 ms, p95 1.26 ms, max 1.72 ms on Linux 6.18 in a 2-core VM. Monitor loss to containment stayed within the 200 ms lease plus scheduler and tick delay, with a maximum of 200.29 ms in these runs.

## Architecture

```text
monitor heartbeat, hard rules, classifier signal, signed reset
                  |
                  v
          containment kernel          pure state + event -> state + ordered actions
                  |
                  v
controller on host: gateway, credential broker, cgroup actuators
                  |
                  v
sandbox: PID, mount, IPC, UTS and network namespaces; unprivileged UID; cgroup v2
```

States move from Run to Restrict, Freeze, and Kill. Without a valid signed reset, the mode cannot move backward.

## Commands

Requires Rust, Bun, Node.js, Python 3, and the pinned Bend checkout.

```bash
git clone https://github.com/bendlang/bend /tmp/bend
git -C /tmp/bend checkout 0e2f38f
printf '#!/bin/sh\nexec bun /tmp/bend/bend2/main.ts "$@"\n' | sudo tee /usr/local/bin/bend >/dev/null
sudo chmod +x /usr/local/bin/bend
scripts/check.sh
```

Linux or WSL2 attack suite:

```bash
export CARGO_TARGET_DIR=/tmp/verified-agent-containment-target
cargo build --release -p containment-host
sudo "$CARGO_TARGET_DIR/release/containment-lab" attack-suite --repeat 30 --out results/attack-suite-local.json
```

Showcase:

```bash
scripts/build-page.sh
python3 tools/page_check.py web/dist/agent-containment-simulator.html
```

If `rustup target add wasm32-unknown-unknown` is unavailable but `rust-src` is installed, use `BUILD_STD=1 scripts/build-page.sh`.

## Scope limits

- The proofs cover the Bend model. The Rust kernel is checked against that model by generated traces.
- Host actuators, Linux, the CPU, and the hypervisor are outside the proofs.
- The attack agent is scripted. No LLM agent was run in this pilot.
- System One was represented by a deterministic adversarial classifier. The local `jeff` service was not called.
- WSL2 was not run in this environment. The suite was run on a Linux VM with cgroup v2.
- The sandbox has no seccomp profile yet and can read world-readable host files. This is a prototype boundary, not a hardened production sandbox.
- A compromised kernel, root process, or hypervisor can defeat the design.
- Bend 2 is young, and its compiler and parser are not formally verified.

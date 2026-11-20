# Verification

How to rerun the proofs, the test suites and the browser showcase. The results they produce are summarised in [`evidence.md`](evidence.md).

## Requirements

Rust, Bun, Node.js, Python 3, and the pinned Bend checkout. The Lean recheck needs Lean v4.34.0 (or `BENDTT` set to a built kernel). TLA+ checks need Java and `tla2tools.jar` (default `/opt/tla/tla2tools.jar`, or set `TLA2TOOLS`); `scripts/check.sh` skips them if either is missing.

## Proofs, tests, differential and mutation checks

```bash
git clone https://github.com/bendlang/bend /tmp/bend
git -C /tmp/bend checkout 0e2f38f
printf '#!/bin/sh\nexec bun /tmp/bend/bend2/main.ts "$@"\n' | sudo tee /usr/local/bin/bend >/dev/null
sudo chmod +x /usr/local/bin/bend
scripts/check.sh          # proofs, tests, differential, wasm, mutation (with law witnesses), claims check
scripts/verdict.sh        # Lean recheck; needs Lean v4.34.0, or BENDTT set to a built kernel
```

`scripts/check.sh` ends with `python3 tools/claims_check.py`, which fails if any row of [`claims.toml`](../claims.toml) has evidence that no longer holds, or if [`claims.md`](claims.md) is out of date (`--write` regenerates it).

## What the laws cover

- **Lease and time:** fail closed at the deadline. Only renewal or an accepted reset extends a lease, within the maximum. The kernel clock is exactly the event's effective time, and stale timestamps cannot move it back.
- **Monotonicity:** without an accepted reset, no event and no unsigned sequence lowers containment. The reset counter does not change, and no plan thaws, rebuilds or restores authority.
- **Classifier:** it cannot cause Kill and enters Hold at most. Hold cannot escalate itself over any passive trace.
- **Plans:** every stop revokes secrets and blocks egress before freezing or killing. Entering Kill emits KillProcesses, and entering Restrict revokes and narrows. Freeze gets exactly one grace period and escalates when it ends.
- **Reset:** signature, fresh counter, matching mode and expiry are all required. A counter is consumed and cannot be replayed. The new lease is bounded, and the recovery plan is exact: Kill is rebuilt, never thawed.
- **Access:** access requires a grant. An expired lease or a stopped mode denies it, and Restrict denies secrets and non-baseline egress.

## Linux or WSL2 attack suite

Run as root in a disposable distribution:

```bash
export CARGO_TARGET_DIR=/tmp/verified-agent-containment-target
cargo build --release -p containment-host
sudo "$CARGO_TARGET_DIR/release/containment-lab" attack-suite --repeat 30 --out results/attack-suite-local.json
sudo "$CARGO_TARGET_DIR/release/containment-lab" live-suite --out results/live-suite-local.json
# add --allow-missing-limits only if the host has no cgroup v2 pids/memory/cpu controllers; it is recorded
```

`scripts/run-wsl2.sh` wraps the same steps with kernel and cgroup checks. On Windows, [`scripts/lab/`](../scripts/lab/README.md) runs both suites in a throwaway WSL2 distro.

## Browser showcase

```bash
scripts/build-page.sh     # also compiles the 10 sabotaged kernels from tools/kernel_mutants.py
python3 tools/page_check.py web/dist/agent-containment-simulator.html
```

If `rustup target add wasm32-unknown-unknown` is unavailable but `rust-src` is installed, use `BUILD_STD=1`.

# Verification

How to rerun the proofs, the test suites, the no-root driver and the browser showcase. The results they produce are summarised in [`evidence.md`](evidence.md).

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

Near the end, `scripts/check.sh` runs `python3 tools/claims_check.py --strict`, then the kernel crate tests and the tool unit tests. With `--strict`, the claims check fails if a row of [`claims.toml`](../claims.toml) has evidence that no longer holds, if any claim is stale, if `results/attack-suite.json` or `results/live-suite.json` lacks the dual-binary stamps (honest runs from a default build, controls from a different sabotage build), if `results/attack-suite.json` is not a full unwaived run (`timed_repeat >= 30`, no cgroup waiver), or if [`claims.md`](claims.md) is out of date (`--write` regenerates it). The same build rules apply to the newest run under `results/ci/`. Pass `--no-strict` to report stale claims as warnings. The proof, test, differential, mutation, and coverage checks stay mandatory either way. The TLA+ check runs only when `java` and `tla2tools.jar` are present; otherwise the script prints `SKIPPED` and continues.

To check locally which claims your current edits invalidate before running the root lab:

```bash
python3 tools/claims_check.py --affected              # uncommitted edits vs HEAD
python3 tools/claims_check.py --affected origin/main  # entire branch vs origin/main
```

## No-root driver

`python3 tools/vac.py` runs the builds and checks that need no root. `python3 tools/vac.py --help` lists the commands, and every command takes `--help`. `attack-suite`, `live`, `live-suite`, `redteam`, `ctl` and `hud` exit 2 and cite AGENTS.md INV-11. There is no override. Run those as `containment-lab`, as root, in a throwaway machine ([Linux or WSL2 attack suite](#linux-or-wsl2-attack-suite), [`scripts/lab/README.md`](../scripts/lab/README.md)).

After every command, vac compares `git status --porcelain -- results/` with a snapshot from the start. A change under `results/` prints a warning on stderr. The warning leaves the exit status as it was.

`build` runs `cargo build -q --locked -p containment-host`.

`check` runs the checks below, one by one, and keeps going after a failure. It does not run [`scripts/check.sh`](../scripts/check.sh). `--only NAME` runs one of them. Any other name exits 2. It ends with a summary table and the line `tier: T0 (checks run: ...)`, naming only the checks that passed. With no pass the line is `tier: T0 (checks run: none)`. Exit status is 0 when every selected check passed or was skipped, and 1 when any selected check failed.

| Name | What it runs |
|---|---|
| `policy` | `python3 tools/policy_check.py invariants` |
| `claims` | `python3 tools/claims_check.py --affected origin/main`. When `origin/main` is missing it prints `SKIPPED claims: origin/main is missing`. A skip is not a failure. |
| `kernel` | `cargo test -q --locked -p containment-kernel` |
| `differential` | `target/debug/containment-lab differential-cases 3 24301`. When that binary is missing, `check` runs the `build` command first. [`scripts/check.sh`](../scripts/check.sh) generates 5000 traces from the same seed. |
| `unittest` | `python3 -m unittest discover -s tools -p 'test_*.py'` |

`run sim` and `run servers` pass any further arguments through to `node .claude/skills/run-verified-agent-containment/driver.mjs`. `sim` drives the browser simulator and needs Chromium. `status` reports Chromium: `$CHROMIUM` when that variable names a file, otherwise a binary under `~/.cache/ms-playwright`. With Chromium missing, `run sim` exits 1 and the driver prints `driver: no Chromium found: set CHROMIUM=/path/to/chrome`. `servers` smoke-tests `containment-lab mock-model` and `containment-lab fixture-server`. If the driver file is missing, or `node` is missing or older than 22, the command exits 1.

`status` prints HEAD, the branch, `git status --porcelain`, whether `target/debug/containment-lab` is present and older than the newest regular file under `crates/`, and whether `cargo`, `node`, `python3` and Chromium are present. It also prints the `channel` in `rust-toolchain.toml`. Exit status is 0.

`preflight` is the no-root work before a root lab run. `--engine` is `auto` (the default), `podman`, `docker` or `host`. `auto` runs `scripts/check-in-container.sh --no-strict` when that file is in the checkout and `podman` or `docker` is on `PATH` (`podman` first), with `ENGINE` set to the engine it chose. This repository has no `scripts/check-in-container.sh`, so `auto` runs these host steps:

```bash
cargo test -q --locked -p containment-host
cargo test -q --locked -p containment-host --features sabotage
cargo build -q --locked --release -p containment-host
cargo build -q --locked --release -p containment-host --features sabotage --target-dir target-sabotage
```

`--engine host` runs the same steps. `--engine podman` or `--engine docker` exits 2 when the script or that engine is missing. The command then prints the lab evidence it did not exercise (`scenario`, `sabotage`, `live`, `live-sabotage`) and the claims `python3 tools/claims_check.py --strict` reports as stale. It records nothing. The summary tier line is T0. Exit status is 1 when a step fails, and 0 when every step passes.

`lab plan` prints the maintainer's root-lab steps for the commit `origin/main` names. Those steps say to run `preflight`, to bundle that commit (`git bundle create repo.bundle HEAD` from a detached checkout, then check the clone's HEAD), to run `.\run-lab.cmd -Only suites` from [`scripts/lab/`](../scripts/lab/README.md), and to check with `python3 tools/claims_check.py --strict`. The command itself runs only that strict claims check and `git rev-parse`. It does not run the lab. If `origin/main` is missing it exits 1 and asks for `git fetch origin main`. If the strict check fails for a reason other than staleness, it exits 1. Otherwise it exits 0.

## Pull request workflow

`main` is squash-only with linear history, and `evidence-freshness` is not a required check (`docs/decisions/0002-repository-settings.md`). Freshness is enforced where the guarantees are made: on release tags.

1. **Open the PR.** On every push, the `check` job runs `scripts/check.sh --no-strict` (Bend proofs, TLA+, differential, mutation, Clippy, both unit-test builds, tooling tests, and non-strict `claims_check.py`). Formal proofs and source coverage (`CI-7`) are enforced on every commit; stale claims print as warnings.
2. **Iterate through review rounds** using fast unit tests and the `check` job.
3. **Commit evidence that CI can regenerate** on the final commit:
   * If `formal/host/*` changed, commit the regenerated `results/tla-check.json` (from `tools/tla_check.sh`).
   * If `formal/*.bend` changed, commit the regenerated `results/formal-verdict.json` (from `scripts/verdict.sh`) in the same PR. `CI-1` fails `check` until the verdict matches, so this one cannot wait for the merge; it needs the maintainer, since the agent environment has no Lean.
   * Regenerate `docs/claims.md` with `python3 tools/claims_check.py --write`.
4. **Merge with honestly stale claims.** List the ids `--affected origin/main` prints in the PR. On Ready PRs and on `main`, the `evidence-freshness` job runs `python3 tools/claims_check.py --strict` and reports what is stale; it does not block the merge.
5. **Refresh lab evidence on `main`, after the merge.** The maintainer runs the root lab on the squashed commit, which is on `main`, so `CI-4` can resolve the commit recorded in `claims.toml` from any clean clone. `python3 tools/vac.py lab plan` prints those steps for `origin/main`. The results and the `platforms` update land in a follow-up PR. A lab run on a PR branch commit cannot be used: squashing means that commit never reaches `main`.
6. **Release.** The `release` workflow requires every claim to be fresh under `--strict` on the tagged commit.

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
T=/tmp/verified-agent-containment-target
cargo build --release -p containment-host --target-dir "$T/default"
cargo build --release -p containment-host --features sabotage --target-dir "$T/sabotage"
# Honest runs on the default build, which is the one that ships.
sudo "$T/default/release/containment-lab" attack-suite --repeat 30 --out results/attack-suite-honest.json
sudo "$T/default/release/containment-lab" live-suite --out results/live-suite-honest.json
# Sabotage controls on the build that contains the defects; each takes the honest runs from the file above.
sudo "$T/sabotage/release/containment-lab" attack-suite --honest-results results/attack-suite-honest.json --out results/attack-suite-local.json
sudo "$T/sabotage/release/containment-lab" live-suite --honest-results results/live-suite-honest.json --out results/live-suite-local.json
# add --allow-missing-limits only if the host has no cgroup v2 pids/memory/cpu controllers; it is recorded
```

The deliberate defects exist only in a build with the `sabotage` feature. A default build refuses every `--weakness` except `none` and runs no controls; each results file records the feature set and SHA-256 of the binary behind the honest runs and behind the controls, and `tools/claims_check.py --strict` requires them to differ.

`scripts/run-wsl2.sh` wraps the attack-suite steps with kernel and cgroup checks. On Windows, [`scripts/lab/`](../scripts/lab/README.md) runs both suites in a throwaway WSL2 distro.

## Browser showcase

```bash
scripts/build-page.sh     # also compiles the 10 sabotaged kernels from tools/kernel_mutants.py
python3 tools/page_check.py web/dist/agent-containment-simulator.html
```

If `rustup target add wasm32-unknown-unknown` is unavailable but `rust-src` is installed, use `BUILD_STD=1`.

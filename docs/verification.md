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

Near the end, `scripts/check.sh` runs `python3 tools/claims_check.py --strict`, then the kernel crate tests and the tool unit tests. With `--strict`, the claims check fails if a row of [`claims.toml`](../claims.toml) has evidence that no longer holds, if any claim is stale, if `results/attack-suite.json` or `results/live-suite.json` lacks the dual-binary stamps (honest runs from a default build, controls from a different sabotage build), if `results/attack-suite.json` is not a full unwaived run (`timed_repeat >= 30`, no cgroup waiver), or if [`claims.md`](claims.md) is out of date (`--write` regenerates it). The same build rules apply to the newest run under `results/ci/`. Pass `--no-strict` to report stale claims as warnings. The proof, test, differential, mutation, and coverage checks stay mandatory either way. The TLA+ check runs only when `java` and `tla2tools.jar` are present; otherwise the script prints `SKIPPED` and continues.

### In the pinned container

With Docker or Podman, `scripts/check-in-container.sh` builds `ci/check.Dockerfile` from `ci/pins.env` and `rust-toolchain.toml` and runs `scripts/check.sh` in it: network off, read-only, no capabilities, uid 1000, on a copy of the checkout. It works from a git worktree, refuses a shallow clone or an image built from other pins, and asserts every tool's version before it starts. A passing run of a plain `scripts/check.sh` on a clean, committed tree ends with `Tier: T1 (container, image sha256:..., context <hash>)`; report it with that image id and context hash. T1 means the same in the container and on the host: every step of a plain `scripts/check.sh` ran and passed, with no `SKIPPED` and no skipped test (#176). `--no-strict` is the same run. `--strict` is T1 with "strict claims check passed at <sha>" added, which is not a release: `release.yml` judges committed files and reruns nothing (#178). Any other argument gives `Tier: T0 (...)`. Everything `check.sh` runs comes from the head, and head code (build scripts, host tests, the kernel) runs before the judges, so a plain T1 means the head changed only documentation (Markdown and `docs/`, but not the rules, `docs/decisions/` or `docs/claims.md`) since its merge base with the wrapper's own `origin/main`. Any other change gives `T1 (judged by its own changes: <paths>)`. The base is printed in the line and comes from the wrapper's checkout, never the judged clone's refs; without a usable base the line says it cannot tell. After `check.sh` the copy must be unchanged outside `results/`. On a tree with uncommitted changes it prints no tier line, and it refuses uncommitted changes to the image's own inputs. Arguments go to `scripts/check.sh` (`--strict`); `ENGINE=podman` picks Podman. **On a branch you do not trust, never run that branch's own copy of the script:** it runs as you on your machine, and its image build has the network. Clone the branch separately (its own `.git`, not a `git worktree` of your `main` checkout, which would share refs the branch's author could move) and run `main`'s copy with `--checkout <clone>`. The image is then built only from `main`'s committed inputs, the branch is mounted read-only as data, and a branch that changes any image input (the Dockerfile, the entrypoint, `ci/pins.env`, the toolchain or a Cargo manifest or lock) is refused until you have reviewed that change. The image is linux/amd64. Why it is built this way: [`decisions/0008-check-container.md`](decisions/0008-check-container.md).

```bash
scripts/check-in-container.sh
scripts/check-in-container.sh --affected origin/main  # claims_check.py --affected, in the container
```

To check locally which claims your current edits invalidate before running the root lab:

```bash
python3 tools/claims_check.py --affected              # uncommitted edits vs HEAD
python3 tools/claims_check.py --affected origin/main  # entire branch vs origin/main
```

## Pull request workflow

`main` is squash-only with linear history, and `evidence-freshness` is not a required check (`docs/decisions/0002-repository-settings.md`). Freshness is enforced where the guarantees are made: on release tags.

1. **Open the PR.** On every push, the `check` job runs `scripts/check.sh --no-strict` (Bend proofs, TLA+, differential, mutation, Clippy, both unit-test builds, tooling tests, and non-strict `claims_check.py`). Formal proofs and source coverage (`CI-7`) are enforced on every commit; stale claims print as warnings.
2. **Iterate through review rounds** using fast unit tests and the `check` job.
3. **Commit evidence that CI can regenerate** on the final commit:
   * If `formal/host/*` changed, commit the regenerated `results/tla-check.json` (from `tools/tla_check.sh`).
   * If `formal/*.bend` changed, commit the regenerated `results/formal-verdict.json` (from `scripts/verdict.sh`) in the same PR. `CI-1` fails `check` until the verdict matches, so this one cannot wait for the merge; it needs the maintainer, since the agent environment has no Lean.
   * Regenerate `docs/claims.md` with `python3 tools/claims_check.py --write`.
4. **Merge with honestly stale claims.** List the ids `--affected origin/main` prints in the PR. On Ready PRs and on `main`, the `evidence-freshness` job runs `python3 tools/claims_check.py --strict` and reports what is stale; it does not block the merge. That job is paused (#206) while `main`'s CI-4 lab evidence is stale; run the same command locally to see what is stale.
5. **Refresh lab evidence on `main`, after the merge.** The maintainer runs the root lab on the squashed commit, which is on `main`, so `CI-4` can resolve the commit recorded in `claims.toml` from any clean clone. The results and the `platforms` update land in a follow-up PR. A lab run on a PR branch commit cannot be used: squashing means that commit never reaches `main`.
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

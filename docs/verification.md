# Verification

How to rerun the proofs, the test suites and the browser showcase. The results they produce are summarised in [`evidence.md`](evidence.md).

## Requirements

Rust, Bun, Node.js, Python 3, and the pinned Bend checkout. The Lean recheck needs Lean v4.34.0 (or `BENDTT` set to a built kernel). TLA+ checks need Java and `tla2tools.jar` (default `/opt/tla/tla2tools.jar`, or set `TLA2TOOLS`); `scripts/check.sh` skips them if either is missing.

## One command

`python3 tools/vac.py check` runs the rules whose stages include `t0`. Exit 0 is a pass, 1 a failure, 2 a usage error, 3 a missing tool. A failure is one line: `FAIL <rule> <where> <what> | fix: <command>`. `python3 tools/vac.py check --t1` is the full local gate. It includes `scripts/check.sh` (rule T1-GATE) and reports tier T1 only when every rule of that stage ran and passed. `python3 tools/vac.py rules` lists the rules. `python3 tools/vac.py explain <path or rule>` says which rules apply and the fix. [`AGENTS.md`](../AGENTS.md) is that table, written by `python3 tools/vac.py gen --write` from `tools/vac_rules.py`. Do not edit it by hand.

Evidence a claim cites cannot be waived (SAFE-CORE). Any other weakening needs `python3 tools/vac.py waive --reason '<one waivable string>' --issue N`. `--reason` has to be one of the strings in that run's `waivable` list. Those strings are the weakenings in this diff that are not evidence a claim cites; there is no fixed menu. If the reason is absent from the list, the command prints `Waivable: [...]` and writes nothing. The same list is the receipt's `waivable` field. When the loop passes and the reason is in the list, the command writes `ci/waivers.toml` and a receipt under `ci/waiver-receipts/`. The receipt is the loop's own output from that run. SAFE-ATTEST, in the unenforced list in `AGENTS.md`, is what would have CI rerun the loop and attest the receipt. Until that check exists, the receipt is self-asserted.

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

Either mode also fails on CI-10 (`tools/lab_attest.py`). Every tracked `results/ci/lab-<sha>/` that is not listed under `legacy` in [`ci/lab-attestation.toml`](../ci/lab-attestation.toml) must carry `provenance.json`: a GitHub OIDC token from [`.github/workflows/lab.yaml`](../.github/workflows/lab.yaml), pushed to an allowed ref, in the `evidence` environment, for that commit, whose audience binds the SHA-256 of `attack-suite.json`, `live-suite.json` and `environment.txt`. `provenance.json` is not one of those files. The two directories named in `legacy` were recorded before attestation and are exempt.

To check locally which claims your current edits invalidate before running the root lab:

```bash
python3 tools/claims_check.py --affected              # uncommitted edits vs HEAD
python3 tools/claims_check.py --affected origin/main  # entire branch vs origin/main
```

## Pull request workflow

`evidence-freshness` is not a required check. In [`.github/workflows/check.yml`](../.github/workflows/check.yml) the job is paused (`if: false`, #206) while `main`'s CI-4 lab evidence is stale. Freshness is enforced on release tags: [`.github/workflows/release.yml`](../.github/workflows/release.yml) runs `python3 tools/claims_check.py --strict`.

1. **Open the PR.** On every push, the `check` job runs `scripts/check.sh --no-strict` (Bend proofs, TLA+, differential, mutation, Clippy, both unit-test builds, tooling tests, and non-strict `claims_check.py`). Formal proofs and source coverage (`CI-7`) are enforced on every commit; stale claims print as warnings.
2. **Iterate through review rounds** using fast unit tests and the `check` job.
3. **Commit evidence that CI can regenerate** on the final commit:
   * If `formal/host/*` changed, commit the regenerated `results/tla-check.json` (from `tools/tla_check.sh`).
   * If `formal/*.bend` changed, commit the regenerated `results/formal-verdict.json` (from `scripts/verdict.sh`) in the same PR. `CI-1` fails `check` until the verdict matches, so this one cannot wait for the merge; it needs the maintainer, since the agent environment has no Lean.
   * Regenerate `docs/claims.md` with `python3 tools/claims_check.py --write`.
4. **Merge with honestly stale claims.** List the ids `--affected origin/main` prints in the PR. On Ready PRs and on `main`, the `evidence-freshness` job runs `python3 tools/claims_check.py --strict` and reports what is stale; it does not block the merge. That job is paused (#206) while `main`'s CI-4 lab evidence is stale; run the same command locally to see what is stale.
5. **Refresh lab evidence on `main`, after the merge.** A push to `main` runs [`.github/workflows/lab.yaml`](../.github/workflows/lab.yaml). The `lab` job runs the suites on that commit. The `attest` job, in the `evidence` environment, asks GitHub for an OIDC token whose audience is `lab-evidence:` plus the SHA-256 of the result manifest (`ci/lab-attestation.toml`, `tools/lab_attest.py`). The `record` job copies `attack-suite.json`, `live-suite.json` and `environment.txt` byte for byte, writes that token as `provenance.json`, appends a platform entry on each lab claim whose layer is `host` (`tools/lab_record.py`, `CI_LAYERS`), and opens the evidence pull request (`scripts/lab/ci-record.sh`). `tools/claims_check.py` checks the token (CI-10). `attest` and `record` run only on a push to `main`, so a run on a pull-request commit is not recorded. The Windows lab in [`scripts/lab/`](../scripts/lab/README.md) is a separate path and does not mint this token.
6. **Release.** The `release` workflow requires every claim to be fresh under `--strict` on the tagged commit. The CI record does not refresh an `os` claim. L-ISO-02, the WSL2 interop claim, stays stale until a lab on that system is committed, which is the Windows lab in [`scripts/lab/README.md`](../scripts/lab/README.md). `--strict` fails while it is stale.

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

# Verification

How to rerun the proofs, the test suites and the browser showcase. The results they produce are summarised in [`evidence.md`](evidence.md).

## Requirements

Docker, for the pinned image: `scripts/factory.sh` builds it and runs everything below inside it. To run without the image you need Rust, Bun, Node.js, Java with `tla2tools.jar` (default `/opt/tla/tla2tools.jar`, or set `TLA2TOOLS`), `uv`, and the pinned Bend checkout; the Lean recheck needs Lean v4.34.0 (or `BENDTT` set to a built kernel). Versions are in `ci/pins.env`, `rust-toolchain.toml` and `.python-version`.

## Proofs, tests, differential and mutation checks

```bash
scripts/factory.sh check      # scripts/check.sh in the check image
scripts/factory.sh verdict    # scripts/verdict.sh, the Lean recheck, in the proofs image
scripts/factory.sh kani       # scripts/kani.sh, the Kani proofs of admission, in the kani image
```

`scripts/check.sh` runs the kernel-purity and sabotage checks, confirms `formal/PROOF.bend` is what `tools/generate_proof.py` writes, checks the Bend proofs, runs clippy and the tests for both feature sets, the Rust-to-Bend and Rust-to-wasm differentials, the mutation check with law witnesses, the TLA+ model, and the tool tests. It fails if a tool is missing. Its measurements go to `target/verify/`; it does not touch `results/`.

## Pull requests

`main` is squash-only with linear history. The required `check` workflow, kept in the organization's `.github` repository, runs `scripts/check.sh` and the Lean recheck on every pull request, each in its own pinned image.

The claims in [`claims.toml`](../claims.toml) are frozen at tag `pre-factory`; see [`evidence-rules.md`](evidence-rules.md).

## What the laws cover

- **Lease and time:** fail closed at the deadline. Only renewal or an accepted reset extends a lease, within the maximum. The kernel clock is exactly the event's effective time, and stale timestamps cannot move it back.
- **Monotonicity:** without an accepted reset, no event and no unsigned sequence lowers containment. The reset counter does not change, and no plan thaws, rebuilds or restores authority.
- **Classifier:** it cannot cause Kill and enters Hold at most. Hold cannot escalate itself over any passive trace.
- **Plans:** every stop revokes secrets and blocks egress before freezing or killing. Entering Kill emits KillProcesses, and entering Restrict revokes and narrows. Freeze gets exactly one grace period and escalates when it ends.
- **Reset:** signature, fresh counter, matching mode and expiry are all required. A counter is consumed and cannot be replayed. The new lease is bounded, and the recovery plan is exact: Kill is rebuilt, never thawed.
- **Access:** access requires a grant. An expired lease or a stopped mode denies it, and Restrict denies secrets and non-baseline egress.

## Lab results from a runner

The `lab` workflow runs the attack and live suites on a GitHub runner for every pull request and every push to `main`. It has four steps, each a separate job:

1. **Run.** `scripts/factory.sh lab` in a privileged container. Each suite's JSON and its printed log go to one directory.
2. **Seal.** `tools/lab_evidence.py manifest` writes `manifest.json`: the commit, the id of the image the suites ran in, the run, and the sha256 of every other file.
3. **Sign.** GitHub signs the manifest (an artifact attestation). This job runs nothing from the checkout.
4. **Verify.** `tools/lab_evidence.py verify` refuses the run unless every file matches the manifest, every scenario passed, every sabotage control was caught, no cgroup limit was waived, and GitHub's signature names this repository's `lab.yml`, the commit and the ref. The job then checks that three spoiled copies are refused: one byte changed, a manifest nobody signed, and this ref's results offered as `main`'s.

To check a run from a clean machine, with `gh` signed in and Python 3:

```bash
gh run download <run id> --repo vac-dev-team/verified-agent-containment --name lab-1 --dir lab
python3 -I tools/lab_evidence.py verify lab --commit <commit> \
  --repo vac-dev-team/verified-agent-containment \
  --signer-workflow vac-dev-team/verified-agent-containment/.github/workflows/lab.yml \
  --source-ref refs/heads/main
```

What the signature shows: these bytes came from `lab.yml` on a GitHub-hosted runner, for that commit and ref. What it does not show:

- **That the suites are honest.** On a pull request the author controls the suites and `lab.yml` itself. Only results signed for `refs/heads/main` say anything about merged code, which is why the verify command above names that ref.
- **That the image is reproducible.** The image id names what ran. The image is built in the job from pinned inputs, and a second build has another id.

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

The deliberate defects exist only in a build with the `sabotage` feature. A default build refuses every `--weakness` except `none` and runs no controls; each results file records the feature set and SHA-256 of the binary behind the honest runs and behind the controls.

`scripts/run-wsl2.sh` wraps the attack-suite steps with kernel and cgroup checks. On Windows, [`scripts/lab/`](../scripts/lab/README.md) runs both suites in a throwaway WSL2 distro.

## Browser showcase

```bash
scripts/build-page.sh     # also compiles the 10 sabotaged kernels from tools/kernel_mutants.py
```

If `rustup target add wasm32-unknown-unknown` is unavailable but `rust-src` is installed, use `BUILD_STD=1`.

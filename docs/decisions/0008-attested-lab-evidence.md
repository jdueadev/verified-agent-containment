# 0008: Lab evidence is authentic when an attestation says so

Status: proposed, 2026-11-23 (#209, track 1). Takes the next free decision number at
merge: #184 and #208 also propose records. No earlier record is edited.

## Context

The maintainer asked that lab output count as authentic when the checks say so,
with no review, and that agents run T2 without them (#209).

Before this change, nothing tied committed lab evidence to the run that made it:
- `lab.yaml` runs the lab on main and uploads an artifact. The `record` job turns
  it into an evidence pull request through `scripts/lab/ci-record.sh` and
  `tools/lab_record.py`.
- CI-9 checked only that some tracked path under `results/` contains the platform's
  commit id.
- `ci-record.sh` asked the maintainer to compare the author, the run and every
  file's SHA-256 by eye.
- `lab_record.py` re-serialised the suites' JSON, so the committed bytes were not
  the run's bytes.
- AGENTS.md INV-1 said: "Whether committed lab output is authentic is review-only."

## Decision

1. **A new `attest` job in `lab.yaml`.** It runs after `lab`, on a push, in the
   main-only `evidence` environment, on a runner that builds and runs no host code.
   - It hashes the artifact into a manifest: committed name → SHA-256.
   - It requests a GitHub OIDC token whose audience is `lab-evidence:` plus the
     manifest's SHA-256.
   - GitHub sets the token's `event_name`, `ref`, `sha`, `workflow_ref`,
     `job_workflow_ref`, `environment` and `repository_id` itself.
2. **`record` commits the files byte for byte**, with `provenance.json`: the
   manifest, the token, the run id and the run attempt. It refuses when the
   manifest does not match the run's files.
3. **CI-10 in `tools/claims_check.py`** (`tools/lab_attest.py`). Every tracked
   `results/ci/lab-<sha>/` must carry a token that:
   - verifies under a key pinned in `ci/github-oidc-jwks.json`;
   - claims a push, to a ref in `ci/lab-attestation.toml`, by `lab.yaml`, in
     `evidence`, from this repository's id, for that directory's commit;
   - has an audience equal to the digest of exactly the committed files.

   CI-10 runs wherever `claims_check` runs, including `release.yml`.
4. **Legacy.** The two directories recorded before this change are listed as
   legacy. `FROZEN_LEGACY` in `tools/lab_attest.py` fixes that set, so the list
   cannot grow.
5. **AGENTS.md.** INV-1 names CI-10 as its enforcer. T2 becomes the attested
   CI lab run, which anyone whose push reaches main starts.

## Why it cannot be forged by a pull request

- A pull request's job gets a token with `event_name=pull_request` and
  `ref=refs/pull/N/merge`, and cannot deploy to `evidence`.
- A token cannot be signed without GitHub's key.
- Changing a committed byte breaks the manifest. Rewriting the manifest to match
  breaks the audience.
- A token from another workflow fails the `workflow_ref` check, and one from
  another repository fails `repository_id`. The repository id survives the move
  to an organization (#207).

## Residual

- **The host code is not proven honest.** The lab job runs main's host code as
  root, so an attestation proves "main's `lab.yaml` at that commit, in that run,
  produced these bytes". It does not prove the host code under test is honest
  (0004). That rests on lane C and the trusted-author decision (#206), and later
  on an external judge (#146).
- **The pinned keys.** `ci/github-oidc-jwks.json` is trusted base (`ci/**`).
  A change to it is a change to the trust root and belongs in its own pull
  request, made only with `refresh-keys`, which reads GitHub's published key
  set.
- **Formal results.** `tla-check.json`, `mutation-check.json` and
  `differential.json` are not attested yet (#209 follow-up). `formal-verdict.json`
  needs Lean in CI first.
- **Root labs outside CI** (WSL2 or a VM) are not attested and stay review-only.

## How to confirm

1. The next push to main runs `lab`, `attest` and `record`. The evidence pull
   request carries `results/ci/lab-<sha>/provenance.json`, and
   `python3 tools/lab_attest.py verify` reports no errors on it.
2. In that pull request, change one byte of `attack-suite.json`. CI-10 fails
   with "differs from the attested manifest".
3. Add a `results/ci/lab-<sha>/` directory by hand. CI-10 fails with "no
   provenance.json".
4. `tools/test_lab_attest.py` breaks each claim check, the byte check, the set
   check and the legacy freeze one at a time, and each is caught.

**Falsifier:** a `results/ci/lab-*` directory that is not legacy passes
`claims_check` without a token from main's `lab.yaml` in `evidence` for its own
commit, or with bytes other than the attested ones.

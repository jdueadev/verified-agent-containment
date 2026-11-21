# 0001: How agents work in this repository

Status: accepted, 2026-11-21. Later decisions add a new record that supersedes
this one; this file is not edited.

## Context

Most changes here are written by AI agents. The repository's product is its
evidence: `claims.toml` and what backs each row. Three things were wanted at
once: changes should merge without the maintainer approving each one, what is
released must be trustworthy, and an agent must not be able to get a change
merged by faking a check.

A six-perspective design review (formal methods, documentation, code quality,
risk, operations, scope) examined the question. Its findings that shaped this
record:

- Claim freshness was attested, not checked: nothing tied a `platforms` entry
  to a lab run that existed.
- The Rust sources are not rustfmt-clean, and reformatting a file a claim
  lists makes its lab evidence stale. A tidy-up is therefore not free.
- A gate that can skip a step silently (TLC was skipped when a tool was
  missing) makes a green result meaningless.

## Options weighed

1. **The maintainer owns every path** (default-deny CODEOWNERS). Safe, and it
   fails closed, but it makes one person the bottleneck for every change.
   Rejected for that reason.
2. **Prose rules only.** Cheap, and unenforceable.
3. **Lanes decided by a check, with ratchets.** Chosen.

## Decision

The maintainer approves changes to the rules. Machines approve changes made
under the rules.

- `ci/lanes.toml` sorts every path into lane A (free), B (evidence-carrying)
  or C (trusted base). A path it does not list is lane C, so the map fails
  closed. `.github/CODEOWNERS` is generated from lane C.
- Ratchets in `tools/policy_check.py` compare a change with its base. Removing
  or rewording a law, mutant, scenario or sabotage control, weakening a claim
  row, or editing a `platforms` entry moves the change to lane C.
- CI-9 in `tools/claims_check.py` requires every passing platform to name a
  commit with committed artifacts under `results/`.
- Tool versions live in `rust-toolchain.toml` and `ci/pins.env` only, and CI
  fails when a tool is missing.
- Lints are limited to ones the code already passes, and formatting is
  switched off by a guard, so introducing them changed no source file.
- A release is a tag for which the `release` workflow is green: every claim
  fresh under `claims_check.py --strict`. Guarantees are made for releases.
- `AGENTS.md` is the single rulebook, written for any agent, with each rule
  naming what enforces it. Design review is described as a practice, not as a
  particular tool.

## What is not enforced yet

- **Identity.** Agents push with the maintainer's own account, so GitHub
  cannot tell them apart and the maintainer cannot approve their own pull
  requests. Until agents have a separate identity with no administration
  rights, the lanes are policy. The `policy` check therefore reports and
  passes unless the repository variable `POLICY_ENFORCE` is `true`.
- **Authenticity of lab results.** CI-9 shows evidence is linked to committed
  files, not that the files are genuine. That rests on review until the lab
  runs in CI and records its own results.
- **Check spoofing.** On a personal-account repository a required check is
  matched by name. A pull request that edits `.github/` could add a job with
  the same name. Code-owner review of `.github/` is the control.
- **The Lean recheck** (`results/formal-verdict.json`) is not regenerated in
  CI, so that file is lane C.

## Repository settings (not versioned by git, so recorded here)

Ruleset `main` at the time of writing: no deletion, no force push, pull
request required with no approving review, required checks `check` and
`evidence-freshness` with "branch must be up to date", no bypass actors.
Auto-merge is off.

To put this decision fully into effect, the maintainer:

1. Creates a bot account or GitHub App for agents, with write access and no
   administration rights.
2. Adds `policy` to the required checks and turns on "require review from
   code owners".
3. Sets the repository variable `POLICY_ENFORCE` to `true`.
4. Enables auto-merge, and requires approval before workflows run for fork
   pull requests.

## Open question

The maintainer decided that, until the lab runs in CI, `main` may carry
honestly stale claims and only releases must be fresh. The ruleset still
requires `evidence-freshness`, which blocks a merge that leaves a claim stale.
This record does not change that setting. Removing `evidence-freshness` from
the required checks puts the decision into effect; keeping it means a change
that stales a host claim waits for a lab run, as `docs/verification.md`
describes.

## Deferred, with what triggers each

- Lab evidence produced by CI: after the agent identity exists.
- A pinned container for `scripts/check.sh`: when local runs of the full gate
  are wanted on Windows.
- Formatting the kernel and wasm crates, then the host: each sweep lands with
  the evidence it invalidates refreshed in the same change.
- `unsafe_op_in_unsafe_fn`: dropped from the first lint set because existing
  host code does not pass it. Enable it with the host sweep.
- A weekly digest of lane B merges: once lane B merges without review.

# 0005: Root judges, immutable spec, and code judged from outside

Status: accepted for its first stage, 2026-11-22 (#125). It amends 0001, 0003
and 0004, which are not edited. #118 and #124 also proposed the number 0005;
they take the next free number.

## Context

Lane C exists so that agents cannot quietly weaken what judges their own work
(0001, 0003, 0004). That purpose stands. The control meant to deliver it, the
maintainer's approval of every lane C head commit, is not delivering it.

Here is the review history since the agent identity went live (#73 onwards).
Each PR's lane comes from `policy_check.py classify` against its own merge base,
and each approval is timed against the head commit it approves.
- **Approvals.** 16 lane C PRs merged, 14 of them with the maintainer's
  approval. The median approval came about 5 minutes after the head commit.
- **Review content.** Zero requests for changes, and zero inline review comments
  from the maintainer.
- **Where defects were found.** CodeRabbit left 36 inline comments, and the
  design and pre-PR reviews found most of the rest. #85 and #86 fixed defects
  in already-approved lane C work.
- **The queue.** 8 lane C PRs were waiting on approval when #125 was filed.

The maintainer asked to stop being the gate for work that checks can judge,
and to spend that time making the codebase more verifiable.

## Options weighed

1. **Judge each change by the base branch's copy of its checks.** This was
   #125's first draft. Rejected by its design review: once agents merge freely,
   the base is agent-written. One PR weakens a checker so that it is strict only
   under test, and the next PR is judged by that checker.
2. **Make a second agent's approval the gate.** Rejected. It shares blind spots
   with the author, the PR text can steer it, and any token on the author's
   machine could forge it (0003, option 2).
3. **Keep the judges with the maintainer, make the spec immutable, and let code
   that a root judge runs from outside merge mechanically.** Chosen.

## Decision

Three parts, introduced in stages. Stage 1 is this record's first pull request.

**Judges are root.** Checkers, the scripts that call them, the mutation and
differential tools, the lab and record path, the workflows, `ci/` and the build
inputs stay with the maintainer, as today. They are small, rarely changed and
high-leverage. Moving them off the human is future work and needs an anchor
copy and a differential test against it (#125, "Later").

**Spec is immutable once it is on `main`.** A test file (`tools/test_*.py`), a
kernel test (`crates/containment-kernel/tests/**`) or a corpus entry
(`ci/corpus/**`) that the base has must be the same at head. Python is compared
by `ast`, Rust by the lexer's code tokens, so reformatting and comments are not
edits; other files are compared as text. Any edit, removal or rename is a ratchet
flag, so the change goes to the maintainer. New spec goes in new files. This
replaces a per-test-body rule, which the design review showed misses helpers,
module constants, `setUp`, decorators (`@skip`, `#[ignore]`), a removed
`#[test]`, `#![cfg(any())]`, `load_tests`, a rebinding after the class, and a
local function that shadows a glob import.

**Judged code merges mechanically once its judge runs outside it.** Later
stages: new spec files leave lane C at stage 2, host code at stage 4, once the
attack harness is a separate program built from the root (stage 3).

### What stage 1 puts in force

- `tools/policy_check.py` keeps its own `RANK` and imports nothing but the lexer,
  so `policy` no longer runs `claims_check.py` inside the gate.
- `policy_check.py invariants --ref REF` checks a commit through git, so `policy`
  can run the invariants from base against the head. `check.sh` still runs them
  on the working tree.
- The spec ratchet, as above.
- `tools/spec_run.py`, the logic of a `spec` check. It runs from a base checkout.
  It takes the spec files and test ids from the base commit, parks head-only spec
  outside the checkout, clears `__pycache__`, and runs each base Python module in
  its own `python3 -I -B` process and each kernel test file as its own
  `cargo test --test`. The verdict is per test id, never an exit code: every id
  the base source defines must be reported as passed, and any failure reported
  counts. A red base run passes only when the owner approved exactly this head.
- `ci/corpus/` and `tools/corpus_run.py`. Each case is a pair of trees that
  `classify` or `invariants` must reject, with an accept twin, run as a black box
  in a new git repository. The run fails on an unknown checker, a missing twin, a
  directory with no case, or no cases.
- The proofs are tests that run on every `check`, so they cannot go stale.
  `tools/test_corpus_run.py` runs the corpus against copies of the gate with one
  rule weakened and against one that rejects everything. `tools/test_spec_run.py`
  covers a module that exits while loading, a skip, a sibling module that patches
  `unittest`, a base copy of a module shadowing the head's, and a stale `.pyc`.
  `tools/test_policy_gate.py` covers every spec edit listed above.

#125 planned two things that stage 1 does differently:
- **No separate attack table.** The attack rows are the tests above, which are
  themselves immutable spec and run on every `check`.
- **No split of tests into pure and repo-state sets.** Under the stricter reading,
  repo-state test files are immutable too, so the split would change nothing in
  stage 1. The cost: an honest change to data that a repo-state test pins, such
  as a lane or a claim's files, now needs the maintainer.

### What the maintainer pushes

Two workflow changes, which the agent identity cannot push:
- a `spec` workflow that runs `spec_run.py base`, `spec_run.py new` and
  `corpus_run.py` from a base checkout, as three fresh jobs, with head code run
  as an unprivileged user;
- a `policy` step that runs `invariants --ref` on the head from base. Its failure
  is not cleared by an approval.

`spec` becomes a required check only after its first green run on `main`'s
corpus, recorded below.

## Proof runs

None yet. The first `spec` run on a throwaway pull request, and the run that
makes it required, are recorded here by URL.

## Residual risks, accepted

- **New spec that looks strict but tests the wrong thing.** Immutability protects
  old spec, not the quality of new spec.
- **A module the base spec imports can still patch its own test process.**
  Per-process isolation keeps a new test away from the base spec, but not the
  code under test away from its own tests. This is why the judges, which are that
  code, stay root.
- **Workflows trusted by permission.** For `pull_request`, GitHub takes the
  workflow from the PR's merge ref. `spec` cannot be skipped only because the
  agent identity has no Workflows permission and forks need the maintainer. If
  either changes, this design breaks.
- **Only `classify` and `invariants` have corpus cases.** The other checkers are
  judged by their unit tests until they get cases of their own.

## Consequences

- Editing an existing test file now always needs the maintainer, even when it is
  only made stricter. Six of the last eighteen commits that touched tests did
  this.
- Nothing leaves lane C in stage 1. The relief comes at stage 2 (new spec files)
  and stage 4 (host code).

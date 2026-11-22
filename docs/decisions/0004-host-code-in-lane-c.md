# 0004: Host containment code and its build inputs are lane C

Status: accepted, 2026-11-22 (#83). Changes the lane map that 0001 set up.
0001 is not edited.

## Context

Under 0001, host source was lane B. It merged on green checks with no
reviewer. Its lab evidence was refreshed separately, and after 0002 that
happens after the merge. The maintainer judged that too loose for the code
that does the containment. #53 (PR #82) therefore puts the root lab in CI as
a `lab` check.

The design review of that lab found a limit that a CI lab cannot remove. The
code under test can fool it. A change to `main.rs` can catch `attack-suite`
and exit 0. The controller can detect the harness. A `build.rs` runs on the
runner with passwordless sudo. A required `lab` check therefore stops honest
mistakes, not an author who means to deceive it.

## Options weighed

1. **Lab gate only.** Rejected. A deliberately weakened change passes and
   merges automatically.
2. **Only the files host lab claims list in lane C.** That is every host
   source file but one (`differential.rs`), so it comes to the same thing,
   with a longer map to keep in step.
3. **The whole host crate and the build inputs in lane C, plus the lab
   gate.** Chosen.

## Decision

Lane C gains:
- `crates/containment-host/**`;
- the inputs that can change the shipped binary without touching host
  source: `Cargo.toml`, `Cargo.lock`, `.cargo/**` and `rust-toolchain.toml`;
- the kernel's `Cargo.toml` and `build.rs`. A build script or a new
  dependency runs code during the host build.

Kernel and wasm source stay lane B. Their behaviour is checked mechanically
by the laws, the mutants and the differential test. A CLI crate split out of
the host (#42) would also be lane B, which is that issue's purpose.

The `lab` check stays. It catches honest regressions before the maintainer
reads the PR. The maintainer's review is the control against a deceptive
change.

## Consequences

- Every host PR, and every dependency or toolchain bump, waits for the
  maintainer's approval.
- #42 becomes more valuable. UX work moved out of the host crate goes back to
  merging without the maintainer.
- `tools/test_policy_check.py` pins the new lanes. Moving a path into a
  stricter lane is a deliberate change to an existing assertion, and the PR
  says so.

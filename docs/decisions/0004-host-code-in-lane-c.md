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

- the wasm crate's `Cargo.toml` and `build.rs`. The wasm build runs in
  `check` before the wasm differential judges it. `check.sh` and
  `build-wasm.sh` now build with `--locked`.

Kernel and wasm source stay lane B. Their decisions are checked
mechanically by the laws, the mutants and the differential test. Those check
decisions, not side effects, so `policy_check.py invariants` now also checks
the kernel's purity on every commit. The crate root must keep `#![no_std]`
and `#![forbid(unsafe_code)]`, and no kernel source may use `std` or
`alloc`, `extern crate`, `include!`/`include_str!`/`include_bytes!`,
`env!`/`option_env!` or `#[path]`. Without this check, deleting `no_std` in a
lane B change would let the kernel do I/O inside the host binary.

A CLI crate split out of the host (#42) would also be lane B, which is that
issue's purpose.

The `lab` check stays. It catches honest regressions before the maintainer
reads the PR. The maintainer's review is the control against a deceptive
change.

## Residual risk, accepted

A coordinated change to `kernel.bend`, the kernel and the wasm crate that
alters a decision only on a rare input can pass the laws, the mutants and the
differential test. The differential uses a fixed seed and 5,000 cases. Such a
change stays pure, so it can only change a decision the laws do not pin.
Moving kernel source to lane C would close this, at the cost of review for
every kernel change.

## Consequences

- Every host PR, and every dependency or toolchain bump, waits for the
  maintainer's approval.
- #42 becomes more valuable. UX work moved out of the host crate goes back to
  merging without the maintainer.
- `tools/test_policy_check.py` pins the new lanes. Moving a path into a
  stricter lane is a deliberate change to an existing assertion, and the PR
  says so.

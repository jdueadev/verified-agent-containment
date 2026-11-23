# How the checks decide "passed": the kernel differential (R-DIFF-01)

The proofs are about the Bend model. The kernel that ships is Rust, and the one
in the browser page is the same Rust compiled to WebAssembly. This recipe shows
how `scripts/check.sh` decides that they agree, and how it shows that the
check would notice if they did not. It is a checker recipe: it explains the
machinery and links to it, and copies none of it.

## Guarantee

<!-- cookbook:begin claim R-DIFF-01 -->
> **R-DIFF-01** · layer `rust-kernel` · Generated from [`claims.toml`](../../claims.toml); claims.toml wins. Status and evidence: [`docs/claims.md`](../claims.md).
>
> **Statement:** The Rust and WebAssembly kernels agree with the Bend model on generated traces, including stale timestamps and resets.
>
> **Limits:** Generated tests, not a proof. Values stay below 2^53.
>
> **Falsifier:** Any transition where Rust or WebAssembly differs from Bend
<!-- cookbook:end claim R-DIFF-01 -->

## The check

Three steps of [`scripts/check.sh`](../../scripts/check.sh), in order:

1. **Generate traces from Rust.** `containment-lab differential-cases 5000 24301`
   (the `differential-cases` command in
   [`crates/containment-host/src/differential.rs`](../../crates/containment-host/src/differential.rs))
   drives the Rust kernel through 5000 generated event sequences from a fixed
   seed, including stale timestamps and resets, and writes every step's
   result: mode, deadlines, clock, reset counter, action plan, and one access
   decision.
2. **Replay them through Bend.** [`tools/differential.mjs`](../../tools/differential.mjs)
   loads the Bend kernel compiled to JavaScript and replays each sequence. Any
   step where a field differs stops the check with the mismatch.
3. **Replay them through WebAssembly.** [`tools/wasm_check.mjs`](../../tools/wasm_check.mjs)
   does the same with the release wasm build.

"Passed" means zero mismatches on every transition. The counts are written to
[`results/differential.json`](../../results/differential.json) and
[`results/wasm-differential.json`](../../results/wasm-differential.json). Those
files are output that `check` regenerates on every run, not lab artifacts.

## How the claim is judged

[`tools/claims_check.py`](../../tools/claims_check.py), the last step of
`scripts/check.sh`, turns those files into the claim's row in
[`docs/claims.md`](../claims.md). For each item in the claim's `evidence`:

- `diff:rust-bend` and `diff:rust-wasm` count as caught only if the mismatch
  count in each file is the integer 0, `results/differential.json` records at
  least 5000 sequences and at least as many transitions (both integers), and
  `results/wasm-differential.json` records that same integer transition count;
- each `rust-mutant:NAME` counts only if `results/mutation-check.json` records
  that mutant as rejected.

A `tested` claim needs at least one such falsifier, and every one it cites must
hold (rule CI-3 in the checker's header). Otherwise `check` fails. A present
differential file that misses those counts is an error from `claims_check.py`
even when `--strict` is left off. Meeting those counts is enough for the files
to count as caught, including when no run wrote them. The checker also requires
every Rust mutant in the repository to be cited by some claim (CI-2), so a
mutant cannot sit unused.

## Watch the control

A differential that never fails proves nothing, so the mutation check
([`tools/mutation_check.py`](../../tools/mutation_check.py)) breaks the Rust
kernel on purpose. For each entry of `RUST_MUTANTS` in
[`tools/kernel_mutants.py`](../../tools/kernel_mutants.py), it applies a small
edit, matched by tokens, to a scratch copy of the Rust kernel, rebuilds, generates 2000
traces, and replays them through the Bend kernel. The mutant counts as
rejected only if the replay finds a mismatch. Every Rust mutant R-DIFF-01
cites must be rejected, or `check` fails.

For example, `lease_off_by_one` changes the expiry check in the Rust kernel's
`settle` from "strictly before the deadline" to "at or before". A step at
exactly the deadline then does not start the stop: Run and Restrict stay put,
and Freeze does not escalate to Kill. The Bend model does start it, so the
replay stops at the first such step, where the mode and the action plan
differ.

The results go to
[`results/mutation-check.json`](../../results/mutation-check.json), again
regenerated output. Read the `rust` entries at the commit you are looking at.

## Reproduce

These are the commands `scripts/check.sh` runs, without its `tee` into
`results/`. The commands need no root; the Bend install in
[`docs/verification.md`](../verification.md) uses `sudo`, or install it under
your home directory.

```bash
mkdir -p target/generated
bend formal/kernel.bend -o target/generated/kernel.mjs
cargo build -q --locked -p containment-host
target/debug/containment-lab differential-cases 5000 24301 > target/generated/differential.jsonl
bun tools/differential.mjs target/generated/kernel.mjs target/generated/differential.jsonl
scripts/build-wasm.sh
node tools/wasm_check.mjs target/wasm32-unknown-unknown/release/containment_wasm.wasm target/generated/differential.jsonl
python3 tools/mutation_check.py target/generated/kernel.mjs target/mutation-check.json  # every mutant; slow
```

The last line writes to `target/` so that it leaves the committed
`results/mutation-check.json` alone.

## What this does not prove

- **Generated tests, not a proof.** The claim's own `limits` say so. 5000
  sequences from one seed cover a lot of the state space, but not all of it.
- **The mutants show the check has teeth, not that it is complete.** A
  rejected mutant shows the differential catches that defect. A Rust bug that
  the generator never reaches, or that no mutant resembles, could still pass.
- **Agreement is not correctness.** If Rust and Bend were wrong in the same
  way, the differential would pass. The Bend side is what the proofs in
  `formal/PROOF.bend` cover; see the K-* claims and
  [the K-MONO-01 recipe](k-mono-01.md).
- **Only the decision kernel.** Whether the host carries out the kernel's plan
  is a set of host claims, for example [H-ACT-01](h-act-01.md).

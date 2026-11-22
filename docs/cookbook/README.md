# Proof cookbook

Short recipe pages, one per guarantee. Each one shows what the guarantee is, the
law that proves it, a deliberate defect that the law rejects, and the commands
to watch that happen yourself. The style follows the
[Rust Cookbook](https://rust-lang-nursery.github.io/rust-cookbook/).

| Recipe | Claim |
| --- | --- |
| [Containment only tightens](k-mono-01.md) | K-MONO-01 |
| [Unconfirmed means stopped](h-act-01.md) (host) | H-ACT-01 |
| [How the checks decide "passed": the kernel differential](r-diff-01.md) (checker) | R-DIFF-01 |
| [What the lab measures: losing the monitor](h-lease-01.md) (lab) | H-LEASE-01 |

## Recipe template

Every recipe has these sections, in this order:

1. **Guarantee.** Name the claim id and add a `claim` region (below). Do not
   restate or reword the claim's `statement` or `falsifier` in prose: the
   generated block copies them, and the claim row is the one source of truth.
2. **The law.** Add a `law` region naming the laws to quote. They are quoted
   exactly from `formal/LAWS.bend` with their line numbers.
3. **Break it.** Pick one mutant from `tools/kernel_mutants.py` that the claim
   lists and add a `mutant` region for its diff. Label any proof output by where
   it came from: a hand run (say when), or the regenerated
   `results/mutation-check.json`. Never show output that no run produced.
4. **Run it.** One snippet (below) that passes on the real kernels and fails on
   that mutant, shown with a `snippet` region.
5. **Reproduce.** List only commands that need no root and that `scripts/check.sh`
   already runs. Break things in a scratch copy, never in the working tree.
   Leave lab suites out; link to [`docs/verification.md`](../verification.md).
6. **What this does not prove.** Give the claim's layer and limits, and name the
   claims that cover what this one does not.

## Generated regions

[`tools/cookbook_check.py`](../../tools/cookbook_check.py) fills these in.
A region is two marker lines, each alone on its line, for example
`<!-- cookbook:begin law tighten_only -->` and then
`<!-- cookbook:end law tighten_only -->`. Write the two lines and run
`python3 tools/cookbook_check.py --write`; never edit between them by hand.
The kinds are:

- `claim ID`: the claim's id, layer, statement, limits and falsifier, copied
  verbatim from `claims.toml`. It shows no status, because that depends on the
  evidence at the commit you are reading; `docs/claims.md` has it.
- `law NAME...`: the laws, quoted exactly from `formal/LAWS.bend` with a link to
  their lines. Laws that sit next to each other in the file share one block.
- `mutant NAME`: the Bend mutant's edit as a diff against `formal/kernel.bend`.
- `snippet ID`: a snippet's source and the output of running it.

Every recipe has exactly one `claim` region. A recipe for a `bend-kernel` claim
also needs at least one `law`, `mutant` and `snippet` region, so a recipe
cannot drop all of its checked blocks. That is a floor, not a full guard: if a
recipe has two `law` regions and one loses its markers, the text left behind
is no longer compared, and only review catches it. Every law and mutant a
recipe shows must be cited in that claim's evidence. A recipe must be a
regular file, not a symlink, and no claim may use a recipe as `doc:` evidence. `scripts/check.sh` runs the
checker without `--write`, and fails if any region differs from what it would
generate. The prose around the regions is checked by review only.

## Snippets

A snippet is a JSON file in [`snippets/`](snippets/): a kernel configuration, a
start state, and up to 64 steps. Each step is an event and the results it must
produce (`mode`, `deadline`, `clock`, `counter`, `actions`, and `access`
checks). Numbers are whole numbers from 0 to 2^47 − 1. The Bend kernel
compiled to JavaScript accepts up to 2^48 − 1, and this cap keeps the sum of
two inputs, such as a time plus a lease, under that limit. `breaks` names a Bend mutant the claim cites (`mutant:NAME`), and
`teeth` names the step and field that mutant must get wrong. The schema is
strict: an unknown key or value is an error, so a typo cannot turn an
expectation into a no-op. The one interpreter is
[`tools/snippet_run.mjs`](../../tools/snippet_run.mjs).

On every `scripts/check.sh` run, each snippet must do the following. If node,
bend or the built kernels are missing, a local run prints
`SKIPPED: cookbook snippets` and checks only the regions; that is tier T0. In
CI a missing tool is an error.

- pass on the Bend kernel compiled to JavaScript;
- pass on the Rust kernel compiled to WebAssembly, observing the same values on
  every step;
- fail on its mutant, at its `teeth` expectation. A run that throws does not
  count.

To add one, write `snippets/<id>.json` (the `id` is the file name), add a
`snippet` region to its recipe, run `--write`, and review the diff. Write the
expectations from the law, not from the output: `--write` records the output
under the snippet, but it never turns output into an expectation.

**Snippets are examples, not evidence.** No claim cites them, and the checker
rejects `doc:` evidence that points into this folder. They still assert things,
so treat them like tests: adding a snippet is a routine change, but removing or
loosening an existing expectation or `teeth` is a heavy change in the sense of
[`AGENTS.md`](../../AGENTS.md) and needs an issue first.

## Host, checker and lab recipes

Guarantees outside the Bend kernel follow the same template with three
changes:

- **No law.** Instead, a section that says where the guarantee is enforced or
  checked, naming the file and function by link. Do not copy host, checker or
  lab code onto the page.
- **Watch the control** replaces **Break it**. Name the deliberate defect,
  behind `cfg(feature = "sabotage")` for host code or in `RUST_MUTANTS` for the
  Rust kernel, and the scenario or check that must catch it. Quote lab results
  only from a committed file under `results/`, say which run produced them, and
  never show them as live.
- **No snippet.** Only the `claim` region is required; host behaviour cannot
  run in a browser or without root.
- **Reproduce** gives no command that needs root. Lab runs belong in a
  throwaway machine (INV-11 in [`AGENTS.md`](../../AGENTS.md)), so link to
  [`docs/verification.md`](../verification.md) instead.

Recipes are documentation (lane A). They must not edit any file a claim lists,
so nothing here can make evidence stale. The checker itself is trusted base
(lane C).

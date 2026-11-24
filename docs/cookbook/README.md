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

Every recipe has these five sections, in this order:

1. **Guarantee.** Name the claim id and link to [`claims.toml`](../../claims.toml)
   and [`docs/claims.md`](../claims.md). Do not restate or reword the claim's
   `statement` or `falsifier`: the claim row is the one source of truth.
2. **The law.** Quote the law exactly as it stands in `formal/LAWS.bend`, and link
   to the lines quoted.
3. **Break it.** Pick one mutant from `tools/kernel_mutants.py` that the claim
   lists, show the edit as a diff, and show the proof failure. Label any output
   by where it came from: a hand run (say when), or the regenerated
   `results/mutation-check.json`. Never show output that no run produced.
4. **Reproduce.** List only commands that need no root and that `scripts/check.sh`
   already runs. Break things in a scratch copy, never in the working tree.
   Leave lab suites out; link to [`docs/verification.md`](../verification.md).
5. **What this does not prove.** Give the claim's layer and limits, and name the
   claims that cover what this one does not.

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
- **Reproduce** gives no command that needs root. Lab runs belong in a
  throwaway machine (LAB-THROWAWAY in [`AGENTS.md`](../../AGENTS.md)), so link to
  [`docs/verification.md`](../verification.md) instead.

Recipes are documentation (lane A). They must not edit any file a claim lists,
so nothing here can make evidence stale. Nothing checks the quoted text
mechanically yet, so a reviewer compares it with its source.

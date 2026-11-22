# Proof cookbook

Short recipe pages, one per guarantee. Each one shows what the guarantee is, the
law that proves it, a deliberate defect that the law rejects, and the commands
to watch that happen yourself. The style follows the
[Rust Cookbook](https://rust-lang-nursery.github.io/rust-cookbook/).

| Recipe | Claim |
| --- | --- |
| [Containment only tightens](k-mono-01.md) | K-MONO-01 |

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

Recipes are documentation (lane A). They must not edit any file a claim lists,
so nothing here can make evidence stale. Nothing checks the quoted text
mechanically yet, so a reviewer compares it with its source.

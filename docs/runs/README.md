# Run logs

`2026-11-25-phase2-night.tsv` is the decision log of the unattended run that took Phase 2 from the first pull request through the first outside eval, the break-to-fix loop and the Kani proof (pull requests 250 to 260). One row per decision: when, the phase, what was decided, why, the evidence, and the result.

- It is append-only. A wrong call is corrected by a later row, never edited. The rows with phase `review` were added after a second reader went through the log; several of them correct earlier rows.
- Evidence that names a commit or a pull request can be followed in this repository. Evidence under `SCRATCH/` was in the run's scratch directory on a disposable machine and is gone; where it mattered it was copied to `evals/agentdojo/runs/`.
- It is a record, not a claim. Nothing in `claims.toml` rests on it.

Read it as a table with `column -s$'\t' -t docs/runs/2026-11-25-phase2-night.tsv | less -S`.

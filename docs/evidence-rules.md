# Evidence rules

What a claim's evidence must satisfy. Before the cut at tag `pre-factory`, `tools/claims_check.py` and `tools/results_ratchet.py` enforced these on every commit. Nothing enforces them now. They are kept as the list to work from when the claims are reset and re-earned.

## A claim

1. Every law a claim cites exists, and the recorded proof verdict matches the Bend sources as they are.
2. Every law, mutant and sabotage control is cited by at least one claim.
3. Each status has the evidence that status needs: a proved claim cites a law, a tested claim cites a scenario and a control that was caught.
4. A claim is stale when a file it covers has changed since the commit its evidence was recorded on, per platform.
5. No claim is stronger than the weakest claim it depends on.
6. Every claim id cited in the design spec exists.
7. Every host source file is covered by a claim.
8. Honest runs and sabotage controls come from different, full builds: the honest runs from the default build, the controls from a build with the `sabotage` feature.
9. Every platform marked passing has its results committed.
10. Lab results produced in CI carry an attestation covering every byte.

## Results, from one run to the next

- No TLC configuration stops behaving as expected, disappears, or explores fewer states.
- No mutant stops being rejected or witnessed, and no law loses its last killing mutant. Every law is broken by at least one mutant.
- No differential runs fewer cases, drops below its floor, or finds a mismatch.
- The formal verdict never stops being ALL PROOFS CHECK.
- No lab scenario or sabotage control is lost, the timed repeat count never drops, and no cgroup-limit waiver appears.

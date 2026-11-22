<!-- Read AGENTS.md first. Keep the headings; write "none" where nothing applies. -->

Closes #

## What changed and why

## Lane
<!-- A, B or C, from ci/lanes.toml. The policy check reports the real one. -->

## Process tier
<!-- Heavy or routine, as AGENTS.md (Workflow, step 1) defines them. Heavy needs an issue and a design review first. -->
- [ ] Touches the rules or the gate (`AGENTS.md`, `CLAUDE.md`, `ci/`, `.github/`, `docs/decisions/`, `tools/policy_check.py`)
- [ ] Touches what decides "passed" (`scripts/check.sh`, `tools/mutation_check.py`, kernel law tests, harness, live suite, red-team runner, lab results)
- [ ] Crosses a trust boundary (kernel events, controller, gateway, reset, sandbox isolation, claims schema)
- [ ] Removes, narrows or loosens a check, widens what a checker accepts, or modifies or deletes an existing test assertion

Any box ticked: heavy. None ticked: say why the change does not widen what any checker accepts.

## Claims affected
<!-- Claim ids from claims.toml. Paste the stale ids exactly as `python3 tools/claims_check.py --affected origin/main` prints them. A change that stales a claim may merge; the lab then runs on the resulting commit on main, and its evidence lands in a follow-up PR (AGENTS.md). -->

## Invariants touched
<!-- INV-n from AGENTS.md, and how the change keeps each one. -->

## Checked
<!-- T0, T1 or T2 as AGENTS.md defines them, and the checks you ran. -->

## Not run
<!-- Every check you skipped, and why. -->

## Evidence
- [ ] I did not edit `results/`, a `platforms` entry or `docs/claims.md` by hand
- [ ] I did not remove or reword a law, mutant, scenario, sabotage control, claim statement or falsifier

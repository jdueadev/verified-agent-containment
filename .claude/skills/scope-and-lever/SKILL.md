---
name: scope-and-lever
description: Worked form of the Scope and levers section in AGENTS.md. Read it when planning a change in this repository. AGENTS.md wins if this file disagrees.
disable-model-invocation: true
---

# Scope and levers

AGENTS.md, section "Scope and levers", is the rule. This file is the worked
form for Claude Code. If the two disagree, AGENTS.md wins, including INV-1
through INV-11 and workflow step 5.

The ideas were read from pstack 0.15.46, commit
`0b46ec399d55f2829e88822998f53b84944837d3` of `cursor/plugins`, in
`principle-laziness-protocol`, `principle-subtract-before-you-add`,
`principle-sequence-verifiable-units`, `principle-build-the-lever` and
`principle-prove-it-works`. Those files are not copied here.
`docs/decisions/0007-scope-and-lever.md` records why, and which upstream
instructions were left out.

## Apply the section

1. **Smallest change.** State the goal in one sentence. The diff contains
   only what that sentence needs. A deletion is in the diff only when the
   goal requires it and INV-2, INV-7 and INV-9 still hold. AGENTS.md,
   "Smallest change".
2. **Lane and weight before the first push.** Commit the change, then run
   `python3 tools/policy_check.py classify --base origin/main`. The command
   reads the commits, so an uncommitted edit is not in the lane it reports.
   Read the lane and any ratchet. Read workflow step 1 and say whether the
   change is heavy. AGENTS.md, "Lane and weight before the first push".
3. **One topic, one pull request.** Workflow step 3. The units below stay in
   that pull request. `main` squash-merges it. AGENTS.md, "One topic, one
   pull request".
4. **Verifiable units.** Each unit ends in a check you can rerun. That check
   is green before the next unit starts. AGENTS.md, "Verifiable units".
5. **Build the lever.** For work beyond a couple of obvious edits, add a
   small rerunnable script, codemod, generator, or check that does the work
   or proves it, and commit it. A new skill is a lane C change of its own
   under INV-3, not the lever. AGENTS.md, "Build the lever".
6. **Prove the result.** Run the check on the artifact. Name the tier from
   What "checked" means. A failing check stays failed. Changing the check so
   that it passes is INV-2, and the maintainer decides. AGENTS.md, "Prove
   the result".

Workflow step 5 and INV-1 already forbid an override merge, an `--admin`
merge, a ruleset bypass, a change to `POLICY_ENFORCE`, any edit under
`results/`, and any edit to a `platforms` entry. INV-1 forbids a hand edit
of `docs/claims.md`. Regenerate that file with
`python3 tools/claims_check.py --write`. This skill grants none of those.

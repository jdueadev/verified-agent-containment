# 0007: Release-gated CI, and a trust split between maintainers and outside collaborators

Status: proposed, 2026-11-23 (#206). Takes the next free decision number at
merge: #184 also proposes a 0007, and whichever merges second is renumbered.
Changes the merge path that 0001, 0002, 0003 and 0005 describe. No earlier
record is edited. The organization move is recorded separately (#207).

Part 1, the pull request that adds this record, lands the trust split
(decision 1), approval freshness in `policy.yml`, and the matching
`AGENTS.md` text. Part 2 lands the staging branch, the release-candidate
workflow and the trigger changes (decisions 2 to 8), and the `AGENTS.md`
text that describes them. Until part 2, `AGENTS.md` describes the CI that
exists.

## Context

Between 2026-11-23 09:03 and 15:02 UTC the repository started 100 workflow
runs. `gate` made 65 of them: 35 from its `*/10` cron and 30 from
`workflow_run` fan-out on `check`, `spec`, `policy`, `policy-refresh` and
`gate-events`. `check`, `spec` and `lab` ran on every pull request push, and
`check`, `lab` and `digest` ran again on every push to `main`. At that rate the
repository starts about 12,000 runs a month for a project with one maintainer.

**Premise, corrected for the record.** The repository is public, and GitHub's
usage API reported 0 billable ms for every sampled run (`gate` schedule,
`check`, `spec`, `lab`). Standard runners are free for public repositories, and
the repository stays public after the move (organization-move record). The cost is run volume, not
money: the free plan's 20-concurrent-job cap, queues, red and yellow noise on
every pull request, and blocked merges. On 2026-11-23 the maintainer turned
Actions off for the repository as a stop gap. With Actions off, the required
checks `check` and `policy` never report, so nothing can merge without the
ruleset bypass.

**Trust model, changed.** 0003 and 0006 treat the coding agent as the
adversary inside the repository. The maintainer now treats the organization's
owners and its agents as good actors, and keeps the lane C gate only for
outside collaborators. That is a choice about who may change the trusted base
(INV-3). It does not change what the product claims about containing an agent
at run time.

**Council review.** The maintainer asked for a multi-angle review: invariants,
attack and testing (AGENTS.md, Workflow step 2). A six-member review (Operator,
Skeptic, Prover, Architect, Strategist, Guardian) recommended a different
design. That design kept `check`, `spec` and `policy` on every pull request,
and added a merge queue after the move. It rejected both a policy-only
pull request check and a staging branch. The maintainer overruled it. The
council's objections are recorded below as accepted risks, and its design as
the rejected alternative.

## Decision

1. **Trusted contributors.** `ci/lanes.toml` gains a `trusted` list:
   `@jdueadev`, `@jdueadev-agent`, `@vac-agent-app[bot]` and
   `@vac-lab-runner[bot]`. Lane C still
   classifies changes, and `policy` still reports the lane. For an author on
   the list, though, lane C needs no approval and no ratchet blocks the merge:
   the policy job reports, but does not fail. For any other author (outside
   collaborators and forks), lane C needs the maintainer's approval of the
   head commit, as before. The list is a reviewed file read from `main`, not
   GitHub's author association, so it works the same before and after the
   organization move.

2. **One cheap job per pull request.** Only `policy` runs on a pull request:
   lanes, the static ratchets and the trust check. It runs no build, no tests,
   no spec, no lab and no head code, so it finishes in about a minute.
   `policy-refresh` stays, so that a review re-runs it.

3. **A staging branch carries the batch.** Pull requests target `staging`,
   which is squash-only with linear history and requires `policy`. Each merged
   pull request is one squash commit on `staging`. `policy` always reads
   `ci/lanes.toml`, the ratchets and the trusted list from `main`, never from
   `staging`, so a batch-mate cannot rewrite the rules for the pull requests
   after it.

4. **The full gate runs once per batch.** The maintainer cuts a release
   candidate by tagging the `staging` tip `vX.Y-rcN`. The release-candidate
   workflow runs `check`, `spec` (with `main` as the base), the lab, and the
   gate attestation against that one commit.

5. **Promotion is a fast-forward.** If the release candidate passes, `main` is
   fast-forwarded to exactly that commit. No squash and no rebase happen, so
   the lab ran on the same SHA that `main` then carries, and 0002's evidence
   binding (`platforms.commit` on `main`, CI-4, CI-9) holds unchanged. The
   evidence pull request then lands on `staging` and is promoted the same way,
   and `v*` is tagged on it.

6. **Reverts.** If a release candidate fails, the bad pull request is
   identified by bisecting its squash commits on `staging`, reverted on
   `staging` by a new pull request, and a new candidate is cut. `main` never
   carries an unpassed commit.

7. **Triggers removed.** Removed: the `gate` `*/10` cron and its
   `workflow_run` fan-out, `gate-events`, every `push: main` trigger, the
   per-pull-request `check`, `spec` and `lab`, and the per-push `digest`.
   `digest` runs weekly and reports the run count and the list of enabled
   workflows. Over 200 runs in a week opens an issue.

8. **Bootstrap without a bypass where possible.** First, disable `gate`,
   `gate-events`, `lab`, `check`, `spec` and `digest` one workflow at a time.
   Then re-enable Actions, so `policy` reports, and remove `check` from the
   required contexts on `main`. The maintainer pushes the workflow change (the
   agent has no Workflows permission today) and merges it on `policy`. Any
   bypass use is logged in this record with its SHA, actor and reason.

## Settings this decision needs

- Ruleset `main`: "require review from code owners" off. Otherwise GitHub
  blocks a trusted author's lane C pull request whatever `policy` says.
  Outside collaborators stay gated by `policy --enforce`.
- The agent identities get the Workflows permission. A trusted agent may
  change `.github/workflows/`.

- Branch `staging`: squash-only, linear history, required context `policy`,
  "branch must be up to date". No deletion, no force push.
- Branch `main`: no pull request merges. Only the promote actor may push, and
  only a fast-forward. The promote actor is the maintainer, or a release
  workflow using an App whose only permission is that push. Linear history, no
  deletion, no force push.
- Tags `v*` and `v*-rc*`: only the maintainer may create them, because a tag
  starts the workflows that hold the lab and evidence secrets.

"Branch must be up to date" on `staging` and fast-forward-only on `main` are
load-bearing. Turning either off breaks the guarantee that `main` holds only
tested commits.

## Accepted risks

These are the council's objections. The maintainer accepts them.

- **Trusted authors are not checked at merge.** A trusted author can reword a
  claim, delete a mutant, loosen a scenario or edit an existing test, and it
  merges to `staging` on a passing `policy`. INV-2 and INV-3 become review
  and release-time rules for trusted authors. The release candidate gate and
  the promotion diff are the only checks.
- **The spec ratchet can freeze an unrun test.** A new `tools/test_*.py` or
  kernel law merges to `staging` without running. If it fails, every later
  candidate's `spec` is red until it is fixed or reverted on `staging`.
- **Lane C on `staging` judges its batch-mates.** The candidate's `check` and
  `spec` run the workflows and checkers that `staging` carries at that commit,
  not `main`'s. A batch that changes a checker is judged by the changed
  checker.
- **A standing push to `main`.** The promote actor can move `main`. In an
  organization that actor must be one person or one narrowly scoped App, never
  the "Repository admin" role (see the organization-move record).
- **Reverts cascade.** Later pull requests in a batch may depend on a bad one,
  and a revert of a lane B change is itself a change to claims and evidence.
- **0006 is narrowed for trusted authors.** Shared `.claude/` changes by a
  trusted author merge without review, and they run on the next contributor's
  machine. The 0006 advice still applies: review a branch that touches agent
  configuration by its diff, or open it with
  `claude --bare --setting-sources user`.

## Rejected alternative: the council's design

The council kept `check`, `spec` and `policy` required on every pull request
into `main`, and made `spec` required for the first time. It ran the lab only
on a release-candidate tag of a `main` commit, removed the same noisy triggers
(about 400 runs a day down to about 20-25), and added a GitHub merge queue
after the move only if the volume was still a problem. It rejected the staging
branch: the branch becomes a judging base (the attack 0005 rejected) and needs
a standing push. It rejected policy-only checks: the INV-2 ratchet would freeze
tests that never ran. The full design is in the review recorded on #206.

## Consequences

- `AGENTS.md` changes in the same pull request:
  - Lanes: lane C approval applies to authors not on the `trusted` list.
  - "When your change makes a claim stale": the lab runs at the next release
    candidate, not after every merge.
  - Workflow step 3: pull requests target `staging`.
  - Workflow step 5: auto-merge on `policy`.
  - The tiers: "the `check` workflow is the gate" becomes "the release
    candidate is the gate".
- `docs/verification.md` and the README describe the candidate and promotion
  flow.
- `tools/policy_check.py` reads `trusted` from `ci/lanes.toml`, with tests in
  a new test file. Existing tests stay unchanged (INV-2).
- `gate.yml`, `gate_check.py` and the OIDC attestation path stay in the
  repository. They are bound to the release-candidate workflow instead of
  `workflow_run`, in new code with new tests, and are never loosened to
  accept both.
- Claims tied to the lab are fresh at each release and stale between them, as
  0002 already allows.

## Process for trusted authors

Issue-first and the design review (AGENTS.md, Workflow steps 1 and 2) apply
only to authors not on the `trusted` list. A trusted author goes straight to a
pull request whose description states the behaviour, the claims affected and
the falsifier.

## Open questions for the maintainer

1. Is the promote actor the maintainer by hand, or a release workflow with a
   push-only App?
2. Do outside collaborators' pull requests target `staging`, or `main` through
   the old per-pull-request gate?

## How to confirm

1. Pull requests by trusted and untrusted authors that touch `ci/lanes.toml`:
   the trusted one merges on `policy`, and the untrusted one waits for the
   maintainer's approval of its head.
2. An untrusted pull request that edits an existing test is lane C and does
   not merge without approval.
3. A candidate whose batch includes a failing new test fails `spec`, and
   `main` does not move.
4. After a passing candidate, `main` HEAD equals the candidate tag's SHA:
   `git rev-parse main` = `git rev-parse vX.Y-rcN^{commit}`.
5. `claims_check.py --strict` passes on the promoted evidence commit, and a
   `platforms` entry that names a `staging`-only SHA fails it.
6. A week with the new triggers starts fewer than 200 runs.

**Falsifier:** `main` carries a commit that no passing release candidate
tested; a lab result names a SHA that never reaches `main`; or an untrusted
author's lane C change merges without the maintainer's approval of its head.

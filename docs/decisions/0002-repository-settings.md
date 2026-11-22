# 0002: Repository settings for agent merges, and stale claims on main

Status: accepted, 2026-11-22 (#52). Records the GitHub settings that put 0001
and 0003 into effect, and settles 0001's open question. GitHub settings are
not versioned by git, so this record is the history. A change to a setting
adds a new record. This file is not edited.

## Context

#52 set out to make lanes A and B merge without the maintainer while lane C
stays blocked, at first without a separate identity for agents. #70 (0003)
then brought that identity forward. Throwaway pull requests #73–#75 and #78
showed which settings work together. Their results are on #70.

0001 left one question open. The maintainer had decided that `main` may carry
honestly stale claims between releases, but the ruleset still required
`evidence-freshness`. The new requirement for squash-only merges forces the
answer. A lab run on a PR branch commit names a commit that never reaches
`main`, so it can no longer be evidence for `main`. The lab has to run after
the merge, which a required freshness check would block.

## Decision

- **Claim freshness is enforced at release, not at merge.** `evidence-freshness`
  still runs on Ready PRs and on `main`, and reports what is stale. It is not
  a required check.
- **The lab runs on `main` after a merge.** The maintainer runs it on the
  squashed commit, and the results and the `platforms` update land in a
  follow-up PR. `AGENTS.md` ("When your change makes a claim stale") and
  `docs/verification.md` ("Pull request workflow") describe the flow.
- **`main` is squash-only with linear history.** Each merge is one commit
  whose message is the PR's title and body. The body carries the PR's lane,
  claims, invariants and tier, which makes `main` easy to audit.

## Settings, as read through the API on 2026-11-22 (UTC)

The agent identity read these. Items it cannot read are marked.

Repository:
- Auto-merge: on. Squash merging only (merge commits and rebase off).
  Squash commit title and message: the PR's title and body. Branches are
  deleted after merge. "Update branch": off.
- Variable `POLICY_ENFORCE`: `true`.

Ruleset `main` (active):
- No deletion. No force push. Linear history.
- Pull request required:
  - 0 approvals;
  - review from code owners;
  - stale approvals dismissed on push;
  - approval of the most recent push **not** required (it blocked lane A; see #70);
  - an extra approval for unattributed changes;
  - squash is the only merge method.
- Required checks `check` and `policy`, from GitHub Actions, with the branch
  up to date. `do_not_enforce_on_create` is on.
- Bypass list: **cannot be read by the agent identity; maintainer to
  confirm.** Per #52 it was Repository admin, for pull requests only. 0003
  step 6 leaves it to the maintainer to remove it or keep it as break-glass.

Ruleset `release-tags` (active, tags `refs/tags/v*`): restricts creation,
update, deletion and force push. Bypass: maintainer to confirm.

Workflows that implement the approval gate: `policy.yml` (on
`pull_request_target` only, since #76) and `policy-refresh.yml` (#77), which
re-runs `policy` when a review arrives.

Follow-up for the maintainer, because the agent identity cannot push
workflows: the comments in `.github/workflows/check.yml` (its header, and the
`evidence-freshness` job) still describe that job as the merge gate.

## Consequences

- Between releases, `docs/claims.md` on `main` may show stale rows. README
  says so, and the guarantees are made for tags.
- **Lane B host changes merge on green `check` and `policy`, with no lab run
  and no reviewer.** `evidence-freshness` on `main` reports only that a
  listed file changed, not that behaviour broke, and it stays red between lab
  runs, so a newly stale row is easy to miss. An agent could therefore merge
  several host changes that weaken a lab-only guarantee, such as
  revoke-before-freeze (H-ACT-01) or the channel fixing the event type
  (C-ARCH-01, INV-6). Nothing would catch that until the maintainer runs the
  lab or tags a release, and the cause would then have to be bisected. INV-6
  is "review-only between lab runs", and for lane B there is now no reviewer.
  This is the accepted cost of not blocking on the lab. #54 (weekly digest)
  and #53 (lab in CI) are what narrow it.
- Every PR the maintainer authors in lane C needs the bypass. The maintainer
  cannot approve their own PR, and the agent identity cannot push workflow
  files, so every workflow change takes this route.

## How to confirm the flow on the first lab refresh

1. Merge a PR that leaves a host claim stale, and note its squash commit S1.
2. Run the root lab on S1.
3. Open the evidence PR. `evidence-freshness` should pass on it.
4. After that PR's own squash merge, check that `evidence-freshness` stays
   green on `main`. No claim lists `claims.toml`, `results/` or
   `docs/claims.md`, so the evidence PR should not leave anything stale.
5. In a fresh clone, `git merge-base --is-ancestor S1 origin/main` succeeds.
6. Negative control: a `platforms` entry that names a commit that exists only
   on a branch fails `claims_check.py --strict` (CI-4 cannot diff it, which
   counts as stale).

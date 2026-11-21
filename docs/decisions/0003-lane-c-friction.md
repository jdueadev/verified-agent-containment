# 0003: A lighter lane C process, and approval-gated merges through an agent identity

Status: accepted, 2026-11-21 (#70). This record changes the process in 0001
and brings forward the agent identity that #52 deferred. 0001 is not edited.
The number 0002 is reserved for #52's record of the repository settings.

## Context

Every pull request merged after #58 (#62, #63, #65, #66, #67, #69) was lane C.
Each one changed checker source (`claims_check.py`, `rust_tokens.py`,
`policy_check.py`, `pins_check.py`, `mutation_check.py`), lab scripts or the
lane map. Each needed an issue, a multi-angle design review and a hand merge
through the ruleset bypass. The bypass is needed because agents push as the
maintainer, and GitHub does not let anyone approve their own pull request. The
maintainer reported the result as unmanageable.

## Options weighed

1. **Move checker source to lane B.** Rejected. Nothing mechanical catches a
   weakened checker: its unit tests change in the same pull request, the
   kernel mutation check does not cover these tools, and the sabotage controls
   run only in the lab. A weakened checker would merge unread.
2. **A label or comment as the maintainer's approval.** Rejected. While agents
   hold the maintainer's account, they can forge any such signal, so it would
   be policy dressed up as a gate.
3. **Split the process into heavy and routine, and gate lane C on a real
   approval by giving agents their own identity.** Chosen.

## Decision

**Process.** `AGENTS.md` (Workflow, steps 1 and 2) requires an issue and a
design review only for heavy changes. Heavy means changes to:
- the rules and the gate;
- what decides "passed";
- a trust boundary;

plus anything that loosens a check or modifies or deletes an existing test
assertion. Routine lane C changes go straight to a pull request, which states
the behaviour, the claims affected and the falsifier, and says why the change
does not widen what any checker accepts. The lane map, the ratchets and
CODEOWNERS are unchanged. The maintainer still reads every lane C pull
request.

**Identity.** Agents push as a separate account or GitHub App. Its token has
Contents, Pull requests, Issues and Metadata permissions only. It has no
Administration and no Workflows permission, it is not a code owner, and it is
on no bypass list. `tools/policy_check.py --enforce` already passes a lane C
pull request when the owner's latest review approves its exact head commit,
and `policy.yml` re-runs on review events. The maintainer's approval is
therefore the gate, and auto-merge completes the merge.

**One workflow change.** `policy.yml` fails for a pull request whose base is
not `main`. A `pull_request_target` run uses the base branch's checker, so
without this guard a pull request aimed at a planted branch with a weakened
`policy_check.py` could post a green `policy` check on a head commit that is
also proposed to `main`.

## Design review (recorded here because issue text can be edited)

Three independent reviews examined #70, from the angles of invariants, attack
and testing. Their findings and the response:

- **The `pull_request_review` trigger runs the pull request's own copy of
  `policy.yml`**, not the base copy. Found by two reviewers independently.
  With a stale approval and a self-left comment review, an edited workflow
  could report green. Response: the bot has no Workflows permission, so it
  cannot push workflow files. The ruleset also dismisses stale approvals and
  requires approval of the most recent push, so code-owner review backs up
  `policy`.
- **A forged `policy` check from a workflow pushed to a side branch.**
  Response: no Workflows permission.
- **A base-branch switch.** Response: the `base.ref == main` guard. Known
  limit: the guard protects only branches that contain it. Without the
  Workflows permission, the bot may still be able to create a branch from a
  commit older than the guard and add a weakened `policy_check.py` on top,
  because that push changes no workflow file. Whether a `policy` run from such
  a pull request counts for the same head commit's pull request into `main`
  is untested. The throwaway pull requests below test it. Where the attack
  touches a code-owner path, code-owner review still blocks it. For
  ratchet-only lane C it would not, and the detective check on `main` in the
  follow-up issue is the remaining control.
- **Ratchet-only lane C** (for example, a weakened `claims.toml` row) is not a
  code-owner path, so for it `policy` is the only gate. Recorded as known. The
  guard and the missing Workflows permission are what keep `policy`
  trustworthy.
- **Calling a weakening "routine".** Response: the paths that decide "passed"
  are heavy by path, and so is any modified or deleted test assertion. The PR
  template asks for the tier. Deciding whether a change loosens a check
  remains review-only.
- **Release tags.** Contents permission can push `v*` tags. Response: a tag
  ruleset.
- **The maintainer's credentials in an agent environment** undo all of this.
  Response: agent sessions run where only the bot's credentials exist (#52's
  separate WSL2 distro or OS user). The bypass, if kept, is used only from the
  maintainer's own environment.
- **Unit-test gaps in `approved()` and `--enforce`.** These include the fact
  that a missing `--head-sha` accepts a review with no commit. That case is
  latent only, because the workflow always passes the SHA. Moved to a
  follow-up issue, along with a detective check on pushes to `main`.

## Repository settings to apply (not versioned by git)

1. Create the bot account or App with the permissions above.
2. In the `main` ruleset, turn on "Require review from code owners", "Dismiss
   stale pull request approvals when new commits are pushed" and "Require
   approval of the most recent reviewable push".
3. Add a tag ruleset for `v*` that only the maintainer may create.
4. Run agent sessions in an environment that holds only the bot's
   credentials, with a repository-local git identity for the bot.
5. Verify with throwaway pull requests pushed by the bot:
   - lane C stays blocked until the maintainer approves its head commit, then
     merges by auto-merge;
   - a push after the approval blocks it again, and auto-merge stays queued;
   - the bot's own comment review unblocks nothing;
   - lane A merges with no human action;
   - a pull request based on a branch other than `main` fails `policy`;
   - a branch created from a commit older than the guard, with a weakened
     `policy_check.py`, as the base of a second pull request with the same
     head commit, does not turn the pull request into `main` green;
   - the bot can still bring its branch up to date after `main`'s workflows
     change (it has no Workflows permission).
6. Then remove the admin bypass, or keep it as break-glass and record which.

Approval of fork workflows (AC-045) stays with #52.

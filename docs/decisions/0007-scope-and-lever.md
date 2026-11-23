# 0007: Scope, levers, and a pinned slice of pstack

Status: proposed, 2026-11-23 (#124). Accepted when the maintainer merges the
pull request that carries this file. It does not edit an earlier record.
0005 and 0006 are taken, so this is the next free number. #124's acceptance
criterion named `0005-shared-agent-skills.md`; that number was already used
by `0005-root-judges-and-immutable-spec.md`.

## Context

#124 asks for the council design review and the pstack workflow skills to be
committed, pinned, and in lane C, so every contributor's agent follows the
same steps. The maintainer named the sources and accepted a custom subset
when it passes a design review and is worth more than vendoring both plugins.

This record covers the pstack half only. Agentic-council stays on #124. The
maintainer named `https://github.com/dtsong/agentic-council`, and an earlier
comment recorded a commit, but this change does not re-read that tree and
does not adopt it.

pstack at the pin below is 58 skills, two agents, a dormant automation pack,
and executable scripts. Several of those instructions fight this repository:

- `poteto-mode/playbooks/shipping.md` merges with `gh pr merge` and pushes
  with `--force-with-lease`. Workflow step 5 forbids an override merge.
- `poteto-mode/worker.md` tells a started agent never to ask a person, and
  not to add a check above the kickoff. Lane C exists so the maintainer
  still approves the trusted base.
- `principle-subtract-before-you-add` says to remove redundant validators
  and to add no speculative guard. INV-7 is that enforcement which cannot
  be read back ends in fail-stop, and a guard that looks spare is often
  that enforcement. INV-9 keeps deliberate defects behind `cfg(feature =
  "sabotage")`; they look like dead code.
- `principle-prove-it-works` says to suspect the observation method when a
  check fails. INV-2 leaves a failing check to the maintainer.
- `principle-build-the-lever` allows the lever to be a skill that delegates
  follow. INV-3 makes a skill part of the trusted base.
- `unslop` bans the words "ratchet" and "harness", which this repository
  uses as defined terms.
- `setup-pstack` writes `~/.cursor/rules/pstack-models.mdc` with
  `alwaysApply: true`. `statechart` installs `tla2tools.jar` through mise.
  `poteto-mode/scripts/bootstrap.ts` runs `bun install --frozen-lockfile`.
  None of that is a hook or an MCP server, and all of it is code or a
  machine-wide rule.

Lane C already names `.claude/**` (0006). CODEOWNERS already lists
`/.claude/`. The allow-list in `policy_check.py` already rejects hooks in
settings, `allowed-tools`, and a shell command that runs when a skill loads.

#154, open and not done, restructures AGENTS.md without changing a rule.
The new section is inserted after the workflow and before Rust, and it does
not edit INV-1 through INV-11 or renumber workflow steps 1 to 5. #154 should
move the section with the rest of the process material and should not add a
second copy of the `classify` step.

## Decision

1. **The rules live in AGENTS.md.** The section "Scope and levers" states
   the smallest change that meets the goal, one issue and one pull request
   per topic, the lane and the weight before the first push, small units
   that each end in a check, the lever (a committed script, codemod,
   generator, or check), and proving the result on the artifact. Deletion
   stays inside INV-2, INV-7 and INV-9. A failing check is not repaired by
   editing the check. A new skill is not a lever.
2. **One worked form, not the plugin.** `.claude/skills/scope-and-lever/SKILL.md`
   names those bullets. It is markdown, `disable-model-invocation: true`,
   and its frontmatter uses only `name`, `description` and
   `disable-model-invocation`. It copies no upstream file. CLAUDE.md points
   Claude Code at it. An agent that never reads `.claude/` still has the
   rules, because they are in AGENTS.md. Workflow step 2 still accepts any
   design-review method that covers the three angles.
3. **The pin is a commit, by copying bytes.** The commit is
   `0b46ec399d55f2829e88822998f53b84944837d3` (pstack 0.15.46, the last
   commit that changed `pstack/`). At `cursor/plugins` HEAD
   `7a583913eb1b8d1a0ee76753d1a2cf072e7b54f9` the `pstack/` tree is the same
   object, `b47cf6d63625b48fd77893233044849935cdae3d`. The files adopted are
   not a marketplace reference. A project marketplace pin fixes the
   marketplace commit, and the plugin's own commit stays in upstream
   `marketplace.json`, which this repository does not control. There is
   therefore no `pins_check.py` change: that check was specified only for a
   reference pin.
4. **What is not adopted.** No other pstack skill, neither agent
   (`comment-sicko`, `poteto-agent`), the `automations/benny` pack, no
   script, no hook, no MCP server, and no permission grant. No
   `.claude/settings.json` is added. `.gitignore` is unchanged: local
   `settings.local.json`, `worktrees/`, `tmp/`, `handover/` scratch and
   `*.local.*` stay ignored, and `.claude/skills/` was already un-ignored
   by 0006.
5. **Lane C by the existing name.** `.claude/**`, `AGENTS.md`, `CLAUDE.md`
   and `docs/decisions/**` are already lane C. This change adds files under
   those patterns and does not edit `ci/lanes.toml`. CODEOWNERS stays the
   generated file; `python3 tools/policy_check.py codeowners` is the check
   that it still matches.
6. **An update is a new lane C pull request.** It names the new upstream
   commit, shows the upstream diff of anything it takes, and reads every
   skill it commits. Moving the pin does not happen by fetching a branch.
7. **Which copy an agent reads.** The rule is the AGENTS.md section, loaded
   with the rulebook. The skill is a second copy of the worked steps. This
   change does not run Claude Code to see whether a personal skill of the
   same name shadows the project skill. Shadowing the skill does not remove
   the AGENTS.md section. A future change that wants the skill to be the
   only copy would be wrong under decision 1.

## Consequences

- Contributors who do not use Claude Code still see the scoping and lever
  rules.
- Sharing the whole plugin would have put merge instructions, machine-wide
  rules and downloaded jars on every checkout. This record refuses that.
- Skill prose beyond the frontmatter, the privacy check and the shell-injection
  check is review-only. `policy_check.py invariants` rejects a forbidden
  frontmatter key, a carriage return, and a command that runs when the skill
  loads. It does not read the bullets.
- #124 stays open for agentic-council.

## Sources

`cursor/plugins` commit `0b46ec399d55f2829e88822998f53b84944837d3`, tree
`pstack/` (and the generated `harness/pstack/claude-code`, which has the
same skill and agent names and no hooks, MCP servers or permission grants).
Read in full before this decision: `principle-laziness-protocol`,
`principle-subtract-before-you-add`, `principle-sequence-verifiable-units`,
`principle-build-the-lever`, `principle-prove-it-works`, `poteto-mode/SKILL.md`,
`poteto-mode/playbooks/shipping.md`, `poteto-mode/worker.md`. The other
skills were inventoried from their frontmatter and a scan, and were not
committed. Design review on #124, second pass, 2026-11-23.

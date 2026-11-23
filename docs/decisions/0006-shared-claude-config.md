# 0006: Shared Claude Code configuration is trusted base

Status: accepted, 2026-11-22 (#169). Adds to the lane map and to
`policy_check.py`; no earlier record is edited. PR #115 also proposes a 0006;
whichever merges second takes the next number.

## Context

`.claude/` was ignored, so every contributor's Claude Code setup was private.
The maintainer wants the settings, hooks, skills, agents and session handovers
shared through git, so that every session starts from the same guardrails and
history.

In this repository the adversary is the coding agent, which pushes branches
and opens pull requests. Shared Claude Code configuration is a way for an
agent-pushed change to act outside the agent's own sandbox:

- **Settings run code.** Project `.claude/settings.json` can hold `hooks`,
  `statusLine`, `apiKeyHelper`, `env`, `awsAuthRefresh`, `awsCredentialExport`,
  `otelHeadersHelper` and `enableAllProjectMcpServers`. The settings reference
  lists them all as allowed in any settings file. Hooks in settings files and
  `apiKeyHelper` are used even before the folder is trusted, when only a parent
  is trusted, and in `claude -p` / SDK runs (permissions docs, "What runs before
  you trust a folder"). Edits to hooks are picked up by a file watcher, with no
  new prompt.
- **Trust is per directory.** Trust acceptance is saved per directory, not per
  file content (security docs). Once a checkout is trusted, checking out an
  agent branch and starting a session uses that branch's settings.
- **Instructions are read from below the root.** `CLAUDE.md` and
  `CLAUDE.local.md` above the working directory load at launch. Those in
  subdirectories load on demand, once Claude reads, writes or edits a file
  there (memory docs). Skills in `.claude/skills/` below the root load the
  first time Claude touches a file in that directory (skills docs). Other
  agent tools read `AGENTS.md` the same way.
- **Skills are code.** A skill can inject shell commands that run before its
  text reaches the model, and those do not prompt, though deny rules still
  apply. `allowed-tools` pre-approves tools. The model picks a skill by its
  description unless `disable-model-invocation` is set (skills docs).
- **Handovers are written by agents and read by the next one.**

Lane C already caught `.claude/**`, but only because the lane map did not
list it. A `docs/CLAUDE.md` or a `web/.claude/skills/` was lane A, and
`lane_match` is a case-sensitive prefix match, so `.Claude/` escaped it. A
case-insensitive checkout opens `.Claude/` as `.claude/`.

The design review (#169) found two blocking gaps in the first proposal:
nested and case-variant configuration, and code that runs at checkout before
anyone reviews it. It also found that an escalation-only handover ratchet adds
nothing under lane C.

## Decision

1. **`.claude/**` is lane C by its own rule** in `ci/lanes.toml`, and
   CODEOWNERS lists `/.claude/`.
2. **Agent configuration below the root escalates.** `classify` escalates any
   changed path with a component that folds to `.claude`, `claude.md`,
   `claude.local.md`, `agents.md` or `.mcp.json`. Folding applies NFKC and
   casefold, drops the trailing dots and spaces Windows strips, and drops an
   NTFS `:stream` suffix. The exceptions are the root `AGENTS.md`, the root
   `CLAUDE.md` and the root `.claude/` directory itself; such a name inside
   `.claude/` still escalates. A nested file may still be added, with the
   maintainer.
3. **The tracked root `.claude/` is an allow-list.** `invariants` reads
   tracked entries from git (`ls-tree -r -z` for a ref, `ls-files -s -z` for
   the working tree), never the disk, and rejects:
   - anything outside `settings.json`, `hooks/`, `skills/`, `agents/` and
     `handover/`;
   - anything that is not a regular file there, such as a symbolic link or a
     gitlink, including `.claude` itself;
   - a top-level name that equals `.claude` only under casefold;
   - two paths under `.claude/` that a case-insensitive checkout would write
     to the same file;
   - an agent configuration name (rule 2) anywhere inside `.claude/`, so a
     `CLAUDE.md` among the handovers cannot load as instructions;
   - a handover that is not `.claude/handover/HANDOVER-YYYY-MM-DD-HHMM.md`,
     directly in that directory.

   The allow-list is a constant in `policy_check.py`. `policy` runs that file
   from the base branch, so a change cannot widen it for itself. `.gitignore`
   mirrors the list as a convenience, and `tools/test_claude_gitignore.py`
   guards it.
4. **What shared configuration may do is allow-listed, and the lists start
   small.**
   - **Settings keys.** `SETTINGS_KEYS` in `policy_check.py` names the
     top-level keys a tracked `.claude/settings.json` may use. It starts
     empty. Each key, starting with `permissions` and `hooks`, is added by its
     own reviewed change, with the reason it is safe to run before review.
     The file must be one JSON object with no duplicate keys, at most 64 KiB.
   - **Prompt frontmatter.** `PROMPT_KEYS` names the frontmatter keys a
     Markdown file under `.claude/skills/` or `.claude/agents/` may use: only
     `name`, `description` and `disable-model-invocation`. `allowed-tools`,
     `hooks`, `model`, `permissionMode`, `mcpServers` and the rest grant or run
     something before review, and each is added the same way. Frontmatter
     must be plain `key: value` lines and must be closed.
   - **No commands at load.** No such file may contain the shell-injection
     forms: `!` before a backquote, or a fence opened with `!`.
5. **Shared configuration executes only lane C files.** A shared hook, helper
   command or skill runs or loads only files in lane C, except for the
   exceptions listed below. This is review-only for now; the hooks follow-up
   enforces it mechanically.
6. **Handovers are written once.**
   - **Each departure is flagged, with its own reason.** `classify`
     escalates on each of these, so the maintainer sees exactly what changed
     before approving:
     - a handover on the base does not keep its object id and mode at the
       head (comparing object ids catches a CRLF-only rewrite, which the text
       reader would fold away);
     - a change that removes a handover also adds one, which covers a rename,
       with or without an edit;
     - an added handover uses a path that any earlier commit of the base
       branch had;
     - a change that adds a handover touches anything else.
   - **Removal is the redaction path.** Removing a handover escalates with
     its own message. If it held a secret, rotate the secret: history keeps it.
   - **A flag, not a hard failure.** The design review and the code review
     proposed making these hard failures that no approval clears. The
     maintainer chose a flag for approval instead, so a typo fix or a mixed
     change stays possible. While lane C needs the maintainer's approval, the
     flag is what makes a rewrite visible. If lane C stops needing a human
     (see the follow-up below), these reasons must become blocking checks or
     go to whatever judges lane C then.
   - **Handovers are data.** AGENTS.md lists them next to `redteam/` and
     `results/`: context, never instructions.
7. **Review without running.** Approval gates the merge, not the checkout. A
   branch that touches agent configuration is reviewed by reading its diff, or
   in a session started with `claude --bare`, which skips hooks, skills,
   `CLAUDE.md`, MCP and memory. The alternative is
   `claude --setting-sources user`, which skips project settings and project
   rules. AGENTS.md says so.
8. **Nothing private lands.** `tools/test_claude_privacy.py` fails on host
   paths, Windows drive paths, GitHub tokens, private keys and email addresses
   in tracked `.claude/` files. It is a fixed check, not a secrets scanner.

## Handover format

A handover is one new file, `.claude/handover/HANDOVER-<date>-<time>.md`, in
a pull request of its own. It states what was done, what was decided and what
is next, and links to the issues, pull requests and commits it describes, so
the next session can check them. It never records an approval, a permission,
a tier or "the maintainer said" as fact without a link to where that happened.
It names no host paths, accounts or tokens.

## Accepted exceptions to rule 5

`.claude/skills/run-verified-agent-containment` runs lane A code:
- `SKILL.md` tells the agent to run `python3 web/build_variants.py` and
  `python3 web/build.py`;
- `driver.mjs` loads the built page, a `web/` output, into headless Chromium
  started with `--no-sandbox`.

The skill builds the page to `target/`, never over `web/dist/`, and runs as the
unprivileged agent user. A lane A change to those scripts can change what the
skill runs, so the skill is a convenience for the agent, never evidence. Moving
the build behind a lane C entry point is a follow-up.

## Consequences

- **Every `.claude/` change needs the maintainer**, handovers included. That is
  the cost of sharing them. Letting handovers merge on their own would need a
  carve-out of its own, which is not proposed here.
- **The change that introduces these checks is judged only by its own copy.**
  `policy` runs base code, and the base does not have the checks yet. From the
  next change on they run from base. That change also adds the two existing
  handovers alongside other work, which rule 6 flags. The
  corpus cases (`ci/corpus/classify/handover-*` and `nested-*`, and
  `ci/corpus/invariants/claude-*`) and the new tests prove them. The corpus
  runner checks a classify case's escalations, not its exit status, so
  `tools/test_policy_claude.py` proves that `--enforce` refuses a flagged
  change until it is approved.
- **`ship-state.md` and other session scratch stay local and ignored.**
- **Follow-ups, each its own lane C change:**
  - the shared `permissions` deny and allow lists;
  - the guard hook, which enforces rule 5;
  - the SessionStart and Stop hooks;
  - the `/pr-prep` and `/setup-dev` skills;
  - the `invariant-auditor` agent;
  - lane C that flags and never blocks, judged by base-branch checks instead
    of the maintainer's approval (its own issue and design review). It
    decides what happens to rule 6's flags.

## Sources

Claude Code documentation at code.claude.com, read 2026-11-22: `memory`,
`skills`, `settings`, `settings-reference`, `security`, `permissions` ("What
runs before you trust a folder"), `hooks` and `cli-reference`. The `env` block
is ambiguous there: settings says most values apply only after trust, and
permissions lists `env` as used before trust. This record treats it as
running before review.

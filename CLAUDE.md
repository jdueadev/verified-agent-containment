@AGENTS.md

# Claude Code notes

AGENTS.md is the rulebook. If anything here disagrees with it, AGENTS.md wins.

- **Windows:** the host crate does not build here, and `scripts/check.sh` needs Linux
  tools. Run the tool unit tests (`python -m unittest discover -s tools -p "test_*.py"`)
  and the kernel crate, report that as tier T0, and rely on the `check` workflow.
- **Line endings:** `.gitattributes` keeps text files LF. The one exception is `*.cmd`,
  which is left byte-for-byte as committed (CRLF) because Windows batch files need it.
  Do not change those settings or commit any other file with CRLF.
- **Design review (optional tooling):** the multi-perspective review that AGENTS.md
  asks for can be done with any method. If you happen to have a council-style review
  command available, that is one way to do it.
- **Scope and levers:** the section of that name in AGENTS.md is the rule, for
  Claude Code and for every other agent. The worked form in this checkout is
  `.claude/skills/scope-and-lever`. Read that skill when you plan a change. It
  adds no rule, and workflow step 2 still accepts any design-review method that
  covers the three angles.
- Personal workflow notes belong in `CLAUDE.local.md`, which git ignores.

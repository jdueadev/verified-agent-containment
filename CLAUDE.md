@AGENTS.md

# Claude Code notes

AGENTS.md is the rulebook. If anything here disagrees with it, AGENTS.md wins.

- **Windows:** the host crate does not build here, and `scripts/check.sh` needs Linux
  tools. Run the tool unit tests (`python -m unittest discover -s tools -p "test_*.py"`)
  and the kernel crate, report that as tier T0, and rely on the `check` workflow.
- **Line endings:** `.gitattributes` keeps every file LF. Do not change that setting
  or commit a file with CRLF.
- **Design review (optional tooling):** the multi-perspective review that AGENTS.md
  asks for can be done with any method. If you happen to have a council-style review
  command available, that is one way to do it.
- Personal workflow notes belong in `CLAUDE.local.md`, which git ignores.

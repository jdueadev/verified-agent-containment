#!/usr/bin/env python3
"""The .gitignore keeps local Claude Code state out of commits and lets the shared
parts in (#169). .gitignore is lane A, so this test is what guards it. It is a
convenience only: `policy_check.py invariants` is what enforces the allow-list."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LOCAL = (".claude/ship-state.md", ".claude/review-1-draft.md", ".claude/tmp/x", ".claude/worktrees/x/y",
         ".claude/settings.local.json", ".claude/commands/x.md")
SHARED = (".claude/settings.json", ".claude/hooks/guard.py", ".claude/skills/s/SKILL.md",
          ".claude/agents/a.md", ".claude/handover/HANDOVER-x.md")
# A nested .claude/ is not ignored: the corpus holds fixtures there, and classify
# escalates any nested agent configuration instead.
NESTED = ("ci/corpus/invariants/x/tree/.claude/ship-state.md", "docs/.claude/x")


def ignored(path):
    child = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", path],
                           capture_output=True, text=True)
    if child.returncode not in (0, 1):
        raise RuntimeError(child.stderr)
    return child.returncode == 0


class ClaudeIgnoreTests(unittest.TestCase):
    def test_local_state_is_ignored(self):
        for path in LOCAL:
            self.assertTrue(ignored(path), path)

    def test_shared_paths_are_not(self):
        for path in SHARED + NESTED:
            self.assertFalse(ignored(path), path)


if __name__ == "__main__":
    unittest.main()

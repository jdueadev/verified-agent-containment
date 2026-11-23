#!/usr/bin/env python3
"""docs/claims.md drift without --strict (#175 review).

Without --strict, drift in docs/claims.md is a warning only when staleness explains
it. Before this, any drift was a warning whenever some claim was stale, which on
main is always, so a hand-edited status passed the required `check` job.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims_check as cc

ROOT = Path(__file__).resolve().parent.parent
CLAIMS = [{"id": "K-1", "status": "tested"}, {"id": "K-2", "status": "proved"}]
HEAD = "# Claims\n\nheader\n\n| id | statement | layer | status | evidence | falsifier | platforms |\n|---|---|---|---|---|---|---|\n"


def row(cid, status, platforms="linux @abc: pass", statement="s", evidence="`law:x`"):
    return f"| {cid} | {statement} | host | {status} | {evidence} | f | {platforms} |\n"


def table(*rows):
    return HEAD + "".join(rows)


class StalenessOnlyTests(unittest.TestCase):
    def drift(self, committed, expected, effective=None):
        return cc.staleness_only_drift(committed, expected, CLAIMS, effective or {"K-1": "stale", "K-2": "proved"})

    def test_staleness_changes_are_explained(self):
        fresh = table(row("K-1", "tested"), row("K-2", "proved"))
        stale = table(row("K-1", "stale", "linux @abc: pass (predates later changes)"), row("K-2", "proved"))
        self.assertTrue(self.drift(fresh, stale))
        self.assertTrue(self.drift(stale, fresh, {"K-1": "tested", "K-2": "proved"}))
        pending = table(row("K-1", "stale (pending lab: scenario:x)"), row("K-2", "proved"))
        self.assertTrue(self.drift(fresh, pending))

    def test_a_hand_edited_status_is_not(self):
        expected = table(row("K-1", "stale"), row("K-2", "proved"))
        for forged in ("proved", "checked-bounded", "assumed", "planned"):
            self.assertFalse(self.drift(table(row("K-1", forged), row("K-2", "proved")), expected), forged)

    def test_other_cells_and_lines_are_not(self):
        expected = table(row("K-1", "stale"), row("K-2", "proved"))
        for committed in (
            table(row("K-1", "stale", statement="s, now stronger"), row("K-2", "proved")),
            table(row("K-1", "stale", evidence="`law:y`"), row("K-2", "proved")),
            table(row("K-1", "stale", platforms="linux @def: pass"), row("K-2", "proved")),
            table(row("K-1", "stale"), row("K-2", "proved"), row("K-3", "proved")),
            table(row("K-2", "proved"), row("K-1", "stale")),
            table(row("K-1", "stale")).replace("header", "Proof verdict matches HEAD: yes") + row("K-2", "proved"),
            table(row("K-1", "stale (needs K-9)"), row("K-2", "proved")),
        ):
            self.assertFalse(self.drift(committed, expected), committed)

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        expected = table(row("K-1", "stale", statement="a \\| b"), row("K-2", "proved"))
        self.assertTrue(self.drift(table(row("K-1", "tested", statement="a \\| b"), row("K-2", "proved")), expected))
        self.assertFalse(self.drift(table(row("K-1", "tested", statement="a \\| c"), row("K-2", "proved")), expected))


class RepositoryTests(unittest.TestCase):
    """claims_check.py on a copy of this checkout with docs/claims.md edited by hand."""

    def run_copy(self, edit):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "repo"
            subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(copy), "HEAD"],
                           check=True, capture_output=True)
            try:
                for name in ("tools/claims_check.py", "tools/rust_tokens.py"):
                    shutil.copy2(ROOT / name, copy / name)
                path = copy / "docs/claims.md"
                path.write_text(edit(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
                child = subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py")],
                                       cwd=copy, capture_output=True, text=True, timeout=300)
                return child.returncode, json.loads(child.stdout[child.stdout.index("{"):])
            finally:
                subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(copy)],
                               capture_output=True)

    def test_hand_edited_status_fails_without_strict(self):
        def forge(text):
            lines = text.split("\n")
            for i, line in enumerate(lines):
                if line.startswith("| ") and " | tested" in line:
                    lines[i] = line.replace(" | tested", " | proved", 1)
                    return "\n".join(lines)
            self.fail("no tested row to forge")
        code, result = self.run_copy(forge)
        self.assertEqual(code, 1)
        self.assertIn("docs/claims.md is out of date; run tools/claims_check.py --write", result["errors"])

    def test_unedited_table_passes_without_strict(self):
        code, result = self.run_copy(lambda text: text)
        self.assertEqual((code, result["errors"]), (0, []))


if __name__ == "__main__":
    unittest.main()

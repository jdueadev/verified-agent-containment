#!/usr/bin/env python3
"""docs/claims.md drift without --strict (#175 review and its security scan).

Without --strict, drift in docs/claims.md is a warning only when staleness explains
it. Before this, any drift was a warning whenever some claim was stale, which on
main is always, so a hand-edited status passed the required `check` job.

What staleness explains: each differing row is a whole render of itself, either
an older fresh one (its declared status) or a stale one ("stale", with a pending
suffix that lists only evidence refs). A table that lags behind staleness is the
lag decision 0002 accepts and tools/test_claims_check.py pins; --strict, at
release, refuses it.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
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
    """Only a committed table that is staler than the evidence is tolerated."""
    FRESH = {"K-1": "tested", "K-2": "proved"}
    STALE = {"K-1": "stale", "K-2": "proved"}

    def drift(self, committed, expected, effective):
        return cc.staleness_only_drift(committed, expected, CLAIMS, effective)

    def test_a_staler_committed_table_is_tolerated(self):
        fresh = table(row("K-1", "tested"), row("K-2", "proved"))
        for stale_row in (row("K-1", "stale", "linux @abc: pass (predates later changes)"),
                          row("K-1", "stale (pending lab: scenario:exfil_race)"),
                          row("K-1", "stale (pending lab: scenario:a, sabotage:b)")):
            self.assertTrue(self.drift(table(stale_row, row("K-2", "proved")), fresh, self.FRESH), stale_row)

    def test_a_table_that_lags_behind_staleness_is_tolerated(self):
        # Decision 0002's lag: the table still shows the declared status of a claim
        # that went stale, until the lab evidence is refreshed and it is regenerated.
        expected = table(row("K-1", "stale (pending lab: scenario:x)", "linux @abc: pass (predates later changes)"),
                         row("K-2", "proved"))
        for committed_row in (row("K-1", "tested"), row("K-1", "tested", "linux @abc: pass (predates later changes)"),
                              row("K-1", "stale")):
            self.assertTrue(self.drift(table(committed_row, row("K-2", "proved")), expected, self.STALE), committed_row)

    def test_a_hand_edited_status_is_not(self):
        expected = table(row("K-1", "tested"), row("K-2", "proved"))
        for forged in ("proved", "checked-bounded", "assumed", "planned"):
            self.assertFalse(self.drift(table(row("K-1", forged), row("K-2", "proved")), expected, self.FRESH), forged)

    def test_smuggled_text_and_dropped_notes_are_not(self):
        # The scan's second finding: free text in a pending suffix, and dropped notes.
        expected = table(row("K-1", "tested"), row("K-2", "proved"))
        for committed_row in (row("K-1", "stale (pending lab: none; verified on all platforms, maintainer sign-off)"),
                              row("K-1", "stale (pending lab: scenario:x; all good)"),
                              row("K-1", "tested (pending lab: scenario:x)"),
                              row("K-1", "stale (pending lab: scenario:x) (pending lab: scenario:y)"),
                              row("K-1", "stale", "linux @abc: pass, verified")):
            self.assertFalse(self.drift(table(committed_row, row("K-2", "proved")), expected, self.FRESH), committed_row)

    def test_other_cells_and_lines_are_not(self):
        expected = table(row("K-1", "tested"), row("K-2", "proved"))
        for committed in (
            table(row("K-1", "stale", statement="s, now stronger"), row("K-2", "proved")),
            table(row("K-1", "stale", evidence="`law:y`"), row("K-2", "proved")),
            table(row("K-1", "stale", platforms="linux @def: pass"), row("K-2", "proved")),
            table(row("K-1", "stale"), row("K-2", "proved"), row("K-3", "proved")),
            table(row("K-2", "proved"), row("K-1", "stale")),
            table(row("K-1", "stale")).replace("header", "Proof verdict matches HEAD: yes") + row("K-2", "proved"),
            table(row("K-1", "stale (needs K-9)"), row("K-2", "proved")),
            table(row("K-1", "stale"), row("K-2", "proved")).replace("\n", "\r\n"),
        ):
            self.assertFalse(self.drift(committed, expected, self.FRESH), committed)

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        expected = table(row("K-1", "tested", statement="a \\| b"), row("K-2", "proved"))
        self.assertTrue(self.drift(table(row("K-1", "stale", statement="a \\| b"), row("K-2", "proved")), expected,
                                   self.FRESH))
        self.assertFalse(self.drift(table(row("K-1", "stale", statement="a \\| c"), row("K-2", "proved")), expected,
                                    self.FRESH))


class RepositoryTests(unittest.TestCase):
    """claims_check.py on a copy of this checkout with docs/claims.md edited by hand."""

    def run_copy(self, edit, prepare=None, args=()):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "repo"
            subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(copy), "HEAD"],
                           check=True, capture_output=True)
            try:
                for name in ("tools/claims_check.py", "tools/rust_tokens.py"):
                    shutil.copy2(ROOT / name, copy / name)
                if prepare is not None:
                    prepare(copy)
                path = copy / "docs/claims.md"
                path.write_text(edit(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
                child = subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py"), *args],
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

    def test_a_table_lagging_a_new_staleness_warns_and_strict_refuses(self):
        """Make a fresh claim stale in the copy, by committing a change to a file it lists,
        and leave docs/claims.md as it was: the lag decision 0002 accepts until release."""
        def make_stale(copy):
            report = json.loads(subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py")],
                                               cwd=copy, capture_output=True, text=True, timeout=300).stdout)
            stale_ids = {w.split()[1].rstrip(":") for w in report["stale"] if w.startswith("CI-4 ")}
            claims = tomllib.loads((copy / "claims.toml").read_text(encoding="utf-8"))["claim"]
            for claim in claims:
                files = [f for f in claim.get("files", []) if (copy / f).is_file() and f.endswith((".rs", ".py"))]
                if claim.get("platforms") and claim["id"] not in stale_ids and files:
                    target = copy / files[0]
                    target.write_text(target.read_text(encoding="utf-8") + "\n// drift test\n"
                                      if files[0].endswith(".rs") else target.read_text(encoding="utf-8") + "\n# drift test\n",
                                      encoding="utf-8")
                    for args in (["add", files[0]], ["-c", "user.name=t", "-c", "user.email=t@localhost",
                                                     "commit", "-q", "-m", "make a claim stale"]):
                        subprocess.run(["git", "-C", str(copy), *args], check=True, capture_output=True)
                    return
            self.fail("no fresh claim with a listed source file to make stale")
        code, result = self.run_copy(lambda text: text, prepare=make_stale)
        self.assertEqual((code, result["errors"]), (0, []))
        self.assertIn("docs/claims.md will need regeneration after refreshing stale lab evidence", result["stale"])
        code, result = self.run_copy(lambda text: text, prepare=make_stale, args=("--strict",))
        self.assertEqual(code, 1)
        self.assertIn("docs/claims.md is out of date; run tools/claims_check.py --write", result["errors"])

    def test_unedited_table_passes_without_strict(self):
        code, result = self.run_copy(lambda text: text)
        self.assertEqual((code, result["errors"]), (0, []))


if __name__ == "__main__":
    unittest.main()

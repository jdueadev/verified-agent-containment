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
import re
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
CLAIMS = [{"id": "K-1", "status": "tested", "evidence": ["law:x", "mutant:m1", "scenario:x", "scenario:exfil_race",
                                                         "scenario:a", "sabotage:b", "sabotage:y"]},
          {"id": "K-2", "status": "proved"}]
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

    def test_a_pending_suffix_out_of_place_is_not(self):
        # CodeRabbit on #179: a suffix stripped from inside the word left "stale" behind.
        fresh = table(row("K-1", "tested"), row("K-2", "proved"))
        # Each forgery is a stale render once the suffix is cut out of the middle, so only the
        # anchor rejects it; every ref is in K-1's own evidence.
        for forged in ("st (pending lab: scenario:exfil_race)ale", "sta (pending lab: scenario:a)le",
                       "s (pending lab: sabotage:b)tale", "stal (pending lab: scenario:x, sabotage:y)e"):
            with self.subTest(forged=forged):
                self.assertFalse(self.drift(table(row("K-1", forged), row("K-2", "proved")), fresh, self.FRESH))

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

    def test_notes_on_an_unchanged_row_must_match(self):
        # Rescan finding: stripping "predates later changes" from a row that is still fresh.
        expected = table(row("K-1", "tested", "linux @abc: pass (predates later changes); wsl @def: pass"),
                         row("K-2", "proved"))
        committed = table(row("K-1", "tested", "linux @abc: pass; wsl @def: pass"), row("K-2", "proved"))
        self.assertFalse(self.drift(committed, expected, self.FRESH))

    def test_pending_refs_must_be_the_claims_own_lab_evidence(self):
        # Rescan finding: a stale suffix naming refs the claim does not have.
        expected = table(row("K-1", "tested"), row("K-2", "proved"))
        for suffix in ("verified:lean-proof-ok", "ci:passed", "scenario:not_mine", "mutant:m1", "law:x"):
            committed = table(row("K-1", f"stale (pending lab: {suffix})"), row("K-2", "proved"))
            self.assertFalse(self.drift(committed, expected, self.FRESH), suffix)
        own = table(row("K-1", "stale (pending lab: scenario:x, sabotage:y)"), row("K-2", "proved"))
        self.assertTrue(self.drift(own, expected, self.FRESH))

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
            # A clone of its own, sharing objects read-only: the judges (spec, the check
            # container) mount this checkout's gitdir read-only, so `git worktree add`,
            # which writes into it, cannot run there.
            head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True,
                                  text=True).stdout.strip()
            subprocess.run(["git", "clone", "-q", "--shared", "--no-checkout", str(ROOT), str(copy)],
                           check=True, capture_output=True)
            subprocess.run(["git", "-C", str(copy), "checkout", "-q", "--detach", head], check=True,
                           capture_output=True)
            for name in ("tools/claims_check.py", "tools/rust_tokens.py"):
                shutil.copy2(ROOT / name, copy / name)
            if prepare is not None:
                prepare(copy)
            path = copy / "docs/claims.md"
            path.write_text(edit(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
            child = subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py"), *args],
                                   cwd=copy, capture_output=True, text=True, timeout=300)
            return child.returncode, json.loads(child.stdout[child.stdout.index("{"):])

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
        and leave docs/claims.md as it was: the lag decision 0002 accepts until release.

        The fresh claim is built in the copy, so the test does not depend on the checkout's
        history: the spec job checks the head out at depth 1, where no platform commit of
        claims.toml is reachable and every claim is stale. Commit A is empty; commit B adds an
        artifact naming A under results/ (CI-9), a passing platform at A for one claim, and the
        regenerated table; commit C changes a file that claim lists."""
        def git(copy, *args):
            return subprocess.run(["git", "-C", str(copy), "-c", "user.name=t", "-c", "user.email=t@localhost",
                                   *args], check=True, capture_output=True, text=True).stdout.strip()

        def make_stale(copy):
            claims = tomllib.loads((copy / "claims.toml").read_text(encoding="utf-8"))["claim"]
            claim = next((c for c in claims if c.get("platforms")
                          and any((copy / f).is_file() and f.endswith((".rs", ".py")) for f in c.get("files", []))),
                         None)
            if claim is None:
                self.fail("no claim with platforms and a listed source file")
            listed = next(f for f in claim["files"] if (copy / f).is_file() and f.endswith((".rs", ".py")))
            git(copy, "commit", "-q", "--allow-empty", "-m", "platform commit")
            commit = git(copy, "rev-parse", "HEAD")
            artifact = copy / "results" / f"drift-test-{commit}" / "run.txt"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("drift test\n", encoding="utf-8")
            text = (copy / "claims.toml").read_text(encoding="utf-8")
            block = re.search(r'(?ms)^id = "' + re.escape(claim["id"]) + r'"\n.*?^platforms = \[.*?\]$', text)
            self.assertIsNotNone(block, claim["id"])
            entry = f', {{ name = "drift-test", commit = "{commit}", result = "pass" }}]'
            text = text[:block.end() - 1] + entry + text[block.end():]
            (copy / "claims.toml").write_text(text, encoding="utf-8", newline="\n")
            subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py"), "--write"],
                           cwd=copy, capture_output=True, text=True, timeout=300)
            git(copy, "add", "-A")
            git(copy, "commit", "-q", "-m", "fresh claim")
            fresh = json.loads(subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py")],
                                              cwd=copy, capture_output=True, text=True, timeout=300).stdout)
            self.assertFalse([w for w in fresh["stale"] if w.startswith(f"CI-4 {claim['id']}:")], fresh["stale"])
            self.assertNotIn("docs/claims.md will need regeneration after refreshing stale lab evidence",
                             fresh["stale"])
            target = copy / listed
            target.write_text(target.read_text(encoding="utf-8")
                              + ("\n// drift test\n" if listed.endswith(".rs") else "\n# drift test\n"),
                              encoding="utf-8")
            git(copy, "add", listed)
            git(copy, "commit", "-q", "-m", "make a claim stale")
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

#!/usr/bin/env python3
"""The differential results must record the run check.sh makes (#178).

Before this, a differential counted if it recorded zero mismatches, so
`{"sequences": 0, "transitions": 0, "mismatches": 0}` passed CI-3. Now the Rust/Bend
run must record at least the cases check.sh generates, and the wasm run, which
replays the same case file, the same number of transitions. This is an error in
both modes: such a file records a run that did not happen, not an old one.
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims_check as cc

ROOT = Path(__file__).resolve().parent.parent
GOOD_BEND = {"sequences": 5000, "transitions": 77364, "mismatches": 0}
GOOD_WASM = {"transitions": 77364, "mismatches": 0}


class ProblemTests(unittest.TestCase):
    def problems(self, bend=GOOD_BEND, wasm=GOOD_WASM):
        records = {}
        if bend is not None:
            records["rust-bend"] = bend
        if wasm is not None:
            records["rust-wasm"] = wasm
        return cc.differential_problems(records)

    def test_the_run_check_sh_makes_passes(self):
        self.assertEqual(self.problems(), {})
        self.assertEqual(self.problems(dict(GOOD_BEND, sequences=6000), GOOD_WASM), {})

    def test_too_few_cases_fail(self):
        for sequences in (0, 1, 4999, None, "5000", True, 5000.0):
            found = self.problems(dict(GOOD_BEND, sequences=sequences))
            self.assertIn("rust-bend", found, sequences)
            self.assertTrue(any("sequences" in why for why in found["rust-bend"]), found)

    def test_zero_everything_fails(self):
        found = self.problems({"sequences": 0, "transitions": 0, "mismatches": 0}, {"transitions": 0, "mismatches": 0})
        self.assertEqual(sorted(found), ["rust-bend", "rust-wasm"])

    def test_transitions_must_cover_the_cases(self):
        self.assertIn("rust-bend", self.problems(dict(GOOD_BEND, transitions=4999)))
        self.assertIn("rust-bend", self.problems(dict(GOOD_BEND, sequences=9000, transitions=8000)))

    def test_mismatches_still_fail(self):
        for value in (1, None, "0", False):
            found = self.problems(dict(GOOD_BEND, mismatches=value))
            self.assertTrue(any("zero mismatches" in why for why in found.get("rust-bend", [])), value)

    def test_wasm_must_replay_the_same_cases(self):
        for wasm in ({"transitions": 77363, "mismatches": 0}, {"transitions": 5000, "mismatches": 0},
                     {"mismatches": 0}, {"transitions": 77364, "mismatches": 2}):
            self.assertIn("rust-wasm", self.problems(GOOD_BEND, wasm), wasm)
        self.assertIn("rust-wasm", self.problems(None, GOOD_WASM))

    def test_a_record_that_is_not_an_object_fails(self):
        for bad in ([], "x", 5, None):
            self.assertIn("rust-wasm", cc.differential_problems({"rust-bend": GOOD_BEND, "rust-wasm": bad}))


class FloorDriftTests(unittest.TestCase):
    def test_floor_is_the_count_check_sh_generates(self):
        text = (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
        found = re.findall(r"differential-cases (\d+) (\d+)", text)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(int(found[0][0]), cc.MIN_DIFF_SEQUENCES)


class RepositoryTests(unittest.TestCase):
    """claims_check.py on a copy of this checkout with a forged differential result."""

    def run_copy(self, bend, *args):
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
                (copy / name).write_bytes((ROOT / name).read_bytes())
            (copy / "results/differential.json").write_text(json.dumps(bend), encoding="utf-8")
            child = subprocess.run([sys.executable, "-I", "-B", str(copy / "tools/claims_check.py"), *args],
                                   cwd=copy, capture_output=True, text=True, timeout=300)
            return child.returncode, json.loads(child.stdout[child.stdout.index("{"):])

    def test_zero_cases_fail_in_both_modes(self):
        for args in ((), ("--strict",)):
            code, result = self.run_copy({"sequences": 0, "transitions": 0, "mismatches": 0}, *args)
            self.assertEqual(code, 1, args)
            self.assertTrue(any(e.startswith("CI-3 results/differential.json") for e in result["errors"]), result)

    def test_the_committed_result_passes(self):
        committed = json.loads((ROOT / "results/differential.json").read_text(encoding="utf-8"))
        code, result = self.run_copy(committed)
        self.assertFalse(any(e.startswith("CI-3 results/") for e in result["errors"]), result["errors"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for #125's stage 2: new spec files are lane B, existing ones stay with the
maintainer through the spec ratchet, and the lane B module that base tests import stays
pure data. Three assertions in test_policy_check.py that pinned test files to lane C were
changed in the same PR; the cases below are what replaces them."""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import policy_check as pc

ROOT = TOOLS.parent
OWNER, LANES = pc.load_lanes((ROOT / "ci/lanes.toml").read_text(encoding="utf-8"))
LAWS_RS = "crates/containment-kernel/tests/laws.rs"


class Stage2LaneTests(unittest.TestCase):
    def lane(self, path):
        return pc.lane_of(path, LANES)[0]

    def test_spec_files_are_lane_b_by_path(self):
        for path in ("tools/test_new_checker.py", "tools/test_policy_check.py", LAWS_RS,
                     "crates/containment-kernel/tests/more_laws.rs"):
            self.assertEqual(self.lane(path), "B", path)

    def test_the_tools_they_test_stay_lane_c(self):
        for path in ("tools/policy_check.py", "tools/spec_run.py", "tools/corpus_run.py", "tools/claims_check.py",
                     "tools/rust_tokens.py", "tools/mutation_check.py", "ci/corpus/classify/law-removed/case.toml",
                     "crates/containment-host/src/harness.rs", "crates/containment-kernel/Cargo.toml"):
            self.assertEqual(self.lane(path), "C", path)

    def test_codeowners_no_longer_lists_spec_files(self):
        text = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
        self.assertNotIn("/tools/test_*.py", text)
        self.assertNotIn("/crates/containment-kernel/tests/", text)
        self.assertIn("/tools/policy_check.py " + OWNER, text)

    def test_a_new_spec_file_classifies_as_b_and_an_edit_to_an_existing_one_as_c(self):
        laws = (ROOT / LAWS_RS).read_text(encoding="utf-8")
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"), LAWS_RS: laws}
        added = dict(base, **{"tools/test_new.py": "import unittest\n"})
        result = pc.classify(["tools/test_new.py"], base.get, added.get, LANES)
        self.assertEqual((result["lane"], result["escalations"]), ("B", []))
        edited = dict(base, **{LAWS_RS: laws.replace("#[test]", "#[test]\n#[ignore]", 1)})
        result = pc.classify([LAWS_RS], base.get, edited.get, LANES)
        self.assertEqual(result["lane"], "C")
        self.assertEqual(result["escalations"], [f"spec {LAWS_RS} was edited"])
        removed = {k: v for k, v in base.items() if k != LAWS_RS}
        self.assertEqual(pc.classify([LAWS_RS], base.get, removed.get, LANES)["lane"], "C")


class DataModuleTests(unittest.TestCase):
    PATH = "tools/kernel_mutants.py"

    def test_the_real_module_is_pure_data(self):
        self.assertEqual(pc.data_module_errors(self.PATH, (ROOT / self.PATH).read_text(encoding="utf-8")), [])

    def test_literals_pass(self):
        text = '"""Doc."""\nA = [("x", "a\\nb", "c")]\nB = ()\nC = {"k": [1, 2.5, None, True]}\n'
        self.assertEqual(pc.data_module_errors(self.PATH, text), [])

    def test_anything_that_runs_is_refused(self):
        for text in ("import os\n", "A = [1]\nimport unittest\n", "A = f()\n", "A = [x for x in ()]\n",
                     "A = B = [1]\nB.append(2)\n", "def f():\n    pass\n", "class K:\n    pass\n",
                     "A = [1]\nif True:\n    A = []\n", "A: list = []\n", "A = [1]\n'late docstring'\n",
                     "A.b = 1\n", "A = (lambda: 1)\n", "A = __import__('os')\n", "A = [1] + [2]\n", "def broken(:\n"):
            self.assertTrue(pc.data_module_errors(self.PATH, text), text)

    def test_classify_sends_code_in_a_data_module_to_lane_c(self):
        base_text = (ROOT / self.PATH).read_text(encoding="utf-8")
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"), self.PATH: base_text}
        head = dict(base, **{self.PATH: base_text + "\nimport unittest\nunittest.TestCase.assertEqual = print\n"})
        result = pc.classify([self.PATH], base.get, head.get, LANES)
        self.assertEqual(result["lane"], "C")
        self.assertTrue(any("is not a literal assignment" in e for e in result["escalations"]))

    def test_an_added_mutant_stays_lane_b(self):
        base_text = (ROOT / self.PATH).read_text(encoding="utf-8")
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"), self.PATH: base_text}
        head_text = base_text.replace("BEND_MUTANTS = [\n", 'BEND_MUTANTS = [\n    ("new_one", "x", "y"),\n', 1)
        result = pc.classify([self.PATH], base.get, dict(base, **{self.PATH: head_text}).get, LANES)
        self.assertEqual((result["lane"], result["escalations"]), ("B", []))


if __name__ == "__main__":
    unittest.main()

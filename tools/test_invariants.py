"""Run the seeded cases in tools/invariant_cases against invariants_check."""
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import invariants_check  # noqa: E402

ROOT = HERE.parent
CASES = sorted(p for p in (HERE / "invariant_cases").iterdir() if p.is_dir())


class SeededCases(unittest.TestCase):
    def test_there_are_cases(self):
        self.assertGreaterEqual(len(CASES), 6)

    def test_each_case_is_judged_as_expected(self):
        for case in CASES:
            with self.subTest(case=case.name), tempfile.TemporaryDirectory() as tmp:
                spec = tomllib.loads((case / "case.toml").read_text())
                tree = Path(tmp)
                shutil.copytree(case / "tree", tree, dirs_exist_ok=True)
                manifest = tree / invariants_check.HOST_MANIFEST
                if not manifest.exists():
                    manifest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(ROOT / invariants_check.HOST_MANIFEST, manifest)
                found = invariants_check.errors(tree)
                if spec["expect"] == "accept":
                    self.assertEqual(found, [])
                else:
                    self.assertTrue(found)
                    if "expect_error" in spec:
                        self.assertTrue(any(spec["expect_error"] in line for line in found), found)

    def test_the_checkout_itself_passes(self):
        self.assertEqual(invariants_check.errors(ROOT), [])


if __name__ == "__main__":
    unittest.main()

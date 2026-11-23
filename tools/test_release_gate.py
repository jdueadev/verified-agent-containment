#!/usr/bin/env python3
"""workflow_lint.py keeps the release gate strict (#175): release.yml runs
`python3 tools/claims_check.py --strict` as a whole step, unskipped and unsoftened."""
import unittest
from pathlib import Path

import workflow_lint as wl

ROOT = Path(__file__).resolve().parent.parent
GOOD = """name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - name: Every claim is fresh at this tag
        run: python3 tools/claims_check.py --strict
"""


class ReleaseGate(unittest.TestCase):
    def errors(self, text):
        return wl.release_gate({wl.RELEASE: text})

    def test_the_committed_release_workflow_passes(self):
        files = wl.workflow_files(ROOT)
        self.assertIn(wl.RELEASE, files)
        self.assertEqual(wl.release_gate(files), [])

    def test_a_strict_step_passes(self):
        self.assertEqual(self.errors(GOOD), [])

    def test_a_missing_release_workflow_fails(self):
        self.assertTrue(any("missing" in e for e in wl.release_gate({})))

    def test_dropping_strict_fails(self):
        self.assertTrue(self.errors(GOOD.replace(" --strict", "")))

    def test_softening_the_command_fails(self):
        for run in ("python3 tools/claims_check.py --strict || true",
                    "|\n          exit 0\n          python3 tools/claims_check.py --strict",
                    "python3 tools/claims_check.py --strict; true"):
            with self.subTest(run=run):
                text = GOOD.replace("run: python3 tools/claims_check.py --strict", "run: " + run)
                self.assertTrue(self.errors(text), text)

    def test_continue_on_error_fails(self):
        for where in ("    continue-on-error: true\n    steps:", "    steps:"):
            text = GOOD.replace("    steps:", where)
            if where == "    steps:":
                text = GOOD.replace("        run: python3", "        continue-on-error: true\n        run: python3")
            with self.subTest(where=where):
                self.assertTrue(any("continue-on-error" in e for e in self.errors(text)), text)

    def test_a_condition_fails(self):
        for text in (GOOD.replace("    runs-on:", "    if: false\n    runs-on:"),
                     GOOD.replace("        run: python3", "        if: false\n        run: python3")):
            with self.subTest(text=text):
                self.assertTrue(any("'if'" in e for e in self.errors(text)), text)

    def test_the_gate_outside_steps_does_not_count(self):
        text = GOOD.replace("      - name: Every claim is fresh at this tag\n        run: python3 tools/claims_check.py "
                            "--strict\n", "      - run: python3 tools/claims_check.py\n") \
            + "    env:\n      run: python3 tools/claims_check.py --strict\n"
        self.assertTrue(self.errors(text), text)


if __name__ == "__main__":
    unittest.main()

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

    def test_a_run_nested_in_env_or_with_does_not_count(self):
        # Security review: env: {run: ...} matched the old rule while the real run was not strict.
        for nest in ("env", "with"):
            text = GOOD.replace("        run: python3 tools/claims_check.py --strict\n",
                                f"        run: python3 tools/claims_check.py\n        {nest}:\n"
                                "          run: python3 tools/claims_check.py --strict\n")
            with self.subTest(nest=nest):
                self.assertTrue(any("no step whose whole run" in e for e in self.errors(text)), text)

    def test_what_swaps_the_runner_is_refused(self):
        for key, where in (("shell", "        shell: true {0}\n"), ("env", "        env:\n          PYTHONPATH: x\n"),
                           ("container", "    container: python:3\n"), ("working-directory",
                                                                          "        working-directory: x\n")):
            anchor = "    steps:\n" if where.startswith("    container") else "        run: python3"
            text = GOOD.replace(anchor, where + anchor, 1)
            with self.subTest(key=key):
                self.assertTrue(any(f"'{key}'" in e for e in self.errors(text)), text)
        text = GOOD.replace("jobs:\n", "defaults:\n  run:\n    shell: true {0}\njobs:\n")
        self.assertTrue(any("'defaults'" in e for e in self.errors(text)), text)

    def test_the_trigger_is_pinned(self):
        for on in ('on:\n  push:\n    tags: ["never-*"]\n', 'on:\n  workflow_dispatch:\n    inputs:\n      x:\n        type: string\n',
                   'on:\n  push:\n    tags: ["v*"]\n    tags-ignore: ["v*"]\n'):
            text = GOOD.replace('on:\n  push:\n    tags: ["v*"]\n', on)
            with self.subTest(on=on):
                self.assertTrue(any("must run on push of tags" in e for e in self.errors(text)), text)


if __name__ == "__main__":
    unittest.main()

"""Seeded cases for lab_throwaway_check: the checkout passes, each removed refusal fails."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lab_throwaway_check as check  # noqa: E402

ROOT = HERE.parent
GUARDED = ["scripts/factory-lab.sh", "scripts/run-wsl2.sh", "scripts/lab/lab-inside.sh"]


class Seeded(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = Path(self.tmp.name)
        shutil.copytree(ROOT / "scripts", self.tree / "scripts")
        (self.tree / check.MAIN_RS).parent.mkdir(parents=True)
        shutil.copy(ROOT / check.MAIN_RS, self.tree / check.MAIN_RS)

    def tearDown(self):
        self.tmp.cleanup()

    def edit(self, rel, old, new):
        path = self.tree / rel
        text = path.read_text()
        self.assertIn(old, text, rel)
        path.write_text(text.replace(old, new, 1))

    def write(self, rel, text):
        (self.tree / rel).write_text(text)

    def assert_fails(self, mention):
        found = check.errors(self.tree)
        self.assertTrue(any(mention in line for line in found), found)

    def test_the_checkout_itself_passes(self):
        self.assertEqual(check.errors(ROOT), [])
        self.assertEqual(check.errors(self.tree), [])

    def test_each_guarded_script_fails_without_its_refusal(self):
        for rel in GUARDED:
            with self.subTest(script=rel):
                self.tearDown()
                self.setUp()
                text = (self.tree / rel).read_text()
                guard = next(line for line in text.splitlines() if check.GUARD_TEST.search(line))
                self.edit(rel, guard + "\n", "")
                self.assert_fails(rel)

    def test_factory_lab_subcommand_fails_without_its_refusal(self):
        self.edit("scripts/factory.sh", 'if [ "${FACTORY_LAB_DISPOSABLE:-}" != "1" ]; then', "if false; then")
        self.assert_fails("scripts/factory.sh")

    def test_a_new_root_script_without_a_refusal_fails(self):
        self.write("scripts/new-root.sh", "#!/usr/bin/env bash\nset -euo pipefail\nsudo target/release/containment-lab live-suite\n")
        self.assert_fails("scripts/new-root.sh")

    def test_a_script_without_the_sh_suffix_is_still_seen(self):
        self.write("scripts/lab/runner", '#!/bin/bash\n"$BIN" attack-suite --repeat 1\n')
        self.assert_fails("scripts/lab/runner")

    def test_a_refusal_after_the_root_line_fails(self):
        self.write("scripts/late.sh", '#!/usr/bin/env bash\nsudo true\n'
                   '[ "${FACTORY_LAB_DISPOSABLE:-}" = 1 ] || { echo "set FACTORY_LAB_DISPOSABLE=1" >&2; exit 1; }\n')
        self.assert_fails("scripts/late.sh")

    def test_a_refusal_that_does_not_exit_fails(self):
        self.write("scripts/noexit.sh", '#!/usr/bin/env bash\n'
                   '[ "${FACTORY_LAB_DISPOSABLE:-}" = 1 ] || { echo "set FACTORY_LAB_DISPOSABLE=1" >&2; }\nsudo true\n')
        self.assert_fails("scripts/noexit.sh")

    def test_a_refusal_that_does_not_name_the_fix_fails(self):
        self.write("scripts/unnamed.sh", '#!/usr/bin/env bash\n'
                   '[ "${FACTORY_LAB_DISPOSABLE:-}" = 1 ] || { echo "not here" >&2; exit 1; }\nsudo true\n')
        self.assert_fails("scripts/unnamed.sh")

    def test_a_commented_out_refusal_fails(self):
        self.write("scripts/commented.sh", '#!/usr/bin/env bash\n'
                   '# [ "${FACTORY_LAB_DISPOSABLE:-}" = 1 ] || { echo "set FACTORY_LAB_DISPOSABLE=1" >&2; exit 1; }\nsudo true\n')
        self.assert_fails("scripts/commented.sh")

    def test_a_script_that_needs_no_root_passes(self):
        self.write("scripts/plain.sh", "#!/usr/bin/env bash\ncargo test\n# sudo is only mentioned here\n")
        self.assertEqual(check.errors(self.tree), [])

    def test_a_binary_command_in_neither_list_fails(self):
        self.edit(check.MAIN_RS, '        Some("redteam") =>', '        Some("new-attack") => redteam::run(&args[1..]),\n        Some("redteam") =>')
        self.assert_fails("`new-attack` is in neither")

    def test_a_root_command_moved_to_the_no_marker_list_fails(self):
        self.edit(check.MAIN_RS, '"attack-suite", "live",', '"live",')
        self.assert_fails("`attack-suite` is in neither")

    def test_a_binary_that_skips_the_refusal_fails(self):
        self.edit(check.MAIN_RS, "and_then(|c| disposable_refusal(", "and_then(|c| skipped(")
        self.assert_fails("does not call disposable_refusal")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for spec_run's per-module copies (#125). The first `spec (base)` run in CI
failed because two claims_check tests write a lab run into results/ci/ of the checkout,
which the unprivileged user may not do. Each module now runs in its own copy, which it
may write to, and no copy reaches another module or the checkout itself."""
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_run as sr

PASSING = textwrap.dedent("""
    import unittest
    import thing


    class T(unittest.TestCase):
        def test_value(self):
            self.assertEqual(thing.VALUE, 1)
""")


def head_with(**files):
    tmp = tempfile.TemporaryDirectory()
    head = Path(tmp.name) / "head"
    for name, text in files.items():
        path = head / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp, head


class CopyTests(unittest.TestCase):
    def test_a_test_may_write_into_the_repository_and_the_checkout_stays_unchanged(self):
        writes = PASSING + textwrap.dedent("""

            import pathlib
            lab = pathlib.Path(__file__).resolve().parents[1] / "results" / "ci" / "lab-x"
            lab.mkdir(parents=True)
            (lab / "attack-suite.json").write_text("{}")
        """)
        tmp, head = head_with(**{"tools/thing.py": "VALUE = 1\n", "tools/test_thing.py": writes,
                                 "results/keep.json": "{}"})
        with tmp:
            results = sr.run_python_module(head, "tools/test_thing.py", writes, isolate=True)
            self.assertEqual(results, {"test_thing.T.test_value": "ok"})
            self.assertFalse((head / "results/ci").exists())
            self.assertEqual(sorted(p.name for p in (head / "results").iterdir()), ["keep.json"])

    def test_a_module_that_weakens_a_checker_on_disk_cannot_reach_a_later_module(self):
        weakens = PASSING + "\n\nimport pathlib\npathlib.Path(__file__).with_name('thing.py').write_text('VALUE = 1\\n')\n"
        tmp, head = head_with(**{"tools/thing.py": "VALUE = 2\n", "tools/test_first.py": weakens,
                                 "tools/test_later.py": PASSING})
        with tmp:
            sr.run_python_module(head, "tools/test_first.py", weakens, isolate=True)
            self.assertEqual((head / "tools/thing.py").read_text(encoding="utf-8"), "VALUE = 2\n")
            later = sr.run_python_module(head, "tools/test_later.py", PASSING, isolate=True)
        self.assertEqual(later, {"test_later.T.test_value": "FAILED"})

    def test_the_module_is_rewritten_from_base_in_the_copy(self):
        tmp, head = head_with(**{"tools/thing.py": "VALUE = 2\n",
                                 "tools/test_thing.py": PASSING.replace("thing.VALUE, 1", "thing.VALUE, 2")})
        with tmp:
            self.assertEqual(sr.run_python_module(head, "tools/test_thing.py", PASSING, isolate=True),
                             {"test_thing.T.test_value": "FAILED"})
            self.assertIn("thing.VALUE, 2", (head / "tools/test_thing.py").read_text(encoding="utf-8"))

    def test_a_shadow_in_the_checkout_still_fails_the_module(self):
        tmp, head = head_with(**{"tools/thing.py": "VALUE = 1\n", "tools/test_thing.py": PASSING,
                                 "tools/test_thing/__init__.py": ""})
        with tmp:
            self.assertIn("could shadow", sr.run_python_module(head, "tools/test_thing.py", isolate=True)["<module>"])

    def test_the_copy_leaves_out_target_and_is_removed_afterwards(self):
        tmp, head = head_with(**{"tools/x.py": "", "target/debug/big": "x"})
        with tmp:
            work, copy = sr.own_copy(head)
            self.assertTrue((copy / "tools/x.py").exists())
            self.assertFalse((copy / "target").exists())
            sr.remove_copy(work, None)
            self.assertFalse(work.exists())

    def test_run_always_isolates_python_modules(self):
        tmp, head = head_with(**{"tools/test_thing.py": PASSING})
        seen = []

        def fake_module(*args, **kwargs):
            seen.append(kwargs)
            return {"test_thing.T.test_value": "ok"}
        with tmp, mock.patch.object(sr, "base_names", lambda ref: ["tools/test_thing.py"]), \
                mock.patch.object(sr, "head_names", lambda h: ["tools/test_thing.py"]), \
                mock.patch.object(sr.policy_check, "reader", lambda ref: {"tools/test_thing.py": PASSING}.get), \
                mock.patch.object(sr, "run_python_module", fake_module):
            report = sr.run("base", "HEAD", head, False)
        self.assertEqual(report["failed"], {})
        self.assertEqual(seen, [{"isolate": True}])

    def test_a_parked_file_is_not_tracked_in_the_copy(self):
        import subprocess
        tmp, head = head_with(**{"tools/test_old.py": "", "tools/test_new.py": ""})
        with tmp:
            for args in (["init", "-q"], ["add", "-A"]):
                subprocess.run(["git", "-C", str(head), *args], check=True, capture_output=True)
            (head / "tools/test_new.py").unlink()  # what run() does to head-only spec
            work, copy = sr.own_copy(head)
            try:
                tracked = subprocess.run(["git", "-C", str(copy), "ls-files"], capture_output=True, text=True,
                                         check=True).stdout.split()
            finally:
                sr.remove_copy(work, None)
            self.assertEqual(tracked, ["tools/test_old.py"])
            head_tracked = subprocess.run(["git", "-C", str(head), "ls-files"], capture_output=True, text=True,
                                          check=True).stdout.split()
            self.assertEqual(head_tracked, ["tools/test_new.py", "tools/test_old.py"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""spec_run hands each module's copy to the child's user only after it has finished
writing to it (#125). The first `spec (base)` run after #132 failed with a permission
error, because the copy was handed over before the module was rewritten from base.
These tests simulate the hand-over by making the copy read-only for this process."""
import os
import stat
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


def read_only(copy, as_user):
    """What chown to another user does to this process: it may read, not write."""
    for root, dirs, files in os.walk(copy):
        for name in files:
            path = Path(root) / name
            path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        Path(root).chmod(Path(root).stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def writable(work, as_user):
    for root, dirs, files in os.walk(work):
        Path(root).chmod(Path(root).stat().st_mode | stat.S_IWUSR)
    import shutil
    shutil.rmtree(work, ignore_errors=True)


class HandOverTests(unittest.TestCase):
    def run_module(self, base_text, head_text):
        with tempfile.TemporaryDirectory() as tmp:
            head = Path(tmp) / "head"
            (head / "tools").mkdir(parents=True)
            (head / "tools/thing.py").write_text("VALUE = 1\n", encoding="utf-8")
            (head / "tools/test_thing.py").write_text(head_text, encoding="utf-8")
            with mock.patch.object(sr, "hand_over", read_only), mock.patch.object(sr, "remove_copy", writable):
                return sr.run_python_module(head, "tools/test_thing.py", base_text, isolate=True)

    def test_the_rewrite_from_base_happens_before_the_hand_over(self):
        self.assertEqual(self.run_module(PASSING, PASSING.replace("VALUE, 1", "VALUE, 2")),
                         {"test_thing.T.test_value": "ok"})

    def test_new_mode_without_a_base_text_also_works(self):
        self.assertEqual(self.run_module(None, PASSING), {"test_thing.T.test_value": "ok"})

    def test_a_stale_pycache_is_cleared_before_the_hand_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            head = Path(tmp) / "head"
            cache = head / "tools/__pycache__"
            cache.mkdir(parents=True)
            (cache / "thing.cpython-312.pyc").write_bytes(b"stale")
            (head / "tools/thing.py").write_text("VALUE = 1\n", encoding="utf-8")
            (head / "tools/test_thing.py").write_text(PASSING, encoding="utf-8")
            seen = []

            def check(copy, as_user):
                seen.append((copy / "tools/__pycache__").exists())
                read_only(copy, as_user)
            with mock.patch.object(sr, "hand_over", check), mock.patch.object(sr, "remove_copy", writable):
                results = sr.run_python_module(head, "tools/test_thing.py", PASSING, isolate=True)
        self.assertEqual((seen, results), ([False], {"test_thing.T.test_value": "ok"}))


if __name__ == "__main__":
    unittest.main()

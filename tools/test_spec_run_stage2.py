#!/usr/bin/env python3
"""spec_run changes from the stage 2 review of #125: a base Rust test file runs as the
base commit has it, and a base file whose tests cannot be read fails without stopping
the run."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_run as sr

BASE_RS = "#[test]\nfn law() {\n    assert!(true);\n}\n"


class RustBaseTextTests(unittest.TestCase):
    def test_the_base_text_is_what_runs_and_the_head_file_is_put_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            head = Path(tmp)
            path = "crates/containment-kernel/tests/laws.rs"
            (head / path).parent.mkdir(parents=True)
            (head / path).write_bytes(b"#[test]\nfn law() {\n    //\r    assert!(true);\n}\n")
            seen = []

            def fake_run(h, p, target_dir, as_user=None):
                seen.append((h / p).read_text(encoding="utf-8"))
                return {"laws::law": "ok"}
            with mock.patch.object(sr, "run_rust_file", fake_run):
                result = sr.run_rust_with_base_text(head, path, BASE_RS, head / "target")
            self.assertEqual((seen, result), ([BASE_RS], {"laws::law": "ok"}))
            self.assertIn(b"//\r", (head / path).read_bytes())

    def test_a_file_missing_from_the_head_is_removed_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            head = Path(tmp)
            path = "crates/containment-kernel/tests/gone.rs"
            (head / path).parent.mkdir(parents=True)
            with mock.patch.object(sr, "run_rust_file", lambda *a, **k: {}):
                sr.run_rust_with_base_text(head, path, BASE_RS, head / "target")
            self.assertFalse((head / path).exists())


class UnreadableBaseTests(unittest.TestCase):
    def test_a_base_file_whose_tests_cannot_be_read_fails_and_the_run_goes_on(self):
        files = {"tools/test_broken.py": "def broken(:\n",
                 "tools/test_fine.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(sr, "base_names", lambda ref: list(files)), \
                mock.patch.object(sr, "head_names", lambda h: list(files)), \
                mock.patch.object(sr.policy_check, "reader", lambda ref: files.get), \
                mock.patch.object(sr, "run_python_module", lambda *a, **k: {"test_fine.T.test_x": "ok"}):
            report = sr.run("base", "HEAD", Path(tmp), False)
        self.assertIn("cannot read its tests", report["failed"]["tools/test_broken.py"])
        self.assertEqual(report["passed"], 1)


if __name__ == "__main__":
    unittest.main()

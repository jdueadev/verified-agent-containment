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
        self.assertTrue(any("is not a single literal assignment" in e for e in result["escalations"]))

    def test_an_added_mutant_stays_lane_b(self):
        base_text = (ROOT / self.PATH).read_text(encoding="utf-8")
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"), self.PATH: base_text}
        head_text = base_text.replace("BEND_MUTANTS = [\n", 'BEND_MUTANTS = [\n    ("new_one", "x", "y"),\n', 1)
        result = pc.classify([self.PATH], base.get, dict(base, **{self.PATH: head_text}).get, LANES)
        self.assertEqual((result["lane"], result["escalations"]), ("B", []))


class ReviewBypassTests(unittest.TestCase):
    """Bypasses the stage 2 review found, each now refused."""

    PY = "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertTrue(True)\n"

    def flags(self, path, old, new):
        return pc.spec_ratchets([path], {path: old}.get, {path: new}.get)

    def test_a_coding_declaration_that_turns_a_comment_into_code_is_refused(self):
        # Line 2 counts when line 1 is a comment, as a shebang is in every tools/test_*.py.
        hidden = "#!/usr/bin/env python3\n# coding: raw_unicode_escape\n" + self.PY \
            + "#\\u000aT.test_x = lambda self: None\n"
        flags = self.flags("tools/test_thing.py", self.PY, hidden)
        self.assertEqual(len(flags), 1)
        self.assertIn("raw-unicode-escape", flags[0])
        self.assertTrue(self.flags("tools/test_thing.py", self.PY, "# -*- coding: utf-7 -*-\n" + self.PY))
        # A declaration after code is ignored by the interpreter too, so it is just a comment.
        late = self.PY.replace("import unittest\n", "import unittest\n# coding: utf-7\n", 1)
        self.assertEqual(pc.declared_encoding(late), "utf-8")

    def test_a_utf8_declaration_is_fine(self):
        self.assertEqual(self.flags("tools/test_thing.py", self.PY, "# -*- coding: utf-8 -*-\n" + self.PY), [])

    def test_a_lone_cr_in_rust_spec_is_refused(self):
        path = LAWS_RS
        old = "#[test]\nfn t() {\n    assert!(1 == 1);\n}\n"
        flags = self.flags(path, old, old.replace("    assert!", "    //\r    assert!"))
        self.assertEqual(len(flags), 1)
        self.assertIn("carriage return", flags[0])
        self.assertEqual(self.flags(path, old, old.replace("\n", "\r\n")), [])

    def test_the_reader_keeps_a_lone_cr(self):
        """Text mode would turn it into a newline, so the lexer would see code there."""
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            run = lambda *a: subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True)
            run("init", "-q")
            (Path(tmp) / "x.rs").write_bytes(b"a\rb\r\nc\n")
            run("add", "x.rs")
            run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
            from unittest import mock
            with mock.patch.object(pc, "ROOT", Path(tmp)):
                self.assertEqual(pc.reader("HEAD")("x.rs"), "a\rb\nc\n")

    def test_a_nested_kernel_test_target_is_refused(self):
        for path in ("crates/containment-kernel/tests/extra/main.rs", "crates/containment-kernel/tests/data.txt"):
            self.assertEqual(pc.spec_ratchets([path], {}.get, {path: "x"}.get),
                             [f"spec {path} is not a direct crates/containment-kernel/tests/<name>.rs file"])
        self.assertEqual(pc.spec_ratchets(["crates/containment-kernel/tests/more.rs"], {}.get,
                                          {"crates/containment-kernel/tests/more.rs": "fn x() {}"}.get), [])

    def test_a_symlinked_spec_file_is_refused(self):
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8")}
        result = pc.classify(["tools/test_link.py"], base.get, dict(base, **{"tools/test_link.py": "x"}).get, LANES,
                             head_links=["tools/test_link.py"])
        self.assertEqual((result["lane"], result["escalations"]), ("C", ["spec tools/test_link.py is a symbolic link"]))

    def test_spec_links_reads_modes_from_git(self):
        import subprocess
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run = lambda *a: subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True)
            run("init", "-q")
            (Path(tmp) / "tools").mkdir()
            (Path(tmp) / "tools/test_real.py").write_text("x = 1\n")
            (Path(tmp) / "tools/test_link.py").symlink_to("../README")
            run("add", "-A")
            run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
            with mock.patch.object(pc, "ROOT", Path(tmp)):
                self.assertEqual(pc.spec_links("HEAD", ["tools/test_real.py", "tools/test_link.py", "README"]),
                                 ["tools/test_link.py"])

    def test_an_edit_to_an_existing_python_test_is_lane_c_through_classify(self):
        base = {"ci/lanes.toml": (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"), "tools/test_x.py": self.PY}
        head = dict(base, **{"tools/test_x.py": self.PY.replace("True)", "True or None)")})
        result = pc.classify(["tools/test_x.py"], base.get, head.get, LANES)
        self.assertEqual((result["lane"], result["escalations"]), ("C", ["spec tools/test_x.py was edited"]))

    def test_data_cannot_be_replaced_or_chained(self):
        path = "tools/kernel_mutants.py"
        for text in ('BEND_MUTANTS = [("a", "b", "c")]\nBEND_MUTANTS = []\n', 'X = BEND_MUTANTS = []\n',
                     'lower = []\n', '__all__ = []\n', '# coding: utf-7\nA = []\n#+AAo-print(1)\n'):
            self.assertTrue(pc.data_module_errors(path, text), text)


class WeakenedStage2GateTests(unittest.TestCase):
    """The corpus cases for the review's bypasses fail against a gate without the fix."""

    def failures(self, patch):
        import tempfile
        import corpus_run
        import test_corpus_run
        with tempfile.TemporaryDirectory() as tmp:
            return corpus_run.run(test_corpus_run.head_copy(tmp, patch), ROOT / "ci/corpus")["failed"]

    def test_without_the_encoding_rule(self):
        self.assertIn("classify/spec-coding-declaration",
                      self.failures([('    if declared not in ("utf-8", "utf-8-sig"):\n        raise ValueError(f"declares',
                                      '    if False:\n        raise ValueError(f"declares')]))

    def test_without_the_lone_cr_rule_or_the_bytes_reader(self):
        self.assertIn("classify/spec-lone-cr", self.failures([
            ('    if "\\r" in text.replace("\\r\\n", ""):', '    if False:'),
            ('git_bytes("show", f"{commit}:{path}").decode("utf-8")', 'git("show", f"{commit}:{path}")')]))

    def test_without_the_nested_target_rule(self):
        self.assertIn("classify/nested-test-target", self.failures([
            ('if rest is not None and ("/" in rest', 'if False and ("/" in rest')]))


if __name__ == "__main__":
    unittest.main()

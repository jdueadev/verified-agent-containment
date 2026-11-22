#!/usr/bin/env python3
"""Unit tests for the parts of tools/policy_check.py that #125 added: the gate's
own imports, `invariants --ref`, and the spec-immutability ratchet. They live in a
file of their own so that the existing test files stay as they are (#125: spec is
added in new files)."""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import policy_check as pc

ROOT = TOOLS.parent


def working_tree_files():
    """The files `invariants` reads, from the working tree, as a dict."""
    files = {path: pc.read(path) for path in (pc.LANES_FILE, pc.CODEOWNERS_FILE, pc.HOST_MANIFEST)}
    return files, pc.kernel_sources()


class GateImportTests(unittest.TestCase):
    def test_the_gate_imports_no_other_checker(self):
        """`policy` runs from the base branch, and every module it imports runs inside
        the gate. Only the lexer is allowed."""
        tree = ast.parse((TOOLS / "policy_check.py").read_text(encoding="utf-8"))
        local = {p.stem for p in TOOLS.glob("*.py")}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported & local, {"rust_tokens"})

    def test_a_fresh_gate_process_loads_no_other_checker(self):
        code = "import sys; sys.path.insert(0, sys.argv[1]); import policy_check; " \
               "print(sorted(m for m in sys.modules if m in {'claims_check', 'pins_check', 'mutation_check', 'lab_record'}))"
        out = subprocess.run([sys.executable, "-I", "-c", code, str(TOOLS)], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "[]")

    def test_rank_matches_the_claims_checker(self):
        import claims_check
        self.assertEqual(pc.RANK, claims_check.RANK)


class InvariantsAtARefTests(unittest.TestCase):
    def errors(self, **changes):
        files, kernel = working_tree_files()
        files.update({k: v for k, v in changes.items() if not k.startswith("kernel:")})
        for key, text in changes.items():
            if key.startswith("kernel:"):
                kernel[key[len("kernel:"):]] = text
        return pc.invariant_errors(files.get, kernel)

    def test_the_working_tree_passes(self):
        self.assertEqual(self.errors(), [])

    def test_each_rule_fires_on_files_read_through_get(self):
        manifest = pc.read(pc.HOST_MANIFEST)
        self.assertTrue(self.errors(**{pc.HOST_MANIFEST: manifest.replace("default = [", 'default = ["sabotage", ', 1)}))
        self.assertTrue(self.errors(**{pc.CODEOWNERS_FILE: ""}))
        root = f"{pc.KERNEL_SRC}/lib.rs"
        _, kernel = working_tree_files()
        self.assertTrue(self.errors(**{f"kernel:{root}": kernel[root].replace("#![no_std]", "", 1)}))
        self.assertTrue(self.errors(**{f"kernel:{pc.KERNEL_SRC}/extra.rs": "use std::fs;\n"}))

    def test_a_missing_file_is_an_error_not_a_pass(self):
        self.assertTrue(self.errors(**{pc.HOST_MANIFEST: None}))
        self.assertTrue(self.errors(**{pc.CODEOWNERS_FILE: None}))
        self.assertEqual(self.errors(**{pc.LANES_FILE: None}), [f"{pc.LANES_FILE}: missing"])

    def test_the_sabotage_default_check_really_fires_on_this_manifest(self):
        """The replace above must change something, or the test proves nothing."""
        manifest = pc.read(pc.HOST_MANIFEST)
        self.assertIn("default = [", manifest)

    def test_a_ref_reads_the_same_kernel_files_as_a_clean_working_tree(self):
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", pc.KERNEL_SRC],
                               capture_output=True, text=True, check=True).stdout
        if dirty:
            self.skipTest("kernel sources have local changes")
        self.assertEqual(pc.kernel_sources("HEAD"), pc.kernel_sources())
        self.assertEqual(pc.main(["invariants", "--ref", "HEAD"]), 0)


PY_BASE = """import unittest


class T(unittest.TestCase):
    LIMIT = 7

    def setUp(self):
        self.cases = range(self.LIMIT)

    def test_law(self):
        for case in self.cases:
            self.assertTrue(case >= 0)
"""
RS_BASE = """use containment_kernel::*;

fn events() -> [u8; 3] { [1, 2, 3] }

#[test]
fn law_holds() {
    for e in events() { assert!(step(e)); }
}
"""
CORPUS_BASE = 'checker = "classify"\nexpect = "lane:C"\n'
SPEC = {"tools/test_thing.py": PY_BASE, "crates/containment-kernel/tests/laws.rs": RS_BASE,
        "ci/corpus/classify/law-removed/case.toml": CORPUS_BASE}


class SpecRatchetTests(unittest.TestCase):
    def reasons(self, **head):
        files = dict(SPEC)
        files.update({path.replace("__", "/"): text for path, text in head.items()})
        paths = sorted(set(SPEC) | set(files))
        return pc.spec_ratchets(paths, SPEC.get, files.get)

    def head(self, path, text):
        files = dict(SPEC, **{path: text})
        return pc.spec_ratchets(sorted(set(SPEC) | {path}), SPEC.get, files.get)

    def test_an_unchanged_or_reformatted_spec_file_passes(self):
        self.assertEqual(self.head("tools/test_thing.py", PY_BASE), [])
        self.assertEqual(self.head("tools/test_thing.py", PY_BASE.replace("    LIMIT = 7", "    LIMIT = 7  # cases")
                                   .replace("\n\n\nclass", "\n\nclass")), [])
        self.assertEqual(self.head("crates/containment-kernel/tests/laws.rs",
                                   "// laws\n" + RS_BASE.replace("{ [1, 2, 3] }", "{\n    [1, 2, 3,]\n}")), [])

    def test_new_spec_files_and_other_paths_pass(self):
        self.assertEqual(self.head("tools/test_new.py", "x = 1\n"), [])
        self.assertEqual(self.head("crates/containment-kernel/tests/more.rs", "#[test]\nfn t() {}\n"), [])
        self.assertEqual(self.head("ci/corpus/classify/new/case.toml", "x = 2\n"), [])
        self.assertEqual(pc.spec_ratchets(["tools/claims_check.py", "README.md"], {}.get, {}.get), [])

    def test_python_edits_outside_a_test_body_are_edits(self):
        for edit in (PY_BASE.replace("LIMIT = 7", "LIMIT = 1"),
                     PY_BASE.replace("range(self.LIMIT)", "range(0)"),
                     PY_BASE.replace("    def test_law", "    @unittest.skip('later')\n    def test_law"),
                     PY_BASE + "\n\nT.test_law = lambda self: None\n",
                     PY_BASE + "\n\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n",
                     PY_BASE.replace("test_law", "test_law_renamed")):
            self.assertEqual(self.head("tools/test_thing.py", edit), ["spec tools/test_thing.py was edited"], edit)

    def test_rust_edits_outside_a_test_body_are_edits(self):
        path = "crates/containment-kernel/tests/laws.rs"
        for edit in (RS_BASE.replace("[1, 2, 3]", "[1]"),
                     RS_BASE.replace("#[test]", "#[test]\n#[ignore]"),
                     RS_BASE.replace("#[test]\n", ""),
                     "#![cfg(any())]\n" + RS_BASE,
                     RS_BASE + "\nfn step(_: u8) -> bool { true }\n"):
            self.assertEqual(self.head(path, edit), [f"spec {path} was edited"], edit)

    def test_a_removed_or_renamed_spec_file_is_flagged(self):
        files = {k: v for k, v in SPEC.items() if k != "tools/test_thing.py"}
        files["tools/test_thing_v2.py"] = PY_BASE
        self.assertEqual(pc.spec_ratchets(sorted(set(SPEC) | set(files)), SPEC.get, files.get),
                         ["spec tools/test_thing.py was removed"])

    def test_corpus_entries_compare_as_text(self):
        path = "ci/corpus/classify/law-removed/case.toml"
        self.assertEqual(self.head(path, CORPUS_BASE.replace("lane:C", "lane:B")), [f"spec {path} was edited"])
        self.assertEqual(self.head(path, CORPUS_BASE + "\n"), [f"spec {path} was edited"])

    def test_a_head_that_cannot_be_read_is_flagged_not_skipped(self):
        self.assertEqual(self.head("tools/test_thing.py", "def broken(:\n"),
                         ["spec tools/test_thing.py does not parse (invalid syntax)"])
        rs = self.head("crates/containment-kernel/tests/laws.rs", 'fn f() { "open\n')
        self.assertEqual(len(rs), 1)
        self.assertIn("cannot be lexed", rs[0])

    def test_a_base_that_cannot_be_read_must_stay_byte_identical(self):
        base = {"tools/test_old.py": "def broken(:\n"}
        self.assertEqual(pc.spec_ratchets(list(base), base.get, base.get), [])
        self.assertEqual(pc.spec_ratchets(list(base), base.get, {"tools/test_old.py": "def broken( :\n"}.get),
                         ["spec tools/test_old.py was edited"])

    def test_every_spec_file_in_this_repository_can_be_read(self):
        """Otherwise its files would fall back to text comparison without anyone noticing."""
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True,
                                 check=True).stdout.splitlines()
        spec = [path for path in tracked if pc.is_spec(path)]
        self.assertIn("crates/containment-kernel/tests/laws.rs", spec)
        self.assertIn("tools/test_policy_check.py", spec)
        for path in spec:
            pc.spec_form(path, (ROOT / path).read_text(encoding="utf-8"))

    def test_classify_puts_a_spec_edit_in_lane_c(self):
        lanes_text = (ROOT / "ci/lanes.toml").read_text(encoding="utf-8")
        base = {"ci/lanes.toml": lanes_text, **SPEC}
        head = dict(base, **{"tools/test_thing.py": PY_BASE.replace("LIMIT = 7", "LIMIT = 1")})
        owner, lanes = pc.load_lanes(lanes_text)
        result = pc.classify(["tools/test_thing.py"], base.get, head.get, lanes)
        self.assertEqual(result["lane"], "C")
        self.assertIn("spec tools/test_thing.py was edited", result["escalations"])


if __name__ == "__main__":
    unittest.main()

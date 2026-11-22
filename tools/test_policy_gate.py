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


if __name__ == "__main__":
    unittest.main()

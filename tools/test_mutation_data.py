#!/usr/bin/env python3
"""tools/mutation_check.py reads tools/kernel_mutants.py as data, never runs it (#185).

kernel_mutants.py is lane B. When the runner imported it, the file ran inside the
judge, where it could patch subprocess or exit 0 before a single mutant ran.
"""
import ast
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))


def load_runner():
    spec = importlib.util.spec_from_file_location("mutation_check_under_test", TOOLS / "mutation_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mc = load_runner()


class NoImportTests(unittest.TestCase):
    def test_the_runner_does_not_import_the_mutant_file(self):
        tree = ast.parse((TOOLS / "mutation_check.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertNotIn("kernel_mutants", [a.name for a in node.names])
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, "kernel_mutants")
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") in ("import_module", "__import__"):
                self.fail("the runner imports a module dynamically")

    def test_the_real_file_reads_the_same_as_its_literals(self):
        tree = ast.parse((TOOLS / "kernel_mutants.py").read_text(encoding="utf-8"))
        literal = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)}
        self.assertEqual(mc.BEND_MUTANTS, literal["BEND_MUTANTS"])
        self.assertEqual(mc.RUST_MUTANTS, literal["RUST_MUTANTS"])
        self.assertGreater(len(mc.BEND_MUTANTS), 0)
        self.assertGreater(len(mc.RUST_MUTANTS), 0)


GOOD = '"""Doc."""\nBEND_MUTANTS = [("b1", "x", "y")]\nRUST_MUTANTS = [("r1", "x", "")]\nSHOWCASE = ["b1"]\n'


class LoaderTests(unittest.TestCase):
    def test_a_data_file_loads(self):
        self.assertEqual(mc.load_mutants(GOOD), ([("b1", "x", "y")], [("r1", "x", "")]))

    def test_code_is_refused_and_never_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "ran"
            for text in (
                f"import os\nopen({str(marker)!r}, 'w')\n" + GOOD,
                GOOD + f"open({str(marker)!r}, 'w')\n",
                GOOD + "import subprocess\n",
                GOOD + "def f():\n    pass\n",
                GOOD + 'BEND_MUTANTS += [("b2", "x", "y")]\n',
                GOOD + 'RUST_MUTANTS.append(("r2", "x", "y"))\n',
                GOOD + "alias = BEND_MUTANTS\n",
                GOOD + 'BEND_MUTANTS = [("b3", "x", "y")]\n',
                GOOD.replace('[("b1", "x", "y")]', '[("b1", "x", "y")] + []'),
                GOOD.replace('[("b1", "x", "y")]', "__import__('os').system('true')"),
            ):
                with self.assertRaises(ValueError, msg=text):
                    mc.load_mutants(text)
            self.assertFalse(marker.exists())

    def test_entries_must_be_named_triples(self):
        for bad in ('[("b1", "x")]', '[("", "x", "y")]', '[("b1", "", "y")]', '[("b1", "x", 3)]',
                    '[["b1", "x", "y"]]', '[]', '("b1", "x", "y")', '[("b1", "x", "y"), ("b1", "z", "w")]'):
            with self.assertRaises(ValueError, msg=bad):
                mc.load_mutants(GOOD.replace('[("b1", "x", "y")]', bad))

    def test_both_lists_are_required(self):
        for text in ('BEND_MUTANTS = [("b1", "x", "y")]\n', 'RUST_MUTANTS = [("r1", "x", "y")]\n', '"""Doc."""\n'):
            with self.assertRaises(ValueError):
                mc.load_mutants(text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for tools/corpus_run.py and for the corpus in ci/corpus/. The corpus must
pass against this checkout, and it must fail against copies of the gate with one rule
weakened, which is what makes it worth running (#125)."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import corpus_run as cr

ROOT = TOOLS.parent
CORPUS = ROOT / "ci/corpus"


def head_copy(tmp, patch=None):
    """A head checkout holding only what the corpus runner reads, with the gate
    optionally weakened by `patch`, a list of (old, new) replacements in policy_check.py."""
    head = Path(tmp) / "head"
    for name in (*cr.GATE_FILES, *cr.REPO_FILES):
        (head / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, head / name)
    gate = head / "tools/policy_check.py"
    text = gate.read_text(encoding="utf-8")
    for old, new in patch or []:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    gate.write_text(text, encoding="utf-8")
    return head


def write_case(corpus, name, case, files=None):
    entry = corpus / name
    entry.mkdir(parents=True)
    (entry / "case.toml").write_text(case, encoding="utf-8")
    for path, text in (files or {}).items():
        (entry / path).parent.mkdir(parents=True, exist_ok=True)
        (entry / path).write_text(text, encoding="utf-8")


class RealCorpusTests(unittest.TestCase):
    def test_the_corpus_passes_against_this_checkout(self):
        report = cr.run(ROOT, CORPUS)
        self.assertEqual(report["failed"], {})
        self.assertEqual(len(report["ran"]), len(list(CORPUS.glob("*/*/case.toml"))))

    def test_every_checker_has_cases_and_every_reject_has_a_twin(self):
        report = cr.run(ROOT, CORPUS)
        for checker in cr.CHECKERS:
            self.assertTrue(any(name.startswith(checker + "/") for name in report["ran"]), checker)


class WeakenedGateTests(unittest.TestCase):
    """Each weakening of the gate must make at least the named cases fail."""

    def failures(self, patch):
        with tempfile.TemporaryDirectory() as tmp:
            return cr.run(head_copy(tmp, patch), CORPUS)["failed"]

    def test_the_unweakened_copy_passes(self):
        self.assertEqual(self.failures([]), {})

    def test_a_gate_without_the_spec_ratchet_fails(self):
        failed = self.failures([("    escalations = ratchets(base_get, head_get) + spec_ratchets(paths, base_get, head_get)\n",
                                 "    escalations = ratchets(base_get, head_get)\n")])
        self.assertIn("classify/spec-helper-shrunk", failed)
        self.assertIn("classify/spec-removed", failed)

    def test_a_gate_that_lets_a_law_go_fails(self):
        failed = self.failures([('            out.append(f"law {name} was removed")\n', "            pass\n")])
        self.assertIn("classify/law-removed", failed)

    def test_a_gate_that_lets_status_rise_fails(self):
        failed = self.failures([('RANK.get(new.get("status"), 99) > RANK.get(old.get("status"), 99)', "False")])
        self.assertIn("classify/status-raised", failed)

    def test_a_gate_that_lets_platforms_through_fails(self):
        failed = self.failures([('old.get("platforms", []) != new.get("platforms", [])', "False")])
        self.assertIn("classify/platforms-added", failed)

    def test_a_gate_that_forgets_raw_identifiers_fails(self):
        failed = self.failures([('return text[2:] if kind == "ident" and text.startswith("r#") else text', "return text")])
        self.assertIn("invariants/raw-identifier-include", failed)

    def test_a_gate_that_allows_include_fails(self):
        failed = self.failures([('    "include": "reads a file at build time",\n', "")])
        self.assertIn("invariants/renamed-include-import", failed)

    def test_a_gate_that_accepts_forbid_anywhere_fails(self):
        failed = self.failures([("                if list(attr) not in leading:", "                if False:")])
        self.assertIn("invariants/forbid-in-nested-module", failed)

    def test_a_gate_that_rejects_everything_fails_the_twins(self):
        failed = self.failures([('    if escalations:\n        lane = "C"\n',
                                 '    escalations = escalations or ["everything"]\n    lane = "C"\n')])
        self.assertIn("classify/law-added", failed)
        self.assertIn("classify/claim-added", failed)


class CompletenessTests(unittest.TestCase):
    ACCEPT = 'checker = "invariants"\norigin = "test"\nexpect = "accept"\n'
    KERNEL = {"tree/crates/containment-kernel/src/lib.rs": "#![no_std]\n#![forbid(unsafe_code)]\n"}

    def run_corpus(self, build):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "corpus"
            corpus.mkdir()
            build(corpus)
            return cr.run(ROOT, corpus)["failed"]

    def test_an_empty_corpus_fails(self):
        self.assertEqual(self.run_corpus(lambda c: None), {"<corpus>": "no case ran"})

    def test_a_directory_without_a_case_fails(self):
        def build(corpus):
            write_case(corpus, "invariants/ok", self.ACCEPT, self.KERNEL)
            (corpus / "invariants/forgotten").mkdir()
        self.assertEqual(list(self.run_corpus(build)), ["invariants/forgotten"])

    def test_an_unknown_or_misplaced_checker_fails(self):
        def build(corpus):
            write_case(corpus, "invariants/ok", self.ACCEPT, self.KERNEL)
            write_case(corpus, "pins/x", 'checker = "pins"\n')
            write_case(corpus, "classify/y", self.ACCEPT, self.KERNEL)
        self.assertEqual(sorted(self.run_corpus(build)), ["classify/y", "pins/x"])

    def test_a_reject_case_needs_an_accept_twin(self):
        reject = 'checker = "invariants"\norigin = "test"\nexpect = "reject"\ntwin = "%s"\n'
        def build(corpus):
            write_case(corpus, "invariants/ok", self.ACCEPT, self.KERNEL)
            write_case(corpus, "invariants/no-twin", reject % "missing", self.KERNEL)
            write_case(corpus, "invariants/reject-twin", reject % "no-twin", self.KERNEL)
        failed = self.run_corpus(build)
        self.assertIn("needs an accept twin", failed["invariants/no-twin"])
        self.assertIn("needs an accept twin", failed["invariants/reject-twin"])


if __name__ == "__main__":
    unittest.main()

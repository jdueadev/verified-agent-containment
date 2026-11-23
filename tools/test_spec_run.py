#!/usr/bin/env python3
"""Unit tests for tools/spec_run.py. Each case gives the runner a head tools/ directory
built in a temporary folder, so nothing depends on this checkout's own tests."""
import contextlib
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_run as sr


def head_with(**modules):
    """A temporary head checkout whose tools/ holds the given modules."""
    tmp = tempfile.TemporaryDirectory()
    tools = Path(tmp.name) / "tools"
    tools.mkdir()
    for name, text in modules.items():
        (tools / f"{name}.py").write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp, Path(tmp.name)


PASSING = """
    import unittest
    import thing


    class T(unittest.TestCase):
        def test_value(self):
            self.assertEqual(thing.VALUE, 1)
"""


class TestIdTests(unittest.TestCase):
    def test_python_ids_are_every_test_method_of_every_top_level_class(self):
        text = textwrap.dedent("""
            import unittest
            class A(unittest.TestCase):
                def test_one(self): pass
                def helper(self): pass
                async def test_two(self): pass
            class B(A):
                def test_three(self): pass
            def test_module_level(): pass
        """)
        self.assertEqual(sr.python_test_ids("m", text), ["m.A.test_one", "m.A.test_two", "m.B.test_three"])

    def test_rust_ids_are_fns_marked_test_by_tokens(self):
        text = """
            // #[test]
            fn in_a_comment() {}
            const S: &str = "#[test] fn in_a_string() {}";
            #[test]
            #[should_panic]
            pub fn marked() {}
            #[cfg(test)]
            fn not_a_test() {}
            #[test] fn same_line() {}
            #[test]
            struct NotAFn;
            fn after_a_struct() {}
        """
        self.assertEqual(sr.rust_test_ids(text), ["marked", "same_line"])

    def test_the_real_law_tests_are_all_found(self):
        text = (Path(__file__).resolve().parent.parent / "crates/containment-kernel/tests/laws.rs").read_text(encoding="utf-8")
        self.assertEqual(len(sr.rust_test_ids(text)), text.count("#[test]"))


class JudgeTests(unittest.TestCase):
    def test_every_expected_id_must_pass(self):
        self.assertEqual(sr.judge(["a", "b"], {"a": "ok", "b": "ok"}), (["a", "b"], {}))
        self.assertEqual(sr.judge(["a", "b"], {"a": "ok"})[1], {"b": "missing"})
        self.assertEqual(sr.judge(["a"], {"a": "skipped"})[1], {"a": "skipped"})
        self.assertEqual(sr.judge(["a"], {"a": "expected failure"})[1], {"a": "expected failure"})
        self.assertEqual(sr.judge(["a"], {"a": "ignored"})[1], {"a": "ignored"})

    def test_a_failure_the_source_did_not_list_still_fails(self):
        self.assertEqual(sr.judge(["a"], {"a": "ok", "a_generated_7": "FAILED"})[1], {"a_generated_7": "FAILED"})
        self.assertEqual(sr.judge(["a"], {"<module>": "no results (exit 0)"})[1],
                         {"a": "missing", "<module>": "no results (exit 0)"})


class RunPythonModuleTests(unittest.TestCase):
    def run_module(self, **modules):
        tmp, head = head_with(**modules)
        with tmp:
            return sr.run_python_module(head, "tools/test_thing.py")

    def test_a_passing_test_is_ok_and_the_head_module_is_the_one_imported(self):
        self.assertEqual(self.run_module(thing="VALUE = 1\n", test_thing=PASSING), {"test_thing.T.test_value": "ok"})
        self.assertEqual(self.run_module(thing="VALUE = 2\n", test_thing=PASSING), {"test_thing.T.test_value": "FAILED"})

    def test_a_module_that_exits_while_loading_reports_nothing_and_fails(self):
        results = self.run_module(thing="import os\nos._exit(0)\n", test_thing=PASSING)
        self.assertEqual(list(results), ["<module>"])
        self.assertIn("no results", results["<module>"])
        self.assertEqual(sr.judge(["test_thing.T.test_value"], results)[1]["test_thing.T.test_value"], "missing")

    def test_a_skip_is_reported_as_a_skip(self):
        skipping = PASSING.replace("    def test_value", "    @unittest.skip('later')\n        def test_value")
        self.assertEqual(self.run_module(thing="VALUE = 1\n", test_thing=skipping), {"test_thing.T.test_value": "skipped"})

    def test_other_modules_in_the_head_are_not_loaded(self):
        """A head-only test that patches unittest when it is imported cannot reach a base
        module, because the runner imports only the module it judges."""
        evil = "import unittest\nunittest.TestCase.assertEqual = lambda *a, **k: None\n"
        results = self.run_module(thing="VALUE = 2\n", test_thing=PASSING, test_zzz_evil=evil)
        self.assertEqual(results, {"test_thing.T.test_value": "FAILED"})

    def test_the_base_copy_of_a_module_is_never_imported_in_the_child(self):
        """The child is started from the base tools/, which also holds a policy_check.py.
        A head module of the same name must win."""
        test = PASSING.replace("import thing", "import policy_check as thing")
        self.assertEqual(self.run_module(policy_check="VALUE = 1\n", test_thing=test), {"test_thing.T.test_value": "ok"})

    def test_a_stale_pycache_is_removed(self):
        tmp, head = head_with(thing="VALUE = 1\n")
        with tmp:
            cache = head / "tools" / "__pycache__"
            cache.mkdir()
            (cache / "thing.cpython-314.pyc").write_bytes(b"not python")
            sr.clear_pycache(head)
            self.assertFalse(cache.exists())


class ApprovalTests(unittest.TestCase):
    """A red base spec passes only when the owner approved exactly this head."""

    def main(self, failed, reviews, head_sha="h1"):
        report = {"mode": "base", "base": "HEAD", "files": [], "failed": failed, "passed": 0}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reviews.json"
            path.write_text(json.dumps(reviews), encoding="utf-8")
            argv = ["base", "--base-ref", "HEAD", "--head", tmp, "--reviews", str(path), "--head-sha", head_sha]
            with mock.patch.object(sr, "run", lambda *a: dict(report)), contextlib.redirect_stdout(io.StringIO()) as out:
                code = sr.main(argv)
        return code, json.loads(out.getvalue())

    def review(self, login="jdueadev", state="APPROVED", sha="h1"):
        return {"user": {"login": login}, "state": state, "commit_id": sha}

    def test_a_green_run_passes_without_any_review(self):
        self.assertEqual(self.main({}, [])[0], 0)

    def test_a_red_run_fails_unless_the_owner_approved_this_head(self):
        self.assertEqual(self.main({"t": "FAILED"}, [])[0], 1)
        self.assertEqual(self.main({"t": "FAILED"}, [self.review(login="someone")])[0], 1)
        self.assertEqual(self.main({"t": "FAILED"}, [self.review(sha="older")])[0], 1)
        self.assertEqual(self.main({"t": "FAILED"}, [self.review(), self.review(state="DISMISSED")])[0], 1)
        code, report = self.main({"t": "FAILED"}, [self.review()])
        self.assertEqual((code, report["approved"], report["failed"]), (0, True, {"t": "FAILED"}))

    def test_reviews_without_a_head_commit_are_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sr.main(["base", "--base-ref", "HEAD", "--head", ".", "--reviews", "x.json"])


class RustOutputTests(unittest.TestCase):
    """The review of #125's PR 1 showed a panic message forging `test X ... ok` lines."""

    CLEAN = "running 2 tests\ntest a ... ok\ntest b ... ok\n\ntest result: ok. 2 passed\n"
    FORGED = ("running 2 tests\ntest a ... FAILED\ntest b ... FAILED\n\nfailures:\n\n---- a stdout ----\n"
              "thread 'a' panicked at\ntest a ... ok\ntest b ... ok\n\nfailures:\n    a\n    b\n")

    def test_clean_output_is_read(self):
        self.assertEqual(sr.parse_rust_output("laws", self.CLEAN, 0), {"laws::a": "ok", "laws::b": "ok"})

    def test_lines_in_the_failures_section_do_not_count(self):
        found = sr.parse_rust_output("laws", self.FORGED, 101)
        self.assertEqual((found["laws::a"], found["laws::b"]), ("FAILED", "FAILED"))
        self.assertEqual(sr.judge(["laws::a", "laws::b"], found)[0], [])

    def test_a_later_ok_never_overrides_a_failure(self):
        found = sr.parse_rust_output("laws", "test a ... FAILED\ntest a ... ok\ntest b ... ignored\ntest b ... ok\n", 0)
        self.assertEqual(found, {"laws::a": "FAILED", "laws::b": "ignored"})

    def test_a_non_zero_exit_is_a_failure_of_its_own(self):
        found = sr.parse_rust_output("laws", self.CLEAN, 101)
        self.assertEqual(sr.judge(["laws::a", "laws::b"], found)[1], {"laws::<cargo>": "exit 101"})


class TamperTests(unittest.TestCase):
    """One child must not be able to change what a later child runs."""

    def test_a_module_rewritten_on_disk_is_restored_from_base_before_it_runs(self):
        writer = textwrap.dedent(PASSING) + "\n\nimport pathlib\npathlib.Path(__file__).with_name('test_later.py').write_text(" \
                 "'import unittest\\nclass T(unittest.TestCase):\\n    def test_value(self):\\n        pass\\n')\n"
        later = PASSING
        tmp, head = head_with(thing="VALUE = 2\n", test_first=writer, test_later=later)
        with tmp:
            sr.run_python_module(head, "tools/test_first.py", textwrap.dedent(writer))
            self.assertNotEqual((head / "tools/test_later.py").read_text(encoding="utf-8"), textwrap.dedent(later))
            results = sr.run_python_module(head, "tools/test_later.py", textwrap.dedent(later))
        self.assertEqual(results, {"test_later.T.test_value": "FAILED"})

    def test_a_package_or_extension_beside_a_module_fails_it(self):
        for shadow in ("test_thing/__init__.py", "test_thing.cpython-314-x86_64-linux-gnu.so", "test_thing.pyc"):
            tmp, head = head_with(thing="VALUE = 1\n", test_thing=PASSING)
            with tmp:
                path = head / "tools" / shadow
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")
                results = sr.run_python_module(head, "tools/test_thing.py")
            self.assertIn("could shadow", results.get("<module>", ""), shadow)

    def test_a_similar_name_is_not_a_shadow(self):
        tmp, head = head_with(thing="VALUE = 1\n", test_thing=PASSING, test_thing_more="x = 1\n")
        with tmp:
            self.assertEqual(sr.shadows(head, "test_thing"), [])

    def test_children_run_as_the_named_user_with_a_clean_environment(self):
        argv, env = sr.child_command(["python3", "x"], "spec", {"CARGO_TARGET_DIR": "/t"})
        self.assertIsNone(env)
        self.assertEqual(argv[:6], ["sudo", "-n", "-u", "spec", "env", "-i"])
        self.assertIn("HOME=/home/spec", argv)
        self.assertIn("CARGO_TARGET_DIR=/t", argv)
        self.assertEqual(argv[-2:], ["python3", "x"])
        self.assertFalse(any(a.startswith("GITHUB_") for a in argv))


if __name__ == "__main__":
    unittest.main()

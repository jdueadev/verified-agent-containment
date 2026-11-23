#!/usr/bin/env python3
"""Unit tests for the no-root driver, tools/vac.py.

No network and no cargo: the root-command refusals and --help are subprocesses
of vac itself, and the summary is rendered in-process. Nothing here starts a
build, a test suite, or scripts/check.sh.
"""
import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
VAC_PATH = TOOLS / "vac.py"
ROOT_COMMANDS = ("attack-suite", "live", "live-suite", "redteam", "ctl", "hud")
HELP_ARGS = (
    ("build",),
    ("check",),
    ("run",),
    ("run", "sim"),
    ("run", "servers"),
    ("status",),
) + tuple((name,) for name in ROOT_COMMANDS)


def load_vac():
    spec = importlib.util.spec_from_file_location("vac_under_test", VAC_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vac = load_vac()


def run_vac(*args):
    return subprocess.run(
        [sys.executable, str(VAC_PATH), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


class Refusals(unittest.TestCase):
    def test_refused_commands_are_exactly_the_root_set(self):
        self.assertEqual(vac.REFUSED, ROOT_COMMANDS)

    def test_root_commands_exit_2_citing_inv_11(self):
        for name in ROOT_COMMANDS:
            with self.subTest(name=name):
                child = run_vac(name)
                self.assertEqual(child.returncode, 2, child.stdout + child.stderr)
                self.assertEqual(child.stdout, "")
                self.assertIn("INV-11", child.stderr)
                self.assertIn("AGENTS.md", child.stderr)
                self.assertIn("throwaway", child.stderr)
                self.assertNotIn("Traceback", child.stderr)


class Help(unittest.TestCase):
    def test_root_help(self):
        child = run_vac("--help")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn("usage:", child.stdout)
        for name in ("build", "check", "run", "status", *ROOT_COMMANDS):
            self.assertIn(name, child.stdout)

    def test_each_subcommand_help(self):
        for args in HELP_ARGS:
            with self.subTest(args=args):
                child = run_vac(*args, "--help")
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertIn("usage:", child.stdout)
                self.assertIn(args[-1], child.stdout)


class Summary(unittest.TestCase):
    def test_tier_line_names_only_passes_and_never_t1_or_t2(self):
        rows = (
            ("policy", "PASS", 1.25),
            ("claims", "SKIPPED", 0),
            ("kernel", "FAIL", 3),
            ("differential", "PASS", 0.4),
            ("unittest", "PASS", 12.5),
        )
        text = vac.format_summary(rows)
        self.assertNotRegex(text, r"T[12]")
        tier = [line for line in text.splitlines() if line.startswith("tier:")]
        self.assertEqual(tier, ["tier: T0 (checks run: policy, differential, unittest)"])
        self.assertNotIn("claims", tier[0])
        self.assertNotIn("kernel", tier[0])
        for name, status, _seconds in rows:
            self.assertIn(name, text)
            self.assertIn(status, text)

    def test_a_run_with_no_pass_still_says_t0(self):
        text = vac.format_summary((("policy", "FAIL", 1), ("claims", "SKIPPED", 0)))
        self.assertEqual(
            [line for line in text.splitlines() if line.startswith("tier:")],
            ["tier: T0 (checks run: none)"],
        )
        self.assertNotRegex(text, r"T[12]")

    def test_an_empty_summary_says_t0(self):
        text = vac.format_summary(())
        self.assertIn("tier: T0 (checks run: none)", text)
        self.assertNotRegex(text, r"T[12]")

    def test_check_names_do_not_look_like_a_higher_tier(self):
        for check in vac.CHECKS:
            self.assertNotRegex(check.name, r"T[12]")


class Checks(unittest.TestCase):
    def test_t0_commands_match_the_no_root_set(self):
        by_name = {check.name: check.argv for check in vac.CHECKS}
        self.assertEqual(
            list(by_name),
            ["policy", "claims", "kernel", "differential", "unittest"],
        )
        self.assertEqual(by_name["policy"], ("python3", "tools/policy_check.py", "invariants"))
        self.assertEqual(
            by_name["claims"],
            ("python3", "tools/claims_check.py", "--affected", "origin/main"),
        )
        self.assertEqual(
            by_name["kernel"],
            ("cargo", "test", "-q", "--locked", "-p", "containment-kernel"),
        )
        self.assertEqual(
            by_name["differential"],
            ("target/debug/containment-lab", "differential-cases", "3", "24301"),
        )
        self.assertEqual(
            by_name["unittest"],
            ("python3", "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"),
        )
        blob = " ".join(" ".join(check.argv) for check in vac.CHECKS)
        self.assertNotIn("check.sh", blob)
        self.assertNotIn("scripts/", blob)
        self.assertEqual(vac.BUILD_ARGV, ("cargo", "build", "-q", "--locked", "-p", "containment-host"))

    def test_a_failure_does_not_stop_the_later_checks(self):
        seen = []

        def fake(check):
            seen.append(check.name)
            if check.name == "policy":
                return "FAIL", 0.1
            if check.name == "claims":
                return "SKIPPED", 0.0
            return "PASS", 0.2

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rows, code = vac.run_selected(vac.CHECKS, fake)
        self.assertEqual(seen, [check.name for check in vac.CHECKS])
        self.assertEqual(code, 1)
        text = vac.format_summary(rows)
        self.assertIn("tier: T0 (checks run: kernel, differential, unittest)", text)
        self.assertNotRegex(text, r"T[12]")
        self.assertNotIn("tier:", buf.getvalue())

    def test_skips_are_not_failures(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rows, code = vac.run_selected(
                (vac.Check("claims", ()),),
                lambda check: ("SKIPPED", 0.0),
            )
        self.assertEqual(code, 0)
        self.assertEqual(rows, [("claims", "SKIPPED", 0.0)])
        text = vac.format_summary(rows)
        self.assertIn("tier: T0 (checks run: none)", text)
        self.assertNotRegex(text, r"T[12]")

    def test_claims_is_skipped_when_origin_main_is_missing(self):
        check = next(item for item in vac.CHECKS if item.name == "claims")
        original = vac.git_ref_exists
        vac.git_ref_exists = lambda ref: False
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                status, _seconds = vac.run_one(check)
        finally:
            vac.git_ref_exists = original
        self.assertEqual(status, "SKIPPED")
        self.assertIn("SKIPPED claims: origin/main is missing", out.getvalue())

    def test_a_missing_driver_fails_with_a_clear_message(self):
        original = vac.DRIVER_REL
        vac.DRIVER_REL = Path(".claude/skills/run-verified-agent-containment/missing-driver.mjs")
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                code = vac.cmd_run("servers", [])
        finally:
            vac.DRIVER_REL = original
        self.assertEqual(code, 1)
        message = err.getvalue()
        self.assertIn("absent", message)
        self.assertIn(str(vac.DRIVER_REL), message)
        self.assertNotIn("Traceback", message)


class Shape(unittest.TestCase):
    def test_shebang_and_executable_bit(self):
        text = VAC_PATH.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/usr/bin/env python3\n"))
        self.assertNotIn("\r", text)
        self.assertTrue(VAC_PATH.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()

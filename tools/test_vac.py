#!/usr/bin/env python3
import argparse
import contextlib
import importlib
import importlib.util
import io
import json
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
    ("preflight",),
    ("lab",),
    ("lab", "plan"),
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

    def test_root_commands_exit_2_citing_the_lab_restriction(self):
        for name in ROOT_COMMANDS:
            with self.subTest(name=name):
                child = run_vac(name)
                self.assertEqual(child.returncode, 2, child.stdout + child.stderr)
                self.assertEqual(child.stdout, "")
                self.assertIn("LAB-THROWAWAY", child.stderr)
                self.assertNotIn("INV-", child.stderr)
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

class Checks(unittest.TestCase):
    def test_a_missing_driver_fails_with_a_clear_message(self):
        original = vac.DRIVER_REL
        missing = Path(".claude/skills/run-verified-agent-containment/missing-driver.mjs")
        vac.DRIVER_REL = missing
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                code = vac.cmd_run("servers", [])
        finally:
            vac.DRIVER_REL = original
        self.assertEqual(code, 1)
        message = err.getvalue()
        self.assertIn("absent", message)
        self.assertIn(str(missing), message)
        self.assertNotIn("Traceback", message)


class VerifyRecord(unittest.TestCase):
    def record(self, answers):
        core, registry = vac.load_registry()
        verify = importlib.import_module("vac_verify")
        queued, recorded = list(answers), []
        saved = (vac.git, core.run, core.render_text, verify.record)
        vac.git = lambda args, cwd=None: queued.pop(0)
        core.run = lambda rules, stage, ctx: [core.Outcome(registry.RULES[0], "PASS", (), ())]
        core.render_text = lambda *args, **kwargs: None
        verify.record = lambda root, head: recorded.append(head) or ["C-1"]
        err = io.StringIO()
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = vac.cmd_verify(argparse.Namespace(action="record", base="origin/main"))
        finally:
            vac.git, core.run, core.render_text, verify.record = saved
        return code, err.getvalue(), recorded

    def test_a_stable_head_is_recorded(self):
        head = (0, "a" * 40 + "\n", "")
        code, err, recorded = self.record([(0, "", ""), head, (0, "", ""), head])
        self.assertEqual((code, err, recorded), (0, "", ["a" * 40]))

    def test_a_tracked_file_the_t1_run_changed_refuses_the_record(self):
        head = (0, "a" * 40 + "\n", "")
        for changed in (" M formal/PROOF.bend\n", " M results/mutation-check.json\n"):
            with self.subTest(changed=changed):
                code, err, recorded = self.record([(0, "", ""), head, (0, changed, ""), head])
                self.assertEqual((code, recorded), (2, []))
                self.assertIn("changed during the T1 run", err)

    def test_any_uncommitted_change_refuses_the_record(self):
        code, err, recorded = self.record([(0, " M Cargo.toml\n", "")])
        self.assertEqual((code, recorded), (2, []))
        self.assertIn("commit every change first", err)

    def test_a_failed_git_status_is_no_clean_checkout(self):
        code, err, recorded = self.record([(1, "", "fatal: not a git repository\n")])
        self.assertEqual((code, recorded), (2, []))
        self.assertIn("git status failed", err)

    def test_a_head_that_moves_during_the_run_is_never_recorded(self):
        code, err, recorded = self.record([(0, "", ""), (0, "a" * 40 + "\n", ""), (0, "", ""), (0, "b" * 40 + "\n", "")])
        self.assertEqual((code, recorded), (2, []))
        self.assertIn("HEAD moved from aaaaaaaaaaaa to bbbbbbbbbbbb", err)


class Shape(unittest.TestCase):
    def test_shebang_and_executable_bit(self):
        raw = VAC_PATH.read_bytes()
        self.assertTrue(raw.startswith(b"#!/usr/bin/env python3\n"))
        self.assertNotIn(b"\r", raw)
        self.assertTrue(VAC_PATH.stat().st_mode & 0o111)


CLAIMS = [
    {"id": "L-ISO-02", "evidence": ["scenario:sandbox_escape", "sabotage:memfd_exec", "doc:x.md#y"],
     "platforms": [{"name": "wsl2-6.18.58"}, {"name": "wsl2-6.18.58"}]},
    {"id": "K-1", "evidence": ["law:a", "mutant:b"], "platforms": []},
]


class Preflight(unittest.TestCase):
    def test_engine_choice(self):
        has = lambda names: (lambda name: f"/usr/bin/{name}" if name in names else None)
        self.assertEqual(vac.pick_engine("auto", has({"podman", "docker"}), True), "podman")
        self.assertEqual(vac.pick_engine("auto", has({"docker"}), True), "docker")
        self.assertEqual(vac.pick_engine("auto", has(set()), True), "host")
        self.assertEqual(vac.pick_engine("auto", has({"podman"}), False), "host")
        self.assertEqual(vac.pick_engine("host", has({"podman"}), True), "host")
        self.assertIsNone(vac.pick_engine("podman", has(set()), True))
        self.assertIsNone(vac.pick_engine("docker", has({"docker"}), False))

    def test_steps_need_no_root_and_write_no_results(self):
        for engine in ("podman", "docker", "host"):
            for name, argv, env in vac.preflight_steps(engine):
                text = " ".join(argv)
                self.assertNotIn("sudo", text, name)
                for refused in ROOT_COMMANDS:
                    self.assertNotIn(f" {refused}", f" {text}", (name, refused))
                self.assertNotIn("results", text, name)
                self.assertNotIn("check.sh --strict", text, name)
        container = vac.preflight_steps("podman")
        self.assertEqual(container, [("container", ("scripts/check-in-container.sh", "--no-strict"), {"ENGINE": "podman"})])
        names = [name for name, _argv, _env in vac.preflight_steps("host")]
        self.assertEqual(names, ["host-tests", "host-tests-sabotage", "release-build", "release-build-sabotage"])

    def test_stale_lab_evidence_names_only_lab_refs(self):
        report = {"errors": ["CI-4 L-ISO-02: stale, crates/x.rs changed after its platform commit; rerun",
                             "CI-3 K-1: something else", "CI-4 NOPE: stale"]}
        self.assertEqual(vac.stale_lab_evidence(report, CLAIMS),
                         [("L-ISO-02", ["scenario:sandbox_escape", "sabotage:memfd_exec"], ["wsl2-6.18.58"])])
        self.assertEqual(vac.stale_lab_evidence({"errors": []}, CLAIMS), [])

    def test_not_exercised_is_explicit(self):
        for stale, problem in (([("L-ISO-02", ["scenario:sandbox_escape"], ["wsl2-6.18.58"])], None),
                               ([], None), (None, "boom")):
            text = vac.format_not_exercised(stale, problem)
            self.assertTrue(text.startswith("not exercised: any lab evidence"), text)
            self.assertNotIn("not exercised: nothing", text)
        self.assertIn("L-ISO-02: scenario:sandbox_escape", vac.format_not_exercised(
            [("L-ISO-02", ["scenario:sandbox_escape"], ["wsl2-6.18.58"])]))
        self.assertIn("unknown (boom)", vac.format_not_exercised(None, "boom"))

    def test_preflight_summary_is_t0_whatever_passes(self):
        summary = vac.format_summary([("container", "PASS", 1.0)])
        self.assertIn("tier: T0", summary)
        self.assertNotIn("T1", summary)
        self.assertNotIn("T2", summary.replace("T0", ""))

    def test_lab_plan_is_text_for_the_maintainer(self):
        text = vac.lab_plan_text("0babf9e", [("L-ISO-02", ["scenario:sandbox_escape"], ["wsl2-6.18.58"])])
        for needle in ("the maintainer runs this, never an agent", "LAB-THROWAWAY", "git checkout --detach 0babf9e",
                       "git bundle create repo.bundle HEAD", "rev-parse HEAD",
                       "run-lab.cmd -Only suites", "throwaway WSL2 distro", "An agent never writes these",
                       "claims_check.py --strict", "L-ISO-02"):
            self.assertIn(needle, text)
        self.assertNotIn("INV-", text)
        self.assertNotIn("\r", text)
        unknown = vac.lab_plan_text("0babf9e", None, "the strict claims check failed")
        self.assertIn("unknown: the strict claims check failed", unknown)
        self.assertNotIn("none: the strict claims check reports no stale claim", unknown)

    def test_other_strict_errors_make_the_stale_list_unknown(self):
        class Done:
            def __init__(self, code, out):
                self.returncode, self.stdout = code, out
        real = vac.subprocess.run
        try:
            for code, report in ((1, {"errors": ["CI-2 inventory: broken"]}),
                                 (1, {"errors": ["CI-4 L-ISO-02: stale", "CI-3 K-1: missing"]}),
                                 (1, {"errors": []})):
                vac.subprocess.run = lambda *a, _c=code, _r=report, **k: Done(_c, json.dumps(_r))
                stale, problem = vac.read_stale_lab_evidence()
                self.assertIsNone(stale, report)
                self.assertIn("other than staleness", problem)
            vac.subprocess.run = lambda *a, **k: Done(1, json.dumps({"errors": ["CI-4 L-ISO-02: stale, x"]}))
            stale, problem = vac.read_stale_lab_evidence()
            self.assertIsNone(problem)
            self.assertEqual([cid for cid, _r, _p in stale], ["L-ISO-02"])
        finally:
            vac.subprocess.run = real

    def test_lab_plan_runs_nothing_but_the_read_only_check(self):
        calls = []
        strict = [sys.executable, "tools/claims_check.py", "--strict"]
        real_run, real_git = vac.subprocess.run, vac.git

        class Done:
            returncode, stdout = 0, json.dumps({"errors": []})

        def spy(argv, *args, **kwargs):
            calls.append(list(argv))
            if list(argv) != strict:
                raise AssertionError(f"vac lab plan started {argv}")
            return Done()
        vac.subprocess.run = spy
        vac.git = lambda argv: (0, "f" * 40 + "\n", "")
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                vac.cmd_lab(None)
        finally:
            vac.subprocess.run, vac.git = real_run, real_git
        self.assertEqual(calls, [strict])
        self.assertIn("Root lab run (T2)", out.getvalue())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""scripts/check.sh's arguments decide how claims_check.py runs (#175).

The real scripts/check.sh runs in a scratch tree, with a stub for every tool it calls
first on PATH. Each stub records its argv, so the test sees the claims_check.py
invocation each argument list produces, not what the script's text seems to say.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ("python3", "cargo", "bend", "bun", "node", "java")
STUB = '#!/bin/sh\nprintf \'%s\\n\' "$(basename "$0") $*" >> "$CHECK_LOG"\n'


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class CheckScriptArgs(unittest.TestCase):
    def run_check(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            tree, stubs, log = Path(tmp) / "repo", Path(tmp) / "bin", Path(tmp) / "log"
            (tree / "scripts").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/check.sh", tree / "scripts/check.sh")
            for d in ("formal", "tools", "target/debug"):
                (tree / d).mkdir(parents=True, exist_ok=True)
            stubs.mkdir()
            for path in [stubs / t for t in TOOLS] + [tree / "scripts/build-wasm.sh", tree / "tools/tla_check.sh",
                                                     tree / "target/debug/containment-lab"]:
                path.write_text(STUB, encoding="utf-8")
                path.chmod(0o755)
            tla = Path(tmp) / "tla2tools.jar"
            tla.write_bytes(b"")
            log.write_text("", encoding="utf-8")
            env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
                       CHECK_LOG=str(log), TLA2TOOLS=str(tla))
            child = subprocess.run(["bash", str(tree / "scripts/check.sh"), *args], cwd=tree, env=env,
                                   capture_output=True, text=True, timeout=120)
            calls = [c.replace(tmp, "<tmp>") for c in log.read_text(encoding="utf-8").splitlines()]
        claims = [c for c in calls if c.startswith("python3 tools/claims_check.py")]
        return child, calls, claims

    def test_plain_run_is_not_strict(self):
        child, calls, claims = self.run_check()
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(claims, ["python3 tools/claims_check.py"])
        self.assertEqual(calls[-1], "python3 -m unittest discover -s tools -p test_*.py")

    def test_strict_is_the_release_gate(self):
        child, _, claims = self.run_check("--strict")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(claims, ["python3 tools/claims_check.py --strict"])

    def test_no_strict_is_accepted_and_changes_nothing(self):
        child, calls, claims = self.run_check("--no-strict")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(claims, ["python3 tools/claims_check.py"])
        self.assertIn("changes nothing", child.stderr)
        self.assertEqual(calls, self.run_check()[1])

    def test_an_unknown_option_runs_nothing(self):
        child, calls, _ = self.run_check("--bogus")
        self.assertEqual(child.returncode, 2)
        self.assertEqual(calls, [])

    def test_the_last_strict_flag_cannot_be_undone(self):
        # --strict then --no-strict stays strict: --no-strict only says it is the default.
        child, _, claims = self.run_check("--strict", "--no-strict")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(claims, ["python3 tools/claims_check.py --strict"])


if __name__ == "__main__":
    unittest.main()

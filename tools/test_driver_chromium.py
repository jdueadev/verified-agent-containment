#!/usr/bin/env python3
"""The simulator driver finds a Chromium on PATH when CHROMIUM and the playwright cache are absent (#196)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / ".claude/skills/run-verified-agent-containment/driver.mjs"


@unittest.skipIf(os.name == "nt" or shutil.which("node") is None, "needs node and a POSIX shell script on PATH")
class ChromiumOnPathTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)
        (self.tmp / "home").mkdir()  # no ~/.cache/ms-playwright
        (self.tmp / "bin").mkdir()
        self.marker = self.tmp / "started"
        # Absolute node path, so PATH holds only what each test puts there.
        self.node = str(Path(shutil.which("node")).resolve())

    def tearDown(self):
        self.dir.cleanup()

    def run_driver(self, path_dirs):
        env = {k: v for k, v in os.environ.items() if k != "CHROMIUM"}
        env["HOME"] = str(self.tmp / "home")
        env["PATH"] = os.pathsep.join(path_dirs)
        return subprocess.run(
            [self.node, str(DRIVER), "sim", "--out", str(self.tmp / "out")],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def test_google_chrome_on_path_is_used(self):
        fake = self.tmp / "bin" / "google-chrome"
        fake.write_text(f'#!/bin/sh\necho "$@" > "{self.marker}"\nexit 7\n', encoding="utf-8")
        fake.chmod(0o755)
        result = self.run_driver([str(self.tmp / "bin")])
        self.assertNotIn("no Chromium found", result.stderr)
        self.assertTrue(self.marker.exists(), f"fake google-chrome never ran: {result.stderr}")
        self.assertIn("--remote-debugging-port=0", self.marker.read_text(encoding="utf-8"))
        self.assertIn("chromium exited 7", result.stderr)
        self.assertEqual(result.returncode, 1)

    def test_non_executable_on_path_is_skipped(self):
        fake = self.tmp / "bin" / "google-chrome"
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o644)
        result = self.run_driver([str(self.tmp / "bin")])
        self.assertIn("no Chromium found", result.stderr)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()

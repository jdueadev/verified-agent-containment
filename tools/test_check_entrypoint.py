#!/usr/bin/env python3
"""The check container's tier line (#176): ci/check-entrypoint.sh's tier_line, sourced
in bash against a scratch repository, for each argument list and for a head that
changes a path that judges "passed"."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "ci/check-entrypoint.sh"
IMAGE = "sha256:" + "a" * 64
CONTEXT = "b" * 64


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
class TierLine(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "README.md").write_text("x\n", encoding="utf-8")
        (self.repo / "tools").mkdir()
        (self.repo / "tools/claims_check.py").write_text("x\n", encoding="utf-8")
        self.commit("base")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@localhost",
                               *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def tier(self, *args):
        head = self.git("rev-parse", "HEAD")
        script = ('source "$1"; shift; HEAD_SHA="$(git rev-parse HEAD)"; CHECK_IMAGE_ID="$IMG"; '
                  'CONTEXT_HASH="$CTX"; tier_line "$@"')
        env = dict(os.environ, IMG=IMAGE, CTX=CONTEXT, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        child = subprocess.run(["bash", "-c", script, "tier", str(ENTRYPOINT), *args], cwd=self.repo, env=env,
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(child.returncode, 0, child.stderr)
        line = child.stdout.strip()
        self.assertIn(f"at HEAD {head} (clean)", line)
        self.assertIn(f"image {IMAGE}, context {CONTEXT}", line)
        return line

    def test_a_plain_run_is_t1(self):
        self.assertTrue(self.tier().startswith("Tier: T1 (container,"), self.tier())

    def test_no_strict_is_the_plain_run(self):
        line = self.tier("--no-strict")
        self.assertTrue(line.startswith("Tier: T1 (container,"), line)

    def test_strict_is_t1_with_its_own_label_not_a_release(self):
        head = self.git("rev-parse", "HEAD")
        line = self.tier("--strict")
        self.assertTrue(line.startswith("Tier: T1 (container,"), line)
        self.assertTrue(line.endswith(f", strict claims check passed at {head}"), line)
        self.assertNotIn("release", line)

    def test_any_other_argument_is_t0(self):
        for args in (("--bogus",), ("--strict", "--no-strict"), ("--no-strict", "--no-strict"), ("",)):
            with self.subTest(args=args):
                line = self.tier(*args)
                self.assertTrue(line.startswith("Tier: T0 (container,"), line)
                self.assertIn("is not a plain scripts/check.sh", line)

    def test_a_modified_checker_is_named(self):
        (self.repo / "tools/claims_check.py").write_text("weaker\n", encoding="utf-8")
        (self.repo / "README.md").write_text("y\n", encoding="utf-8")
        self.commit("weaken the checker")
        for args in ((), ("--strict",)):
            with self.subTest(args=args):
                line = self.tier(*args)
                self.assertTrue(line.startswith("Tier: T1 (modified checker: tools/claims_check.py) (container,"),
                                line)

    def test_each_trusted_root_is_watched(self):
        for path in ("scripts/check.sh", "ci/check-entrypoint.sh", ".github/workflows/check.yml", "AGENTS.md",
                     "crates/containment-kernel/tests/laws.rs", "Cargo.lock"):
            with self.subTest(path=path):
                target = self.repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"{path}\n", encoding="utf-8")
                self.commit(path)
                self.assertIn(path, self.tier())

    def test_a_change_elsewhere_is_plain_t1(self):
        (self.repo / "README.md").write_text("y\n", encoding="utf-8")
        self.commit("docs")
        self.assertTrue(self.tier().startswith("Tier: T1 (container,"))

    def test_without_origin_main_it_cannot_tell(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        line = self.tier()
        self.assertTrue(line.startswith("Tier: T1 (modified checker: unknown, no merge base with origin/main)"), line)


if __name__ == "__main__":
    unittest.main()

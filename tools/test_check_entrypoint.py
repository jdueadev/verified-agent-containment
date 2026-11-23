#!/usr/bin/env python3
"""The check container's tier line (#176): ci/check-entrypoint.sh's tier_line, sourced
in bash against a scratch repository, for each argument list, and for heads whose
changes run or are judged in the run (anything but documentation)."""
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
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@localhost",
                               *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def tier(self, *args, base=None):
        head = self.git("rev-parse", "HEAD")
        script = ('source "$1"; shift; HEAD_SHA="$(git rev-parse HEAD)"; CHECK_IMAGE_ID="$IMG"; '
                  'CONTEXT_HASH="$CTX"; tier_line "$@"')
        env = dict(os.environ, IMG=IMAGE, CTX=CONTEXT, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                   CHECK_BASE_SHA=self.base if base is None else base)
        child = subprocess.run(["bash", "-c", script, "tier", str(ENTRYPOINT), *args], cwd=self.repo, env=env,
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(child.returncode, 0, child.stderr)
        line = child.stdout.strip()
        self.assertIn(f"at HEAD {head} (clean)", line)
        self.assertIn(f"image {IMAGE}, context {CONTEXT}", line)
        self.assertIn(f", base {self.base if base is None else base or 'none'}, ", line)
        return line

    def change(self, path, text="changed\n"):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        self.commit(path)

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
        self.change("tools/claims_check.py", "weaker\n")
        self.change("README.md", "y\n")
        for args in ((), ("--strict",)):
            with self.subTest(args=args):
                line = self.tier(*args)
                self.assertTrue(line.startswith("Tier: T1 (judged by its own changes: tools/claims_check.py) "
                                                "(container,"), line)

    def test_anything_that_runs_or_is_judged_is_named(self):
        # Security review: lab evidence, host and wasm build inputs, formal inputs, claims and
        # rules all passed as plain T1 under a fixed list of checker paths.
        for path in ("scripts/check.sh", "ci/check-entrypoint.sh", ".github/workflows/check.yml", "AGENTS.md",
                     "CLAUDE.md", ".claude/settings.json", "docs/decisions/0009-x.md", "docs/claims.md",
                     "crates/containment-kernel/tests/laws.rs", "crates/containment-kernel/src/lib.rs",
                     "crates/containment-host/src/harness.rs", "crates/containment-host/build.rs",
                     "crates/containment-wasm/build.rs", "Cargo.lock", "Cargo.toml", "rust-toolchain.toml",
                     ".cargo/config.toml", "results/attack-suite.json", "results/ci/lab-abc/live-suite.json",
                     "results/formal-verdict.json", "formal/LAWS.bend", "formal/host/HostModel.cfg", "claims.toml",
                     ".gitattributes", "web/build.py", "examples/live/policy.toml", "docs/cookbook/x/AGENTS.md"):
            with self.subTest(path=path):
                self.git("reset", "-q", "--hard", self.base)
                self.git("clean", "-qfdx")
                self.change(path, f"{path}\n")
                line = self.tier()
                self.assertTrue(line.startswith("Tier: T1 (judged by its own changes: "), line)
                self.assertIn(path, line)

    def test_a_long_list_is_cut_with_a_count(self):
        for n in range(15):
            self.change(f"tools/t{n:02}.py")
        line = self.tier()
        self.assertIn("tools/t11.py and 3 more)", line)
        self.assertNotIn("tools/t12.py", line)

    def test_documentation_alone_is_plain_t1(self):
        for path in ("README.md", "docs/verification.md", "docs/cookbook/snippets/x.json", "docs/blog/hud.png",
                     "crates/containment-host/README.md"):
            self.change(path)
        line = self.tier()
        self.assertTrue(line.startswith("Tier: T1 (container,"), line)

    def test_the_judged_repositorys_own_main_does_not_count(self):
        # Security review: moving the judged clone's origin/main to HEAD hid a weakened checker.
        self.change("tools/claims_check.py", "weaker\n")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.assertIn("judged by its own changes: tools/claims_check.py", self.tier())

    def test_without_a_usable_base_it_cannot_tell(self):
        for base in ("", "not-a-sha", "f" * 40):
            with self.subTest(base=base):
                line = self.tier(base=base)
                self.assertTrue(line.startswith("Tier: T1 (judged by its own changes: unknown, no usable base)"),
                                line)


if __name__ == "__main__":
    unittest.main()

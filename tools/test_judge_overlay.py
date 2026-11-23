#!/usr/bin/env python3
"""tools/judge_overlay.py: the base's judges over the head's code, deny by default (#185).

Fixture git repositories only: no cargo, no bend. Each case builds a base commit and a
head commit and checks the whole output tree, not a few files.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import judge_overlay as jo  # noqa: E402

LANES = '''owner = "@owner"
[lanes]
C = ["scripts/**", "ci/**", "tools/claims_check.py", "tools/policy_check.py", "Cargo.lock", "Cargo.toml",
     "crates/containment-host/**", ".cargo/**", "results/attack-suite*"]
B = ["crates/**", "formal/**", "claims.toml", "tools/test_*.py", "results/**"]
A = ["docs/**"]
'''
BASE_FILES = {
    "ci/lanes.toml": LANES,
    "ci/pins.env": "BEND_COMMIT=base\n",
    "scripts/check.sh": "#!/bin/sh\necho base check\n",
    "tools/claims_check.py": "print('base claims')\n",
    "tools/policy_check.py": "print('base policy')\n",
    "tools/test_x.py": "# base test\n",
    "crates/containment-kernel/src/lib.rs": "// base kernel\n",
    "crates/containment-host/src/main.rs": "// base host\n",
    "Cargo.lock": "# base lock\n",
    "formal/kernel.bend": "# base bend\n",
    "claims.toml": "# base claims\n",
    "docs/x.md": "base doc\n",
}


def git(repo, *args, data=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@localhost", "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@localhost", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
    return subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True, text=True,
                          env=env, check=True).stdout


class Fixture:
    def __init__(self, tmp):
        self.repo = Path(tmp) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        self.write(BASE_FILES)
        (self.repo / "scripts/check.sh").chmod(0o755)
        self.base = self.commit("base")

    def write(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def commit(self, message):
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.repo, "rev-parse", "HEAD").strip()

    def overlay(self, head, out):
        return jo.overlay(self.repo, self.base, head, out)


def files_of(out):
    return {p: (Path(out) / p).read_text(encoding="utf-8")
            for p in git(out, "ls-files", "-z").split("\0") if p}


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(self.tmp.name)
        self.out = Path(self.tmp.name) / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def test_hostile_head_gets_every_judge_from_base(self):
        self.fx.write({
            "scripts/check.sh": "#!/bin/sh\nexit 0\n",
            "tools/claims_check.py": "print('always pass')\n",
            "ci/pins.env": "BEND_COMMIT=evil\n",
            "ci/lanes.toml": LANES.replace('"scripts/**", ', ""),
            "tools/test_x.py": "# edited base test\n",
            # Head-only files no lane lists (lane C by default) or that sit at judge paths.
            "scripts/extra.sh": "echo extra\n",
            "tools/json.py": "raise SystemExit(0)\n",
            "unittest.py": "raise SystemExit(0)\n",
            "bunfig.toml": "preload = ['evil.ts']\n",
            "formal/bunfig.toml": "preload = ['evil.ts']\n",
            ".cargo/config.toml": "[build]\nrustflags = ['--cap-lints', 'allow']\n",
            "rust-toolchain": "nightly\n",
            "package.json": "{}\n",
            # Code under test: stays the head's.
            "crates/containment-kernel/src/lib.rs": "// head kernel\n",
            "crates/containment-host/src/main.rs": "// head host\n",
            "Cargo.lock": "# head lock\n",
            "formal/kernel.bend": "# head bend\n",
            "claims.toml": "# head claims\n",
            "docs/x.md": "head doc\n",
            "tools/test_new.py": "import os\nos._exit(0)\n",
        })
        head = self.fx.commit("hostile head")
        result = self.fx.overlay(head, self.out)
        got = files_of(self.out)
        expected = dict(BASE_FILES)
        expected.update({
            "crates/containment-kernel/src/lib.rs": "// head kernel\n",
            "crates/containment-host/src/main.rs": "// head host\n",
            "Cargo.lock": "# head lock\n",
            "formal/kernel.bend": "# head bend\n",
            "claims.toml": "# head claims\n",
            "docs/x.md": "head doc\n",
        })
        self.assertEqual(got, expected)
        for name in ("scripts/extra.sh", "tools/json.py", "unittest.py", "bunfig.toml", "formal/bunfig.toml",
                     ".cargo/config.toml", "rust-toolchain", "package.json", "tools/test_new.py"):
            self.assertIn(name, result["removed"], name)
        self.assertEqual(git(self.out, "status", "--porcelain"), "")
        self.assertEqual(git(self.out, "rev-parse", "HEAD^").strip(), head)
        self.assertEqual(result["head"], head)

    def test_modes_come_from_base(self):
        (self.fx.repo / "scripts/check.sh").chmod(0o644)
        head = self.fx.commit("mode change")
        self.fx.overlay(head, self.out)
        self.assertTrue(os.access(self.out / "scripts/check.sh", os.X_OK))
        self.assertIn("100755", git(self.out, "ls-files", "-s", "scripts/check.sh"))

    def test_a_link_at_a_judge_path_is_refused(self):
        (self.fx.repo / "tools/claims_check.py").unlink()
        os.symlink("../docs/x.md", self.fx.repo / "tools/claims_check.py")
        head = self.fx.commit("link")
        with self.assertRaises(jo.Refused):
            self.fx.overlay(head, self.out)

    def test_a_base_link_at_a_judge_path_is_refused(self):
        os.symlink("check.sh", self.fx.repo / "scripts/alias.sh")
        self.fx.base = self.fx.commit("base with a link")
        head = self.fx.commit("head")
        with self.assertRaises(jo.Refused):
            self.fx.overlay(head, self.out)

    def test_a_directory_swapped_for_a_file_takes_the_base_shape(self):
        (self.fx.repo / "tools/claims_check.py").unlink()
        self.fx.write({"tools/claims_check.py/inner.py": "print('x')\n"})
        head = self.fx.commit("swap")
        self.fx.overlay(head, self.out)
        self.assertEqual((self.out / "tools/claims_check.py").read_text(), "print('base claims')\n")
        self.assertFalse((self.out / "tools/claims_check.py/inner.py").exists())

    def test_blobs_are_read_raw(self):
        # A head .gitattributes asking for a filter or CRLF must not change what is written.
        self.fx.write({".gitattributes": "*.py filter=evil eol=crlf\n"})
        git(self.fx.repo, "config", "filter.evil.smudge", "touch /tmp/judge-overlay-smudge-ran; cat")
        head = self.fx.commit("attributes")
        self.fx.overlay(head, self.out)
        self.assertEqual((self.out / "tools/claims_check.py").read_bytes(), b"print('base claims')\n")
        self.assertNotIn(".gitattributes", files_of(self.out))

    def test_the_source_repository_config_is_not_used(self):
        with tempfile.TemporaryDirectory() as marks:
            marker = Path(marks) / "fsmonitor-ran"
            script = Path(marks) / "monitor.sh"
            script.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            script.chmod(0o755)
            head = self.fx.commit("head")
            # Set after the fixture's own commits, which would otherwise run it themselves.
            git(self.fx.repo, "config", "core.fsmonitor", str(script))
            self.fx.overlay(head, self.out)
            self.assertFalse(marker.exists())

    def test_the_head_lane_map_is_never_read(self):
        self.fx.write({"ci/lanes.toml": 'owner = "@owner"\n[lanes]\nA = ["scripts/**", "tools/**"]\n',
                       "scripts/check.sh": "exit 0\n"})
        head = self.fx.commit("reclassify")
        self.fx.overlay(head, self.out)
        self.assertEqual((self.out / "scripts/check.sh").read_text(), BASE_FILES["scripts/check.sh"])

    def test_a_non_empty_output_is_refused(self):
        self.out.mkdir()
        (self.out / "x").write_text("x")
        with self.assertRaises(jo.Refused):
            self.fx.overlay(self.fx.base, self.out)

    def test_cli_prints_json_and_refusals_exit_1(self):
        head = self.fx.commit("head")
        child = subprocess.run([sys.executable, str(TOOLS / "judge_overlay.py"), "--repo", str(self.fx.repo),
                                "--base", self.fx.base, "--head", head, "--out", str(self.out)],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)["head"], head)
        again = subprocess.run([sys.executable, str(TOOLS / "judge_overlay.py"), "--repo", str(self.fx.repo),
                                "--base", self.fx.base, "--head", head, "--out", str(self.out)],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(again.returncode, 1)
        self.assertIn("judge-overlay:", again.stderr)


class ConfigNameTests(unittest.TestCase):
    def test_config_names_anywhere_in_the_head_code_are_removed(self):
        _owner, lanes = jo.pc.load_lanes(LANES)
        head = {p: ("100644", "blob", "0" * 40) for p in (
            "formal/bunfig.toml", "formal/.env", "formal/.env.local", "crates/containment-kernel/.cargo/config.toml",
            "crates/containment-kernel/rust-toolchain", "crates/containment-kernel/rust-toolchain.toml",
            "formal/package.json", "formal/node_modules/x/index.js", "formal/sitecustomize.py",
            "crates/containment-kernel/src/evil.pth", "crates/x/.gitattributes", "formal/kernel.bend")}
        take, remove, keep = jo.plan({}, head, lanes)
        self.assertEqual(keep, ["formal/kernel.bend"])
        self.assertEqual(sorted(remove), sorted(p for p in head if p != "formal/kernel.bend"))

    def test_ordinary_names_are_not_config(self):
        for path in ("formal/kernel.bend", "crates/containment-kernel/src/lib.rs", "docs/environment.md",
                     "tools/envelope.py", "formal/LAWS.bend"):
            self.assertFalse(jo.is_config(path), path)


class PlanTests(unittest.TestCase):
    def test_keep_list_and_default_lane(self):
        _owner, lanes = jo.pc.load_lanes(LANES)
        self.assertFalse(jo.is_judge("crates/containment-host/src/main.rs", lanes))
        self.assertFalse(jo.is_judge("Cargo.lock", lanes))
        self.assertFalse(jo.is_judge("results/attack-suite.json", lanes))
        self.assertTrue(jo.is_judge("scripts/check.sh", lanes))
        self.assertTrue(jo.is_judge("anything/unlisted.py", lanes))
        self.assertTrue(jo.is_judge(".cargo/config.toml", lanes))
        self.assertFalse(jo.is_judge("formal/kernel.bend", lanes))


if __name__ == "__main__":
    unittest.main()

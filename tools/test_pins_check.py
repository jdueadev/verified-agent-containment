#!/usr/bin/env python3
"""Unit tests for tools/pins_check.py. Each rule has a case that makes it fire."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pins_check as pk

ROOT = Path(__file__).resolve().parent.parent
PINS = {"BUN_VERSION": "1.4.5", "NODE_VERSION": "22", "JAVA_VERSION": "21", "BEND_COMMIT": "0e2f38f759cc830849e4",
        "TLA_VERSION": "v1.7.4", "TLA_SHA256": "936a262061c914694dfd"}
GOOD = "steps:\n  - uses: oven-sh/setup-bun@abc\n    with:\n      bun-version: ${{ env.BUN_VERSION }}\n"


class DriftTests(unittest.TestCase):
    def errors(self, workflow=GOOD, pins=PINS, channel="1.100.0", rustc=None):
        return pk.drift_errors(pins, channel, {"check.yml": workflow}, rustc)

    def test_clean_configuration_passes(self):
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.errors(rustc="rustc 1.100.0 (abc 2026-01-01)\n"), [])

    def test_workflow_with_a_literal_version_fails(self):
        for bad in ("      bun-version: 1.4.5\n", "      node-version: 22\n", "      java-version: '21'\n",
                    "      bun-version: latest\n", "      node-version: lts/*\n", "      java-version: ${{ env.OTHER }}\n",
                    "      bun-version: ${{ env.OTHER_VERSION }}\n", "      node-version: ${{ env.BUN_VERSION }}\n",
                    "      java-version: '${{ env.JAVA_VERSION }}-ea'\n", "      bun-version: ${{ env.BUN_VERSION }}x\n",
                    "    with: {bun-version: latest}\n", "    with: { node-version: 22, cache: npm }\n",
                    "    with: {java-version: ${{ env.BUN_VERSION }}}\n", "      bun-version:\n        latest\n",
                    "env:\n  RUST_TOOLCHAIN: 1.100.0\n", "env:\n  BEND_COMMIT: 0e2f38f759cc830849e4\n",
                    "run: rustup toolchain install 1.100.0\n", "run: echo 936a262061c914694dfd\n"):
            self.assertTrue(self.errors(GOOD + bad), bad)

    def test_each_input_accepts_only_its_own_pin(self):
        for good in ("      node-version: ${{ env.NODE_VERSION }}\n", "      java-version: '${{ env.JAVA_VERSION }}'\n",
                     '      bun-version: "${{env.BUN_VERSION}}"  # from ci/pins.env\n',
                     "    - bun-version: ${{ env.BUN_VERSION }} # pinned\n",
                     "    with: {bun-version: '${{ env.BUN_VERSION }}', other: 1}\n",
                     "    with: { java-version: ${{ env.JAVA_VERSION }} }\n"):
            self.assertEqual(self.errors(GOOD + good), [], good)

    def test_missing_pin_or_loose_channel_fails(self):
        self.assertTrue(self.errors(pins={k: v for k, v in PINS.items() if k != "TLA_SHA256"}))
        self.assertTrue(self.errors(channel="stable"))
        self.assertTrue(self.errors(channel=None))

    def test_wrong_rustc_fails(self):
        self.assertTrue(self.errors(rustc="rustc 1.99.1 (abc 2026-01-01)\n"))

    def test_repository_configuration_passes(self):
        workflows = pk.load_workflows()
        self.assertIn("check.yml", workflows)
        pins = pk.parse_pins((ROOT / "ci/pins.env").read_text(encoding="utf-8"))
        channel = pk.toolchain_channel((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
        self.assertEqual(pk.drift_errors(pins, channel, workflows), [])


class DiscoveryTests(unittest.TestCase):
    def test_yaml_and_yml_workflows_are_both_read(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / ".github/workflows"
            folder.mkdir(parents=True)
            (folder / "a.yml").write_text("x", encoding="utf-8")
            (folder / "b.yaml").write_text("      bun-version: 1.4.5\n", encoding="utf-8")
            (folder / "notes.txt").write_text("ignored", encoding="utf-8")
            workflows = pk.load_workflows(Path(td))
            self.assertEqual(sorted(workflows), ["a.yml", "b.yaml"])
            self.assertTrue(pk.drift_errors(PINS, "1.100.0", workflows))


class RequireTests(unittest.TestCase):
    def run_require(self, ci, have=("cargo",), files=()):
        return pk.require(["cargo", "java"], ["/opt/tla/tla2tools.jar"], ci,
                          which=lambda t: t if t in have else None, exists=lambda f: f in files)

    def test_missing_tool_is_fatal_in_ci(self):
        code, message = self.run_require(ci=True)
        self.assertEqual(code, 1)
        self.assertIn("java", message)
        self.assertIn("tla2tools.jar", message)

    def test_missing_tool_is_reported_as_skipped_locally(self):
        code, message = self.run_require(ci=False)
        self.assertEqual(code, 0)
        self.assertTrue(message.startswith("SKIPPED"))

    def test_everything_present_is_silent(self):
        self.assertEqual(self.run_require(ci=True, have=("cargo", "java"), files=("/opt/tla/tla2tools.jar",)), (0, ""))


if __name__ == "__main__":
    unittest.main()

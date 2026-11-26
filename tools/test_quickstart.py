#!/usr/bin/env python3
"""Checks that docs/quickstart-local-model.md still works when followed literally.

A native Linux reader must not be told to skip the step that builds the binary,
and every `containment-lab` subcommand the guide runs must exist in main.rs.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUICKSTART = ROOT / "docs" / "quickstart-local-model.md"
MAIN_RS = ROOT / "crates" / "containment-host" / "src" / "main.rs"
BUILD = "cargo build --release -p containment-host"
WHOLE_STEP_SKIP = re.compile(r"\bskip\s+step\s+(\d+)\b", re.IGNORECASE)


def steps(text):
    """Map each numbered `## N.` step to its body."""
    out, current = {}, None
    for line in text.splitlines():
        heading = re.match(r"^## (\d+)\.", line)
        if heading:
            current = int(heading.group(1))
            out[current] = []
        elif line.startswith("## "):
            current = None
        elif current is not None:
            out[current].append(line)
    return {n: "\n".join(body) for n, body in out.items()}


def skipped_builds(text):
    """Steps the native-Linux note skips whole even though they build the binary."""
    body = steps(text)
    notes = [line for line in text.splitlines() if line.startswith(">") and "native linux" in line.lower()]
    skipped = {int(n) for note in notes for n in WHOLE_STEP_SKIP.findall(note)}
    return sorted(n for n in skipped if BUILD in body.get(n, ""))


def code_lines(text):
    fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
        elif fence:
            yield line


class QuickstartTests(unittest.TestCase):
    def setUp(self):
        self.text = QUICKSTART.read_text(encoding="utf-8")

    def test_native_linux_note_keeps_the_build(self):
        self.assertEqual(skipped_builds(self.text), [])

    def test_the_check_catches_a_note_that_skips_the_build(self):
        old = ("> **On native Linux?** Skip Step 1 and run the commands directly inside a VM.\n\n"
               f"## 1. Setup\n\n```bash\n{BUILD}\n```\n\n## 2. Run\n")
        self.assertEqual(skipped_builds(old), [1])

    def test_build_comes_before_the_binary_is_used(self):
        self.assertIn(BUILD, self.text)
        self.assertLess(self.text.index(BUILD), self.text.index("target/release/containment-lab"))

    def test_subcommands_exist(self):
        known = set(re.findall(r'Some\("([a-z-]+)"\)', MAIN_RS.read_text(encoding="utf-8")))
        used = {m for line in code_lines(self.text) for m in re.findall(r"containment-lab\s+([a-z][a-z-]*)", line)}
        self.assertTrue(used)
        self.assertEqual(used - known, set())


if __name__ == "__main__":
    sys.exit(unittest.main())

#!/usr/bin/env python3
"""Unit tests for tools/md_links.py: which links count, and how they resolve."""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import md_links  # noqa: E402


class BrokenLinkTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "here.md").write_text("x", encoding="utf-8")
        (self.root / "top.md").write_text("x", encoding="utf-8")

    def tearDown(self):
        self.dir.cleanup()

    def check(self, text):
        page = self.root / "docs" / "page.md"
        page.write_text(text, encoding="utf-8")
        return md_links.broken(page, self.root)

    def test_existing_relative_links_pass(self):
        self.assertEqual(self.check("[a](here.md) [b](../top.md) ![c](./here.md) [d](..)\n"), [])

    def test_missing_relative_link_is_reported_with_its_line(self):
        self.assertEqual(self.check("intro\n[a](gone.md)\n"), [(2, "gone.md")])

    def test_fragment_and_query_are_dropped(self):
        self.assertEqual(self.check("[a](here.md#part) [b](here.md?x=1) [c](gone.md#part)\n"),
                         [(1, "gone.md#part")])

    def test_root_relative_link_resolves_against_root(self):
        self.assertEqual(self.check("[a](/top.md) [b](/docs/gone.md)\n"), [(1, "/docs/gone.md")])

    def test_urls_and_anchors_are_skipped(self):
        self.assertEqual(self.check("[a](https://x.invalid/gone.md) [b](mailto:a@b.c) [c](#gone)\n"), [])

    def test_reference_definitions_are_checked(self):
        self.assertEqual(self.check("[a][r]\n\n[r]: gone.md\n[s]: <here.md>\n"), [(3, "gone.md")])

    def test_links_with_a_title_or_nested_brackets(self):
        self.assertEqual(self.check('[a](gone.md "title") [`x` [y]](here.md)\n'), [(1, "gone.md")])

    def test_code_is_skipped(self):
        text = "`[a](gone.md)`\n```\n[b](gone.md)\n```\n~~~~\n```\n[c](gone.md)\n~~~~\n[d](gone.md)\n"
        self.assertEqual(self.check(text), [(9, "gone.md")])

    def test_main_prints_each_broken_link_and_fails(self):
        page = self.root / "docs" / "page.md"
        page.write_text("[a](gone.md)\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = md_links.main(["--root", str(self.root), str(page)])
        self.assertEqual(status, 1)
        self.assertEqual(out.getvalue(), f"{page.as_posix()}:1: gone.md\n")

    def test_main_passes_when_nothing_is_broken(self):
        page = self.root / "docs" / "page.md"
        page.write_text("[a](here.md)\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(md_links.main(["--root", str(self.root), str(page)]), 0)


if __name__ == "__main__":
    unittest.main()

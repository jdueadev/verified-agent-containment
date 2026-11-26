#!/usr/bin/env python3
"""The simulator page must declare UTF-8 where a browser looks for it.

README tells people to open web/dist/agent-containment-simulator.html from disk.
A file:// page has no Content-Type header, so the browser decides the encoding
from a <meta charset> in the first 1024 bytes; without one Chromium falls back
to Windows-1252 and the decision trace shows "Â·" and "â†’" (issue #191).
"""
import re
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
PAGES = ["web/template.html", "web/dist/agent-containment-simulator.html"]
CHARSET = re.compile(rb"<meta\s+charset=[\"']?utf-8[\"']?\s*/?>", re.I)


class PageCharsetTests(unittest.TestCase):
    def test_pages_declare_utf8_in_first_1024_bytes(self):
        for name in PAGES:
            with self.subTest(page=name):
                self.assertRegex((root / name).read_bytes()[:1024], CHARSET)

    def test_pages_decode_as_utf8(self):
        for name in PAGES:
            with self.subTest(page=name):
                (root / name).read_bytes().decode("utf-8")


if __name__ == "__main__":
    unittest.main()

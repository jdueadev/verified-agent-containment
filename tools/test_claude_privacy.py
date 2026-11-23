#!/usr/bin/env python3
"""Nothing private in the shared .claude/ (#169). The repository is public and
handovers are written once, so a host path or a token that lands there stays in
history. This is a cheap fixed check, not a secrets scanner."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PATTERNS = {
    "a home directory": re.compile(r"/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+"),
    "a Windows user folder": re.compile(r"(?i)[A-Z]:\\Users\\"),
    "a Windows drive path": re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/](?![\\/])"),
    "a mounted Windows drive": re.compile(r"/mnt/[a-z]/"),
    "a GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "an email address": re.compile(r"[A-Za-z0-9._%+-]+@(?!localhost\b)(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
}


def findings(name, text):
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        for what, pattern in PATTERNS.items():
            if pattern.search(line):
                out.append(f"{name}:{number}: {what}")
    return out


class PatternTests(unittest.TestCase):
    def test_each_pattern_fires(self):
        for sample in ("/home/someone/x", "C:\\Users\\someone", "H:\\repo", "D:/repo", "/mnt/h/repo",
                       "ghp_" + "a" * 36, "github_pat_" + "a" * 30, "-----BEGIN OPENSSH PRIVATE KEY-----",
                       "someone@example.com"):
            self.assertTrue(findings("s", sample), sample)

    def test_ordinary_text_does_not(self):
        for sample in ("http://127.0.0.1:8080/", "file:///x", "ws:\\S+", "Lane A: free", "`~/src/repo`",
                       "noreply@localhost", "#169 and #44", "binaryen@123.0.0", "react@18.3.1"):
            self.assertEqual(findings("s", sample), [], sample)


class SharedClaudeTests(unittest.TestCase):
    def test_tracked_claude_files_are_clean(self):
        names = [n for n in subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", ".claude/"],
                                           capture_output=True, text=True, check=True).stdout.split("\0") if n]
        out = []
        for name in names:
            out += findings(name, (ROOT / name).read_text(encoding="utf-8", errors="replace"))
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()

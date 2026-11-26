#!/usr/bin/env python3
"""Report relative links in Markdown files that point at a file that does not exist.

Inline links `[text](target)`, images, and reference definitions `[id]: target`
are checked. URLs with a scheme, `#fragment`-only links and anything inside code
are skipped. A fragment or query is dropped before the path is resolved; a path
starting with `/` resolves against ROOT, any other against the file's folder.

Usage: md_links.py [--root ROOT] FILE...
Prints `FILE:LINE: TARGET` for each broken link and exits 1 if there is one.
"""
import argparse
import re
import sys
from pathlib import Path

INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*(<[^>]*>|[^)\s]+)")
REFERENCE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
CODE_SPAN = re.compile(r"(`+).*?\1")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def links(text):
    """Yield (line number, target) for every link outside code."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        opened = FENCE.match(line)
        if fence:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        line = CODE_SPAN.sub("", line)
        for match in [*INLINE.finditer(line), *REFERENCE.finditer(line)]:
            yield number, match.group(1).strip("<>")


def broken(path, root):
    """Return (line, target) for each relative link in `path` whose file is missing."""
    out = []
    for number, target in links(path.read_text(encoding="utf-8")):
        if SCHEME.match(target) or target.startswith("#"):
            continue
        file = re.split(r"[#?]", target, maxsplit=1)[0]
        resolved = root / file.lstrip("/") if file.startswith("/") else path.parent / file
        if not resolved.exists():
            out.append((number, target))
    return out


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    failed = False
    for path in args.files:
        for number, target in broken(path, args.root):
            print(f"{path.as_posix()}:{number}: {target}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

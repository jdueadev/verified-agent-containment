#!/usr/bin/env python3
"""Check that every root entry point refuses to start without the throwaway marker.

AGENTS.md: run the root lab only in a disposable Linux or WSL2 machine. No check can
tell whether a machine is disposable, so the rule is enforced by asking: every way in
refuses unless FACTORY_LAB_DISPOSABLE=1 confirms it, and says how to set it.

- The binary: every command in `main.rs` is in exactly one of ROOT_COMMANDS (refused
  without the marker) and NO_MARKER_COMMANDS, and `main` calls `disposable_refusal`
  before it dispatches. The refusal itself is unit-tested in `main.rs`.
- Shell scripts under scripts/: a script that does something as root (sudo, a
  privileged container, a mount, a cgroup write, apt-get, or a root command of the
  binary) must test the marker, exit non-zero and name `FACTORY_LAB_DISPOSABLE=1`
  before the first such line.

Usage: lab_throwaway_check.py [ROOT]
"""
import re
import sys
from pathlib import Path

MARKER = "FACTORY_LAB_DISPOSABLE"
MAIN_RS = "crates/containment-host/src/main.rs"
SCRIPTS = "scripts"

# A line that acts as root, or starts a root command of the binary.
ROOT_ACTION = re.compile(
    r"\bsudo\b|--privileged|\bmount\s+-t\b|>\s*/sys/fs/cgroup|\bapt-get\b"
    r"|\b(attack-suite|live-suite|redteam)\b"
    r"|(containment-lab\"?|\"\$\{?\w+\}?\")\s+live\b"
)
# `[ "${FACTORY_LAB_DISPOSABLE:-}" = 1 ] ||` or `if [ "${FACTORY_LAB_DISPOSABLE:-}" != "1" ]; then`
GUARD_TEST = re.compile(r'\[\s*"\$\{' + MARKER + r':-\}"\s*(=|!=)\s*"?1"?\s*\]')
GUARD_WINDOW = 4  # the test, its message and its exit sit within this many lines


def code(line):
    stripped = line.strip()
    return "" if stripped.startswith("#") else stripped


def is_shell(path):
    if path.suffix == ".sh":
        return True
    try:
        first = path.read_text(errors="replace").split("\n", 1)[0]
    except OSError:
        return False
    return first.startswith("#!") and re.search(r"\b(ba)?sh\b", first) is not None


def guard_at(lines, index):
    """True when lines[index] opens a marker test whose failure exits and names the fix."""
    match = GUARD_TEST.search(lines[index])
    if not match:
        return False
    if match.group(1) == "=" and "||" not in lines[index][match.end():]:
        return False
    if match.group(1) == "!=" and not re.match(r"\s*if\b", lines[index]):
        return False
    window = "\n".join(lines[index:index + GUARD_WINDOW])
    named = any("echo" in line and f"{MARKER}=1" in line for line in lines[index:index + GUARD_WINDOW])
    return named and re.search(r"\bexit\s+[1-9]", window) is not None


def script_errors(path, rel):
    lines = [code(line) for line in path.read_text(errors="replace").splitlines()]
    first_root = next((i for i, line in enumerate(lines) if ROOT_ACTION.search(line)), None)
    if first_root is None:
        return []
    if any(guard_at(lines, i) for i in range(first_root)):
        return []
    return [
        f"{rel}:{first_root + 1}: acts as root (`{lines[first_root][:60]}`) with no refusal before it; "
        f'add `[ "${{{MARKER}:-}}" = 1 ] || {{ echo "...set {MARKER}=1 to confirm" >&2; exit 1; }}` above it'
    ]


def string_list(text, name):
    match = re.search(r"const\s+" + name + r"\s*:\s*&\[&str\]\s*=\s*&\[(.*?)\];", text, re.S)
    return None if match is None else re.findall(r'"([^"]*)"', match.group(1))


def binary_errors(text):
    errors = []
    root, plain = string_list(text, "ROOT_COMMANDS"), string_list(text, "NO_MARKER_COMMANDS")
    if root is None or plain is None:
        return [f"{MAIN_RS}: ROOT_COMMANDS or NO_MARKER_COMMANDS is missing"]
    main = re.search(r"fn main\(\)[^{]*\{(.*)", text, re.S)
    body = main.group(1) if main else ""
    dispatch = body.find("match args.first()")
    refusal = body.find("disposable_refusal(")
    if dispatch < 0 or refusal < 0 or refusal > dispatch:
        errors.append(f"{MAIN_RS}: main does not call disposable_refusal before it dispatches a command")
    arms = re.findall(r'Some\("([^"|]+)"\)\s*=>', body)
    for command in arms:
        if command in root and command in plain:
            errors.append(f"{MAIN_RS}: `{command}` is in both ROOT_COMMANDS and NO_MARKER_COMMANDS")
        elif command not in root and command not in plain:
            errors.append(
                f"{MAIN_RS}: `{command}` is in neither ROOT_COMMANDS nor NO_MARKER_COMMANDS; "
                "add it to ROOT_COMMANDS if it runs attack code as root"
            )
    for command in sorted(set(root + plain) - set(arms)):
        errors.append(f"{MAIN_RS}: `{command}` is listed but main has no such command")
    return errors


def errors(root):
    root = Path(root)
    found = binary_errors((root / MAIN_RS).read_text())
    for path in sorted((root / SCRIPTS).rglob("*")):
        if path.is_file() and is_shell(path):
            found += script_errors(path, path.relative_to(root).as_posix())
    return found


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    found = errors(root)
    for line in found:
        print(f"lab-throwaway: {line}", file=sys.stderr)
    if found:
        return 1
    print("lab-throwaway: every root entry point refuses without FACTORY_LAB_DISPOSABLE=1")
    return 0


if __name__ == "__main__":
    sys.exit(main())

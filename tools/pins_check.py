#!/usr/bin/env python3
"""Keep tool versions in one place, and refuse to pass with a tool missing.

Usage:
  pins_check.py drift [--rustc]
  pins_check.py require TOOL... [--file PATH]...

drift    The Rust version lives only in rust-toolchain.toml and every other
         tool pin only in ci/pins.env. Fails if a workflow carries its own
         copy, if a pin is missing, or (--rustc) if the active rustc is not
         the pinned one.
require  Fails when CI=true and a tool or file is missing. Outside CI it lists
         what is missing as SKIPPED and succeeds, so a partial local run is
         visible but is never mistaken for the full gate.
"""
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = ("BUN_VERSION", "NODE_VERSION", "JAVA_VERSION", "BEND_COMMIT", "TLA_VERSION", "TLA_SHA256")
# A workflow may read a pin, never state one.
LITERALS = [
    (r"\b(bun|node|java)-version:\s*['\"]?[0-9v]", "a literal tool version"),
    (r"\bRUST_TOOLCHAIN\b", "its own Rust toolchain variable"),
    (r"\b(BEND_COMMIT|TLA_VERSION|TLA_SHA256|BUN_VERSION|NODE_VERSION|JAVA_VERSION):\s*\S", "its own copy of a pin"),
    (r"rustup\s+(toolchain\s+install|default)\s+[0-9]", "a literal Rust version"),
]


def parse_pins(text):
    pins = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(\S+)", line.strip())
        if match:
            pins[match.group(1)] = match.group(2)
    return pins


def toolchain_channel(text):
    return tomllib.loads(text).get("toolchain", {}).get("channel")


def drift_errors(pins, channel, workflows, rustc_version=None):
    errors = [f"ci/pins.env: {key} is missing" for key in PINS if not pins.get(key)]
    if not channel or not re.fullmatch(r"\d+\.\d+\.\d+", channel):
        errors.append("rust-toolchain.toml: channel must be an exact version")
    for name, text in sorted(workflows.items()):
        for pattern, what in LITERALS:
            if re.search(pattern, text):
                errors.append(f"{name}: carries {what}; read it from ci/pins.env or rust-toolchain.toml")
        for key, value in pins.items():
            if len(value) >= 8 and value in text:
                errors.append(f"{name}: repeats the value of {key}")
    if rustc_version is not None and channel and f"rustc {channel} " not in rustc_version + " ":
        errors.append(f"active rustc is `{rustc_version.strip()}`, not the pinned {channel}")
    return errors


def missing(tools, files, which=shutil.which, exists=os.path.exists):
    return [t for t in tools if not which(t)] + [f for f in files if not exists(f)]


def require(tools, files, ci, which=shutil.which, exists=os.path.exists):
    """Returns (exit code, message). A missing tool is fatal only in CI."""
    absent = missing(tools, files, which, exists)
    if not absent:
        return 0, ""
    if ci:
        return 1, "error: missing in CI, so the gate would pass without running: " + ", ".join(absent)
    return 0, "SKIPPED (not the full gate): missing " + ", ".join(absent)


def main(argv):
    if argv[:1] == ["drift"]:
        workflows = {str(p.relative_to(ROOT)).replace("\\", "/"): p.read_text(encoding="utf-8")
                     for p in sorted((ROOT / ".github/workflows").glob("*.yml"))}
        rustc = None
        if "--rustc" in argv:
            rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True, cwd=ROOT).stdout
        errors = drift_errors(parse_pins((ROOT / "ci/pins.env").read_text(encoding="utf-8")),
                              toolchain_channel((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")), workflows, rustc)
        for error in errors:
            print(error, file=sys.stderr)
        return 1 if errors else 0
    if argv[:1] == ["require"]:
        tools, files, rest = [], [], argv[1:]
        while rest:
            item = rest.pop(0)
            (files if item == "--file" else tools).append(rest.pop(0) if item == "--file" else item)
        code, message = require(tools, files, os.environ.get("CI") == "true")
        if message:
            print(message, file=sys.stderr)
        return code
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

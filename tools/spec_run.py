#!/usr/bin/env python3
"""Run the base branch's spec against a head checkout, so that a change is never judged
only by tests it could have edited (#125).

Usage:
  spec_run.py base --base-ref REF --head DIR [--rust] [--json FILE]
  spec_run.py new  --base-ref REF --head DIR [--rust] [--json FILE]

base  runs every spec test file the base commit has. Each Python test module runs in
      its own `python3 -I -B` process, with the head's tools/ on its path, after the
      head's __pycache__ is removed (a cached .pyc could run in place of the source).
      Head-only spec files are moved out of the checkout first, so that a new test
      cannot run beside the base spec, patch it, or rewrite what it builds. With
      --rust, each base file in crates/containment-kernel/tests/ runs as its own
      `cargo test --test NAME`.
new   runs only the head-only spec files, the same way. The workflow runs it in a
      separate job after `base`, so nothing it does can reach the base verdict.

The verdict is never an exit code. The ids every test file defines are read from the
source with ast (Python) or the lexer (Rust), and each one must be reported as passed.
A skip, an ignored test or a missing id is a failure. The result is printed as JSON;
the exit status is 1 when any expected test did not pass.

This file runs from the base branch (the workflow checks it out from base, as `policy`
does). It reads the base commit only through git and never imports head code into its
own process; the head's code runs only in the child processes it judges.
"""
import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def _one(tools_dir, module, out):
    """Child process: load one test module from the head's tools/ and record each
    test's outcome by id. It runs head code, so its only output is the result file."""
    # This process must import the head's modules, never the base copies next to this
    # file, so the base tools/ that `python3 script.py` put on the path is removed.
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != TOOLS]
    sys.path.insert(0, tools_dir)
    results = {}

    class Recorder(unittest.TestResult):
        def addSuccess(self, test):
            results[test.id()] = "ok"

        def addFailure(self, test, err):
            results[test.id()] = "FAILED"

        def addError(self, test, err):
            results[getattr(test, "id", lambda: str(test))()] = "ERROR"

        def addSkip(self, test, reason):
            results[test.id()] = "skipped"

        def addExpectedFailure(self, test, err):
            results[test.id()] = "expected failure"

        def addUnexpectedSuccess(self, test):
            results[test.id()] = "unexpected success"

        def addSubTest(self, test, subtest, err):
            if err is not None:
                results[test.id()] = "FAILED"

    suite = unittest.defaultTestLoader.loadTestsFromName(module)
    recorder = Recorder()
    suite.run(recorder)
    # A failed subtest marks the whole test failed, even if addSuccess came after it.
    for test, _ in recorder.failures + recorder.errors:
        results[getattr(test, "id", lambda: str(test))()] = "FAILED"
    Path(out).write_text(json.dumps(results), encoding="utf-8")


if __name__ == "__main__" and sys.argv[1:2] == ["_one"]:
    _one(*sys.argv[2:5])
    sys.exit(0)

sys.path.insert(0, str(TOOLS))
import policy_check  # noqa: E402  (the gate's spec patterns and git reader, from base)
import rust_tokens  # noqa: E402

PY_SPEC = "tools/test_*.py"
RS_SPEC = "crates/containment-kernel/tests/"
RESULT_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b", re.M)


# ---------- which tests the source defines ----------

def python_test_ids(module, text):
    """module.Class.method for every test method of every top-level class. Inherited
    methods are not counted here, so they can only add to what must pass."""
    ids = []
    for node in ast.parse(text).body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    ids.append(f"{module}.{node.name}.{item.name}")
    return ids


def rust_test_ids(text):
    """Names of the functions marked #[test], read by tokens: a #[test] in a comment or a
    string is not a test. Other attributes and `pub`/`async`/... may sit between."""
    toks = [t for _, t in rust_tokens.code_tokens(text)]
    modifiers = {"pub", "async", "const", "unsafe", "extern"}
    ids, i, pending = [], 0, False
    while i < len(toks):
        if toks[i] == "#" and toks[i + 1:i + 2] == ["["]:
            depth, j = 0, i + 1
            while j < len(toks):
                depth += toks[j] == "["
                depth -= toks[j] == "]"
                if depth == 0:
                    break
                j += 1
            pending = pending or toks[i + 1:j + 1] == ["[", "test", "]"]
            i = j + 1
            continue
        if pending and toks[i] == "fn" and i + 1 < len(toks):
            ids.append(toks[i + 1])
            pending = False
        elif toks[i] not in modifiers:
            pending = False
        i += 1
    return ids


def spec_files(get_names, include_rust):
    names = [n for n in get_names() if policy_check.lane_match(n, PY_SPEC)]
    if include_rust:
        names += [n for n in get_names() if n.startswith(RS_SPEC) and n.endswith(".rs") and "/" not in n[len(RS_SPEC):]]
    return sorted(names)


def base_names(ref):
    return policy_check.git("ls-tree", "-r", "--name-only", f"{ref}^{{commit}}").splitlines()


def head_names(head):
    out = subprocess.run(["git", "-C", str(head), "ls-files", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    return [n for n in out if (head / n).is_file()]


# ---------- running ----------

def run_python_module(head, path):
    """Run one test module in a fresh isolated interpreter and return {id: outcome}.
    The child loads the module from the head's tools/ and writes its results to a file
    this process names; nothing it prints is parsed."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "result.json"
        child = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_one",
                                str(head / "tools"), Path(path).stem, str(out)],
                               cwd=head, capture_output=True, text=True, timeout=1800)
        results = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        if not results:
            results = {"<module>": f"no results (exit {child.returncode}): {child.stderr.strip()[-400:]}"}
        return results


def run_rust_file(head, path, env=None):
    name = Path(path).stem
    child = subprocess.run(["cargo", "test", "--locked", "-p", "containment-kernel", "--test", name,
                            "--", "--test-threads=1"], cwd=head, capture_output=True, text=True,
                           env=env, timeout=3600)
    found = {m.group(1): m.group(2) for m in RESULT_LINE.finditer(child.stdout)}
    return {f"{name}::{k}": ("ok" if v == "ok" else v) for k, v in found.items()} or \
        {"<build>": f"no results (exit {child.returncode}): {child.stderr.strip()[-400:]}"}


def judge(expected, reported):
    """Every expected id must be reported as passed, and nothing reported may have
    failed: tests made at run time (in a loop, by a subclass) are not in the source
    count, but they still count against the verdict."""
    passed = sorted(i for i in expected if reported.get(i) == "ok")
    failed = {i: reported.get(i, "missing") for i in expected if reported.get(i) != "ok"}
    failed.update({i: outcome for i, outcome in reported.items() if outcome != "ok" and i not in failed})
    return passed, failed


def clear_pycache(head):
    for cache in (head / "tools").rglob("__pycache__"):
        shutil.rmtree(cache)


def run(mode, base_ref, head, rust):
    head = head.resolve()
    base_spec = spec_files(lambda: base_names(base_ref), rust)
    head_spec = spec_files(lambda: head_names(head), rust)
    head_only = sorted(set(head_spec) - set(base_spec))
    get = policy_check.reader(base_ref)
    report = {"mode": mode, "base": base_ref, "files": [], "failed": {}, "passed": 0}
    parked = Path(tempfile.mkdtemp(prefix="spec-parked-"))
    try:
        if mode == "base":
            # Park head-only spec outside the checkout for the whole run.
            for name in head_only:
                target = parked / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(head / name), str(target))
            todo = [(name, get(name)) for name in base_spec]
        else:
            todo = [(name, (head / name).read_text(encoding="utf-8")) for name in head_only]
        clear_pycache(head)
        for name, text in todo:
            if text is None:
                report["failed"][name] = "missing at base"
                continue
            if name.endswith(".py"):
                expected = python_test_ids(Path(name).stem, text)
                reported = run_python_module(head, name)
            else:
                stem = Path(name).stem
                expected = [f"{stem}::{t}" for t in rust_test_ids(text)]
                reported = run_rust_file(head, name)
            passed, failed = judge(expected, reported)
            if not expected:
                failed = {name: "defines no tests"}
            report["files"].append({"file": name, "expected": len(expected), "passed": len(passed)})
            report["passed"] += len(passed)
            report["failed"].update(failed)
    finally:
        for name in head_only:
            if (parked / name).exists():
                (head / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(parked / name), str(head / name))
        shutil.rmtree(parked, ignore_errors=True)
    if mode == "base" and not report["files"]:
        report["failed"]["<spec>"] = "the base commit has no spec files"
    return report


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("mode", choices=("base", "new"))
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--rust", action="store_true", help="also run crates/containment-kernel/tests")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    report = run(args.mode, args.base_ref, args.head, args.rust)
    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())

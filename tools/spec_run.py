#!/usr/bin/env python3
"""Run the base branch's spec against a head checkout, so that a change is never judged
only by tests it could have edited (#125).

Usage:
  spec_run.py base --base-ref REF --head DIR [--rust] [--json FILE]
  spec_run.py new  --base-ref REF --head DIR [--rust] [--json FILE]
  (either) [--reviews FILE --head-sha SHA]

base  runs every spec test file the base commit has. Head-only spec files are moved out
      of the checkout first, so a new test cannot run beside the base spec. With --rust,
      each base file in crates/containment-kernel/tests/ runs first, as its own `cargo
      test --test NAME`, before any Python child has run head code. Then each base
      Python test module runs in its own `python3 -I -B` process, in its own throwaway
      copy of the head checkout, so a test may write into the repository without
      reaching any other module. In that copy the module's file is rewritten from the
      base commit and __pycache__ is removed; the child loads it by path, so a package
      or extension of the same name cannot stand in for it, and any such file beside it
      fails the module.
new   runs only the head-only spec files, the same way. The workflow runs it in a
      separate job after `base`, so nothing it does can reach the base verdict.

--as-user USER runs every child that runs head code as that unprivileged user, through
`sudo -n -u USER env -i`, and kills everything the user left running after each child,
so a child cannot write a later child's results. The workflow uses it; a local run
without it judges only the author's own machine.

The verdict is never an exit code. The ids every test file defines are read from the
source with ast (Python) or the lexer (Rust), and each one must be reported as passed.
A skip, an ignored test or a missing id is a failure, and so is any failure reported
for a test the source does not list. Rust results are read only from the lines before
libtest's `failures:` section, where a panic message could imitate a result line, and a
non-zero cargo exit is a failure of its own. The result is printed as JSON; the exit
status is 1 when any expected test did not pass.

A red base spec is not a dead end. A legitimately stricter change can fail the base test
that encoded the old verdict, and the immutability ratchet stops the author from editing
that test. With --reviews and --head-sha (the pull request's reviews, as `policy` reads
them), a failing run exits 0 when the owner in the base lane map approved exactly this
head commit. The failures are still printed, and the report says it was approved.

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
    # Load the module from its file, never by name: a package tools/<module>/ or an
    # extension module of the same name would otherwise win the import.
    import importlib.util
    source = Path(tools_dir) / f"{module}.py"
    spec = importlib.util.spec_from_file_location(module, source)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[module] = loaded
    spec.loader.exec_module(loaded)
    if Path(loaded.__file__).resolve() != source.resolve():
        raise SystemExit(f"{module} was loaded from {loaded.__file__}, not {source}")

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

    # A failed subtest records FAILED, and unittest does not call addSuccess after it.
    unittest.defaultTestLoader.loadTestsFromModule(loaded).run(Recorder())
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
FAILURES_SECTION = re.compile(r"^failures:$", re.M)


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
    # -z: without it git quotes an unusual name, and a quoted name matches no pattern.
    return [n for n in policy_check.git("ls-tree", "-r", "-z", "--name-only", f"{ref}^{{commit}}").split("\0") if n]


def head_names(head):
    out = subprocess.run(["git", "-C", str(head), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, text=True, check=True).stdout.split("\0")
    return [n for n in out if n and (head / n).is_file()]


# ---------- running ----------

def child_command(argv, as_user, env):
    """The command for a child that runs head code. With as_user it runs as that
    unprivileged user with a clean environment (the workflow's isolation); without it,
    as this user (local runs, which judge only the author's own machine)."""
    if not as_user:
        return argv, {**os.environ, **env}
    keep = {k: os.environ[k] for k in ("PATH", "RUSTUP_HOME", "LANG") if k in os.environ}
    pairs = [f"{k}={v}" for k, v in {**keep, "HOME": f"/home/{as_user}", **env}.items()]
    return ["sudo", "-n", "-u", as_user, "env", "-i", *pairs, *argv], None


def end_children(as_user):
    """Kill anything a child left running, so it cannot write a later child's results."""
    if as_user:
        subprocess.run(["sudo", "-n", "pkill", "-KILL", "-u", as_user], capture_output=True)


def shadows(head, module):
    """Files that could load in place of tools/<module>.py, or be imported beside it."""
    return sorted(p.name for p in (head / "tools").glob(f"{module}*")
                  if p.name != f"{module}.py" and p.name.split(".")[0] == module)


def own_copy(head):
    """A throwaway copy of the head checkout (without target/) for one child, which may
    write to it freely: some tests write into the repository, and a copy per child keeps
    one child from changing what a later one runs or imports."""
    work = Path(tempfile.mkdtemp(prefix="spec-module-"))
    work.chmod(0o755)  # mkdtemp makes it 0700; the child's user must reach the copy inside
    copy = work / "repo"
    shutil.copytree(head, copy, symlinks=True, ignore=shutil.ignore_patterns("target"))
    # Head-only spec is parked during a base run, so it is missing from the copy. Drop
    # such files from the copy's index too, so the copy reads as a checkout without
    # them; a test that walks every tracked file would otherwise trip on a parked one.
    if (copy / ".git").exists():
        gone = subprocess.run(["git", "-C", str(copy), "ls-files", "-z", "--deleted"],
                              capture_output=True, text=True, check=True).stdout.split("\0")
        gone = [name for name in gone if name]
        if gone:
            subprocess.run(["git", "-C", str(copy), "rm", "-q", "--cached", "--", *gone],
                           capture_output=True, check=True)
    return work, copy


def remove_copy(work, as_user):
    # Files the child made belong to the child's user, so with as_user they are removed as root.
    if as_user:
        subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(work)], capture_output=True)
    shutil.rmtree(work, ignore_errors=True)


def hand_over(copy, as_user):
    """Give the copy to the child's user, so the child may write to it."""
    if as_user:
        subprocess.run(["sudo", "-n", "chown", "-R", as_user, str(copy)], check=True, capture_output=True)


def run_python_module(head, path, base_text=None, as_user=None, isolate=False, prepared=False):
    """Run one test module in a fresh isolated interpreter and return {id: outcome}.

    With base_text, the module file is first rewritten from the base commit, so an
    earlier child cannot have changed it on disk. With isolate, the child runs in its
    own copy of the checkout (own_copy), which `run` always asks for. The child loads
    the module by path from tools/ and writes its results into a directory made for it
    alone; nothing it prints is parsed. Afterwards anything it left running is killed."""
    if isolate:
        work, copy = own_copy(head)
        try:
            # Every write this process makes to the copy happens before it is handed to the
            # child's user: after hand_over, this process may no longer write there.
            if base_text is not None:
                (copy / "tools" / f"{Path(path).stem}.py").write_text(base_text, encoding="utf-8")
            clear_pycache(copy)
            hand_over(copy, as_user)
            return run_python_module(copy, path, None, as_user, isolate=False, prepared=True)
        finally:
            remove_copy(work, as_user)
    module = Path(path).stem
    source = head / "tools" / f"{module}.py"
    if base_text is not None:
        source.write_text(base_text, encoding="utf-8")
    found = shadows(head, module)
    if found:
        return {"<module>": f"files that could shadow {module}.py: {found}"}
    if not prepared:
        clear_pycache(head)
    results_dir = Path(tempfile.mkdtemp(prefix="spec-result-"))
    try:
        results_dir.chmod(0o777)
        out = results_dir / "result.json"
        argv, env = child_command([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_one",
                                   str(head / "tools"), module, str(out)], as_user, {})
        child = subprocess.run(argv, cwd=head, env=env, capture_output=True, text=True, timeout=1800)
        end_children(as_user)
        results = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    finally:
        shutil.rmtree(results_dir, ignore_errors=True)
    if not results:
        results = {"<module>": f"no results (exit {child.returncode}): {child.stderr.strip()[-400:]}"}
    return results


def parse_rust_output(name, stdout, returncode):
    """{name::test: outcome} from libtest's output. Only the lines before the `failures:`
    section count, because a failing test's panic message is printed there and can hold
    text that looks like a result line. A failure or an ignored test is never overridden
    by a later `ok`, and a non-zero exit is a failure of its own."""
    match = FAILURES_SECTION.search(stdout)
    head = stdout[:match.start()] if match else stdout
    found = {}
    for m in RESULT_LINE.finditer(head):
        key = f"{name}::{m.group(1)}"
        if found.get(key, "ok") == "ok":
            found[key] = m.group(2)
    if returncode != 0:
        found[f"{name}::<cargo>"] = f"exit {returncode}"
    return found


def run_rust_file(head, path, target_dir, as_user=None):
    name = Path(path).stem
    argv, env = child_command(["cargo", "test", "--locked", "-p", "containment-kernel", "--test", name,
                               "--", "--test-threads=1"], as_user,
                              {"CARGO_TARGET_DIR": str(target_dir), "CARGO_TERM_COLOR": "never"})
    child = subprocess.run(argv, cwd=head, env=env, capture_output=True, text=True, timeout=3600)
    end_children(as_user)
    found = parse_rust_output(name, child.stdout, child.returncode)
    if not any(not k.endswith("::<cargo>") for k in found):
        found[f"{name}::<build>"] = f"no results (exit {child.returncode}): {child.stderr.strip()[-400:]}"
    return found


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


def run(mode, base_ref, head, rust, as_user=None):
    head = head.resolve()
    base_spec = spec_files(lambda: base_names(base_ref), rust)
    head_spec = spec_files(lambda: head_names(head), rust)
    head_only = sorted(set(head_spec) - set(base_spec))
    get = policy_check.reader(base_ref)
    report = {"mode": mode, "base": base_ref, "files": [], "failed": {}, "passed": 0}
    parked = Path(tempfile.mkdtemp(prefix="spec-parked-"))
    target_dir = Path(tempfile.mkdtemp(prefix="spec-target-"))
    target_dir.chmod(0o777)
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
        # Rust first: it builds and runs before any Python child has run head code.
        todo.sort(key=lambda item: not item[0].endswith(".rs"))
        for name, text in todo:
            if text is None:
                report["failed"][name] = "missing at base"
                continue
            if name.endswith(".py"):
                expected = python_test_ids(Path(name).stem, text)
                reported = run_python_module(head, name, text if mode == "base" else None, as_user, isolate=True)
            else:
                stem = Path(name).stem
                expected = [f"{stem}::{t}" for t in rust_test_ids(text)]
                reported = run_rust_file(head, name, target_dir, as_user)
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
        shutil.rmtree(target_dir, ignore_errors=True)
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
    parser.add_argument("--reviews", type=Path, help="the pull request's reviews, as JSON")
    parser.add_argument("--head-sha", help="the head commit the reviews must approve")
    parser.add_argument("--as-user", help="run every child that runs head code as this user, through sudo")
    args = parser.parse_args(argv)
    if args.reviews and not args.head_sha:
        parser.error("--reviews needs --head-sha: approval is only ever of one commit")
    report = run(args.mode, args.base_ref, args.head, args.rust, args.as_user)
    report["approved"] = None
    if report["failed"] and args.reviews:
        lanes_text = policy_check.reader(args.base_ref)(policy_check.LANES_FILE)
        owner, _ = policy_check.load_lanes(lanes_text)
        reviews = json.loads(args.reviews.read_text(encoding="utf-8"))
        report["approved"] = policy_check.approved(reviews, owner, args.head_sha)
    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    return 1 if report["failed"] and not report["approved"] else 0


if __name__ == "__main__":
    sys.exit(main())

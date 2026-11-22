#!/usr/bin/env python3
"""Run the known-bad corpus in ci/corpus/ against a head checkout's checkers (#125).

Usage:
  corpus_run.py --head DIR [--corpus DIR] [--json FILE]

Each entry is a directory ci/corpus/<checker>/<id>/ with a case.toml:

  checker = "classify" | "invariants"
  origin  = "#86"                      # where the case came from
  twin    = "<id>"                     # reject cases only: the accept case beside it
  # classify: the lane policy_check must give, and what its escalations must say
  expect_lane = "C"
  expect_escalation = "law b was removed"   # or: expect_no_escalation = true
  # invariants: whether the commit must pass
  expect = "reject" | "accept"
  expect_error = "uses `include`"           # reject only
  delete = ["path", ...]                    # classify: paths the head removes

and its inputs: for classify, base/ and head/ trees (the head is the base with head/
laid over it, minus `delete`); for invariants, tree/, the kernel's whole src/ directory.

The checker runs as a black box: the head's policy_check.py and rust_tokens.py are
copied into a new git repository built from the case, and run there with `python3 -I
-B` as a child process. The lane map, CODEOWNERS and host manifest come from the head
checkout. Nothing is imported into this process.

The run fails when any case does not come out as expected, when a case names an
unknown checker, when a reject case has no accept twin, or when no case ran at all.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

CHECKERS = ("classify", "invariants")
GATE_FILES = ("tools/policy_check.py", "tools/rust_tokens.py")
REPO_FILES = ("ci/lanes.toml", ".github/CODEOWNERS", "crates/containment-host/Cargo.toml")
KERNEL_SRC = "crates/containment-kernel/src"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def new_repo(path):
    git(path, "init", "-q")
    git(path, "config", "user.email", "corpus@localhost")
    git(path, "config", "user.name", "corpus")
    git(path, "config", "commit.gpgsign", "false")


def commit_all(repo, message):
    # Re-add every file from scratch: a file laid over another with the same size and
    # copied timestamps can look unchanged to git's stat cache.
    git(repo, "rm", "-r", "-q", "--cached", "--ignore-unmatch", ".")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


def lay(src, dst):
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True, copy_function=shutil.copy)


def checker_output(repo, *argv):
    child = subprocess.run([sys.executable, "-I", "-B", str(repo / "tools/policy_check.py"), *argv],
                           cwd=repo, capture_output=True, text=True, timeout=300)
    text = child.stdout
    try:
        return child.returncode, json.loads(text[text.index("{"):])
    except ValueError:
        return child.returncode, {"unreadable": (text + child.stderr)[-400:]}


def run_case(case_dir, case, head):
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        new_repo(repo)
        for name in REPO_FILES:
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(head / name, repo / name)
        if case["checker"] == "classify":
            lay(case_dir / "base", repo)
            base = commit_all(repo, "base")
            lay(case_dir / "head", repo)
            for name in case.get("delete", []):
                (repo / name).unlink()
            head_sha = commit_all(repo, "head")
        else:
            lay(case_dir / "tree", repo)
            head_sha = commit_all(repo, "tree")
        (repo / "tools").mkdir(exist_ok=True)
        for name in GATE_FILES:
            shutil.copy2(head / name, repo / name)
        if case["checker"] == "classify":
            _, result = checker_output(repo, "classify", "--base", base, "--head", head_sha)
            return verdict_classify(case, result)
        code, result = checker_output(repo, "invariants", "--ref", head_sha)
        return verdict_invariants(case, code, result)


def verdict_classify(case, result):
    if "lane" not in result:
        return f"no verdict: {result}"
    escalations = result.get("escalations", [])
    if result["lane"] != case["expect_lane"]:
        return f"lane {result['lane']}, expected {case['expect_lane']} (escalations: {escalations})"
    if case.get("expect_no_escalation") and escalations:
        return f"expected no escalation, got {escalations}"
    wanted = case.get("expect_escalation")
    if wanted and not any(wanted in e for e in escalations):
        return f"no escalation mentions {wanted!r}: {escalations}"
    return None


def verdict_invariants(case, code, result):
    if "errors" not in result:
        return f"no verdict: {result}"
    errors = result["errors"]
    if case["expect"] == "accept":
        return None if code == 0 and not errors else f"expected to pass, got {errors}"
    if code == 0 or not errors:
        return "expected to be rejected, but it passed"
    wanted = case.get("expect_error")
    if wanted and not any(wanted in e for e in errors):
        return f"no error mentions {wanted!r}: {errors}"
    return None


def is_reject(case):
    if case["checker"] == "classify":
        return bool(case.get("expect_escalation"))
    return case.get("expect") == "reject"


def run(head, corpus):
    head = head.resolve()
    entries = sorted(p.parent for p in corpus.glob("*/*/case.toml"))
    dirs = sorted(p for p in corpus.glob("*/*") if p.is_dir())
    report = {"ran": [], "failed": {}}
    for stray in sorted(set(dirs) - set(entries)):
        report["failed"][stray.relative_to(corpus).as_posix()] = "directory has no case.toml"
    cases = {}
    for entry in entries:
        name = entry.relative_to(corpus).as_posix()
        try:
            case = tomllib.loads((entry / "case.toml").read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as error:
            report["failed"][name] = f"case.toml does not parse: {error}"
            continue
        if case.get("checker") != entry.parent.name or case.get("checker") not in CHECKERS:
            report["failed"][name] = f"unknown checker {case.get('checker')!r} (must be its directory, one of {CHECKERS})"
            continue
        cases[name] = case
    for name, case in cases.items():
        if is_reject(case):
            twin = f"{case['checker']}/{case.get('twin', '')}"
            if twin not in cases or is_reject(cases[twin]):
                report["failed"][name] = f"a reject case needs an accept twin; {twin!r} is not one"
                continue
        problem = run_case(corpus / name, case, head)
        report["ran"].append(name)
        if problem:
            report["failed"][name] = problem
    if not report["ran"]:
        report["failed"]["<corpus>"] = "no case ran"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--corpus", type=Path, help="default: HEAD/ci/corpus")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    report = run(args.head, args.corpus or args.head / "ci/corpus")
    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())

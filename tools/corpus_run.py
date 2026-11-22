#!/usr/bin/env python3
"""Run the known-bad corpus in ci/corpus/ against a head checkout's checkers (#125).

Usage:
  corpus_run.py --head DIR [--corpus DIR] [--json FILE]

Each entry is a directory ci/corpus/<checker>/<id>/ with a case.toml:

  checker = "classify" | "invariants" | "approval"
  origin  = "#86"                      # where the case came from
  twin    = "<id>"                     # reject cases only: the accept case beside it
  # classify: the lane policy_check must give, and what its escalations must say
  expect_lane = "C"
  expect_escalation = "law b was removed"   # or: expect_no_escalation = true
  # invariants: whether the commit must pass
  expect = "reject" | "accept"
  expect_error = "uses `include`"           # reject only
  # approval: also "refuse", which needs expect_error
  delete = ["path", ...]                    # classify and approval: paths the head removes

and its inputs: for classify, base/ and head/ trees (the head is the base with head/
laid over it, minus `delete`); for invariants, tree/, the kernel's whole src/ directory;
for approval, base/ and head/ trees for a lane C change, and inputs/<name>.json files.

An approval case runs the two commands the workflows run (#149): the head's

  policy_check.py fresh-reviews --head-sha SHA --<name> inputs/<name>.json ...

which gets every input (reviews.json is required) and prints the reviews that still
count as a JSON list, then the head's `classify --reviews <that list> --head-sha SHA`.
inputs/ may hold only regular files named <name>.json, <name> being lower-case letters,
digits and dashes and not head-sha. In the inputs, @HEAD@ and @BASE@ stand for the
commits the case builds. The change must be lane C. "accept" needs `"approved": true`;
"reject" needs `"approved": false`; "refuse" needs fresh-reviews to exit 1 with no
traceback and a last stderr line that starts with "fresh-reviews: " and contains
expect_error, which is how a workflow step stops. Anything else, such as unreadable
output, a null verdict, another lane, an argparse error or a crash, fails the case.

`approval` is in STAGED, not CHECKERS: the runner knows it, but the corpus has no
approval cases until the checker has fresh-reviews (#149, PR 2). That change moves it
into CHECKERS, which requires every checker to have cases.

The checker runs as a black box: the head's policy_check.py and rust_tokens.py are
copied into a new git repository built from the case, and run there with `python3 -I
-B` as a child process. The lane map, CODEOWNERS and host manifest come from the head
checkout. Nothing is imported into this process.

The run fails when any case does not come out as expected, when a case names an
unknown checker, when a reject case has no accept twin, or when no case ran at all.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

CHECKERS = ("classify", "invariants")
# Known to the runner, but not yet required to have cases. Each moves into CHECKERS
# in the change that adds its first cases.
STAGED = ("approval",)
KINDS = CHECKERS + STAGED
INPUT_NAME = re.compile(r"[a-z][a-z0-9-]*\.json")
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
        if case["checker"] in ("classify", "approval"):
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
        if case["checker"] == "approval":
            return run_approval(case_dir, case, repo, base, head_sha)
        code, result = checker_output(repo, "invariants", "--ref", head_sha)
        return verdict_invariants(case, code, result)


def run_approval(case_dir, case, repo, base, head_sha):
    """The head's fresh-reviews, then its classify on what fresh-reviews kept. The
    inputs live outside the case's repository, so they are not part of its diff."""
    folder = case_dir / "inputs"
    sources = sorted(folder.iterdir()) if folder.is_dir() and not folder.is_symlink() else []
    for source in sources:
        if source.is_symlink() or not source.is_file() or not INPUT_NAME.fullmatch(source.name) \
                or source.stem == "head-sha":
            return f"inputs/{source.name} is not an input: inputs/ holds only regular files named <name>.json"
    if "reviews" not in {p.stem for p in sources}:
        return "an approval case needs inputs/reviews.json"
    # A refusal stops the workflow before classify runs, so check the lane on its own.
    _, plain = checker_output(repo, "classify", "--base", base, "--head", head_sha)
    if plain.get("lane") != "C":
        return f"an approval case must be lane C, got {plain}"
    with tempfile.TemporaryDirectory() as box:
        inputs = Path(box)
        argv = ["fresh-reviews", "--head-sha", head_sha]
        for source in sources:
            text = source.read_text(encoding="utf-8").replace("@HEAD@", head_sha).replace("@BASE@", base)
            (inputs / source.name).write_text(text, encoding="utf-8")
            argv += [f"--{source.stem}", str(inputs / source.name)]
        try:
            child = subprocess.run([sys.executable, "-I", "-B", str(repo / "tools/policy_check.py"), *argv],
                                   cwd=repo, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return "fresh-reviews did not finish in 300 s"
        if case["expect"] == "refuse":
            lines = child.stderr.strip().splitlines()
            last = lines[-1] if lines else ""
            if child.returncode == 0:
                return f"expected fresh-reviews to refuse, but it kept {child.stdout.strip()[:200]}"
            if child.returncode != 1 or "Traceback (most recent call last)" in child.stderr \
                    or not last.startswith("fresh-reviews: ") or case["expect_error"] not in last:
                return (f"fresh-reviews did not refuse with 'fresh-reviews: ...{case['expect_error']}...': "
                        f"exit {child.returncode}, {child.stderr.strip()[-400:]}")
            return None
        if child.returncode != 0:
            return f"fresh-reviews failed: {(child.stdout + child.stderr).strip()[-400:]}"
        try:
            kept = json.loads(child.stdout)
        except ValueError:
            kept = None
        if not isinstance(kept, list):
            return f"fresh-reviews printed no JSON list: {child.stdout.strip()[-400:]}"
        (inputs / "kept.json").write_text(child.stdout, encoding="utf-8")
        _, result = checker_output(repo, "classify", "--base", base, "--head", head_sha,
                                   "--reviews", str(inputs / "kept.json"), "--head-sha", head_sha)
    return verdict_approval(case, result)


def verdict_approval(case, result):
    if result.get("lane") != "C":
        return f"an approval case must be lane C, got {result}"
    wanted = case["expect"] == "accept"
    if result.get("approved") is not wanted:
        return f"approved is {result.get('approved')!r}, expected {wanted}"
    return None


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
    return case.get("expect") in ("reject", "refuse")


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
        if case.get("checker") != entry.parent.name or case.get("checker") not in KINDS:
            report["failed"][name] = f"unknown checker {case.get('checker')!r} (must be its directory, one of {KINDS})"
            continue
        if case["checker"] == "approval" and (case.get("expect") not in ("accept", "reject", "refuse")
                                              or (case["expect"] == "refuse" and not case.get("expect_error"))):
            report["failed"][name] = "an approval case needs expect = accept, reject or refuse (refuse with expect_error)"
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

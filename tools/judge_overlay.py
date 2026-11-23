#!/usr/bin/env python3
"""Lay the base branch's judges over a pull request's code, deny by default (#185).

Usage:
  judge_overlay.py --repo DIR --base SHA --head SHA --out DIR [--json FILE]

The result is a fresh repository at --out whose HEAD is one synthetic commit, the
head's tree with every judge path taken from --base:

- A path is a judge path when the base's ci/lanes.toml puts it in lane C, and that
  includes every path the lane map does not list (lane C by default). Each judge path
  gets the base's blob and mode, read raw with `git cat-file` (no filters, no
  textconv). A judge path the base does not have is removed, so a head-only
  `tools/json.py`, `bunfig.toml`, `.cargo/config.toml` or root `rust-toolchain` cannot
  run inside a judge.
- KEEP, held here and so on the base, lists the lane C paths that are code under test
  and stay the head's: the host crate, the Cargo manifests and lock, the crates' build
  scripts, lab results, workflows, agent configuration and decision records.
- Spec files are the base's set: a head-only test file is removed (`spec new` judges it
  on its own), and a test file the base has is the base's copy.
- Configuration a judge's tools read by name wherever they run (bunfig.toml, .env*,
  package.json, node_modules, .cargo/, rust-toolchain, sitecustomize, usercustomize,
  .pth, .gitattributes and the like) is removed from the head's code; the root copies
  are judge paths.
- A symbolic link or submodule at a judge path, in the base or the head, is refused.

The head's lane map is never read. Nothing from --repo's config or work tree is used:
the output is a new repository that fetches the two commits, with git's own config
neutralised. The result is printed as JSON: the head and base commits, the synthetic
commit, and the paths taken from base, removed, and kept. Exit 1 on a refusal.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc  # noqa: E402  (the base's copy: this tool runs from the base checkout)

LANES_FILE = "ci/lanes.toml"
# Lane C paths that are the code under test, not judges. Everything else in lane C,
# and every unlisted path, is a judge path and comes from the base.
KEEP = (
    "crates/containment-host/**",
    "Cargo.toml",
    "Cargo.lock",
    "crates/containment-kernel/Cargo.toml",
    "crates/containment-kernel/build.rs",
    "crates/containment-wasm/Cargo.toml",
    "crates/containment-wasm/build.rs",
    "results/**",
    ".github/**",
    ".claude/**",
    "docs/decisions/**",
)
SPEC_DIRS = ("tools/test_*.py", "crates/containment-kernel/tests/**")
# Names that a judge's tools read as configuration from wherever they run, whatever
# lane the directory is in: bun reads bunfig.toml and .env from its working directory
# (formal/ for bend), cargo reads .cargo/ and rust-toolchain from the directory it runs
# in and its parents, Python runs sitecustomize, usercustomize and .pth files, node
# reads package.json, and git applies .gitattributes. In the head's code they are
# removed; the root copies are judge paths and come from base.
CONFIG_NAME = re.compile(r"(?i)^(bunfig\.toml|\.env.*|package(-lock)?\.json|bun\.lockb?|node_modules|\.npmrc"
                         r"|rust-toolchain(\.toml)?|\.cargo|(site|user)customize\.py|.*\.pth|pyvenv\.cfg"
                         r"|\.python-version|\.gitattributes|\.gitmodules)$")
REGULAR = ("100644", "100755")
SAFE_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "file",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_AUTHOR_NAME": "judge-overlay", "GIT_AUTHOR_EMAIL": "judge-overlay@localhost",
    "GIT_COMMITTER_NAME": "judge-overlay", "GIT_COMMITTER_EMAIL": "judge-overlay@localhost",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
}
SAFE_CONFIG = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
               "-c", "core.symlinks=true", "-c", "protocol.allow=never", "-c", "protocol.file.allow=always")


class Refused(Exception):
    pass


def git(repo, *args, data=None, binary=False, extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(SAFE_ENV)
    env.update(extra or {})
    proc = subprocess.run(["git", *SAFE_CONFIG, "-C", str(repo), *args], input=data, capture_output=True,
                          env=env, check=False)
    if proc.returncode != 0:
        raise Refused(f"git {' '.join(args[:3])} failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout if binary else proc.stdout.decode("utf-8")


def tree(repo, commit):
    """{path: (mode, kind, oid)} for every entry of a commit, read with -z."""
    out = {}
    for item in git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split("\0"):
        if "\t" in item:
            meta, path = item.split("\t", 1)
            mode, kind, oid = meta.split(" ")
            out[path] = (mode, kind, oid)
    return out


def matches(path, patterns):
    return any(pc.lane_match(path, pattern) for pattern in patterns)


def is_config(path):
    return any(CONFIG_NAME.match(part) for part in path.split("/"))


def is_judge(path, lanes):
    if matches(path, KEEP):
        return False
    return pc.lane_of(path, lanes)[0] == "C"


def plan(base_tree, head_tree, lanes):
    """(take, remove, keep): the paths the overlay takes from base, removes, and leaves as
    the head's. Pure, so the rules can be tested without git."""
    take, remove, keep = [], [], []
    for path in sorted(set(base_tree) | set(head_tree)):
        spec = matches(path, SPEC_DIRS)
        if is_judge(path, lanes) or spec:
            if path in base_tree:
                mode = base_tree[path][0]
                if mode not in REGULAR:
                    raise Refused(f"{path}: the base has it as mode {mode}; a judge path must be a regular file")
                if path in head_tree and head_tree[path][0] not in REGULAR:
                    raise Refused(f"{path}: the head has it as mode {head_tree[path][0]} at a judge path")
                take.append(path)
            else:
                remove.append(path)
        elif path in head_tree:
            (remove if is_config(path) else keep).append(path)
    return take, remove, keep


def overlay(repo, base, head, out):
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise Refused(f"{out} must be empty")
    out.mkdir(parents=True, exist_ok=True)
    # Resolve names to commit ids in --repo, then fetch exactly those ids.
    base = git(repo, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
    head = git(repo, "rev-parse", "--verify", f"{head}^{{commit}}").strip()
    git(out, "init", "-q")
    for commit in (base, head):
        git(out, "fetch", "-q", "--no-tags", str(Path(repo).resolve()), commit)
    lanes_text = git(out, "cat-file", "blob", f"{base}:{LANES_FILE}")
    _owner, lanes = pc.load_lanes(lanes_text)
    base_tree, head_tree = tree(out, base), tree(out, head)
    take, remove, keep = plan(base_tree, head_tree, lanes)
    # Build the synthetic tree in a private index: the head's entries, judge paths from base.
    index = out / ".git" / "overlay-index"
    env_index = {"GIT_INDEX_FILE": str(index)}
    entries = []
    for path in keep:
        mode, _kind, oid = head_tree[path]
        entries.append(f"{mode} {oid}\t{path}")
    for path in take:
        mode, _kind, oid = base_tree[path]
        entries.append(f"{mode} {oid}\t{path}")
    git(out, "read-tree", "--empty", extra=env_index)
    git(out, "update-index", "-z", "--index-info", data=("\0".join(entries) + "\0").encode("utf-8"), extra=env_index)
    synthetic_tree = git(out, "write-tree", extra=env_index).strip()
    commit = git(out, "commit-tree", synthetic_tree, "-p", head, "-m",
                 f"judge overlay: head {head} with the judges of base {base}").strip()
    git(out, "update-ref", "refs/heads/overlay", commit)
    git(out, "symbolic-ref", "HEAD", "refs/heads/overlay")
    git(out, "reset", "-q", "--hard", commit)
    index.unlink(missing_ok=True)
    return {"base": base, "head": head, "commit": commit, "from_base": take, "removed": remove,
            "kept": len(keep)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        result = overlay(args.repo, args.base, args.head, args.out)
    except (Refused, ValueError) as error:
        print(f"judge-overlay: {error}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

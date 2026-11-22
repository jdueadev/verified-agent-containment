#!/usr/bin/env python3
"""Keep secrets out of reach of every ref but main, and event text out of scripts.

Usage:
  workflow_lint.py [--ref REF]

Checks every `.github/workflows/*.yml` and `*.yaml` file (#137, stage 1):

- A `secrets` expression may appear only in a job whose `environment:` is
  named in ci/workflow_lint.toml. Each environment listed there is limited to
  the `main` branch, so a workflow pushed to any other ref cannot read the
  secret. This includes `secrets.X`, `secrets[...]` and `toJSON(secrets)`. Not
  allowed at all: secrets at workflow level, `secrets:` passed to a reusable
  workflow (including `secrets: inherit`), and an `environment:` given by an
  expression.
- A job that holds a secret or an environment must not run code that a pull
  request controls. Each checkout `ref:` must be `${{ github.sha }}`, and the
  `repository`, `run-id` and `github-token` inputs are refused. `workflow_run`
  and `pull_request_target` jobs run as main and pass the environment's branch
  rule, so this rule is what keeps PR code away from their keys.
- No `run:` script may expand `github.event`, `github.head_ref` or the whole
  `github` context. Values that come from the event reach scripts only through
  `env:`, so a branch name or title cannot become shell code.

The YAML is read as text with the standard library, because the repository
has no YAML parser. Anything this reader cannot follow fails, rather than
being guessed at. That covers anchors, aliases, merge keys, tags, flow
mappings, tabs in indentation, document markers, sequences not indented under
their key, and lines it cannot classify.

With --ref it checks that commit's workflows, read through git. The allowlist
always comes from the working tree: `policy` checks out the base branch, so a
pull request cannot allow its own environment.
"""
import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ".github/workflows"
ALLOW_FILE = "ci/workflow_lint.toml"

KEY = re.compile(r"(?P<key>[A-Za-z0-9_][A-Za-z0-9_.\-/]*|\"[^\"]*\"|'[^']*')[ ]*:(?:[ ]+(?P<val>.*?)|)[ ]*$")
BLOCK = re.compile(r"[|>][-+0-9]*[ ]*(#.*)?$")
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'")
SECRETS = re.compile(r"\bsecrets\b")
# In a script: github.event..., github.head_ref, github[...] or a bare `github`.
EVENT_TEXT = re.compile(r"\bgithub\b(?!\s*\.\s*(?!event\b|head_ref\b)[A-Za-z_])")
ENV_NAME = re.compile(r"[A-Za-z0-9_-]+")
SAFE_REF = re.compile(r"\$\{\{\s*github\.sha\s*\}\}")
REFUSED_WITH = ("repository", "run-id", "github-token")


class Scalar:
    """One scalar value, with its position and the mapping path it sits under."""

    def __init__(self, line, path, text):
        self.line, self.path, self.text = line, path, text


def unquote(key):
    return key[1:-1] if key[:1] in "\"'" else key


def parse(text):
    """Split a workflow into scalars, each tagged with its mapping path. Returns
    (scalars, errors). Only the subset of YAML that workflows here use is accepted."""
    lines = text.replace("\r\n", "\n").split("\n")
    scalars, errors = [], []
    stack = []  # (column, key, has_inline_value)
    owner = None  # (column, Scalar) while collecting continuation lines
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip(" ")
        indent = len(raw) - len(raw.lstrip(" "))
        if owner is not None:
            column, scalar = owner
            if not stripped or indent > column:
                scalar.text += "\n" + raw
                continue
            owner = None
        if not stripped or stripped.startswith("#"):
            continue
        if raw[indent] == "\t" or "\t" in raw[:indent]:
            errors.append(f"{number}: a tab in the indentation")
            continue
        if indent == 0 and stripped in ("---", "..."):
            errors.append(f"{number}: a document marker; one workflow is one document")
            continue
        body, column = raw[indent:], indent
        dash = re.match(r"-(?: +|$)", body)
        if dash:
            while stack and stack[-1][0] > indent:
                stack.pop()
            if stack and stack[-1][0] == indent:
                errors.append(f"{number}: a sequence item must be indented under its key")
                continue
            body, column = body[dash.end():], indent + dash.end()
            if not body:
                errors.append(f"{number}: an empty sequence item")
                continue
        match = KEY.fullmatch(body)
        if match:
            while stack and stack[-1][0] >= column:
                stack.pop()
            key, value = unquote(match.group("key")), match.group("val") or ""
            stack.append((column, key, bool(value)))
            path = [k for _, k, _ in stack]
            if key == "<<":
                errors.append(f"{number}: a merge key")
                continue
            scalar = Scalar(number, path, "")
            if BLOCK.fullmatch(value):
                scalars.append(scalar)
                owner = (column, scalar)
                continue
            if value:
                problem = inline_problem(value)
                if problem:
                    errors.append(f"{number}: {problem}")
                    continue
                scalar.text = value
                scalars.append(scalar)
                owner = (column, scalar)
            continue
        if dash:
            problem = inline_problem(body)
            if problem:
                errors.append(f"{number}: {problem}")
                continue
            scalar = Scalar(number, [k for _, k, _ in stack] + ["-"], body)
            scalars.append(scalar)
            owner = (column, scalar)
            continue
        # A bare line under a key with no value of its own is a multi-line plain scalar.
        if stack and not stack[-1][2] and indent > stack[-1][0]:
            scalar = Scalar(number, [k for _, k, _ in stack], raw)
            scalars.append(scalar)
            owner = (stack[-1][0], scalar)
            continue
        errors.append(f"{number}: cannot read this line")
    return scalars, errors


def inline_problem(value):
    """Anchors, aliases, tags and flow mappings, outside quotes and expressions."""
    bare = QUOTED.sub("''", EXPR.sub("x", value))
    bare = re.sub(r"\s+#.*$", "", bare)
    if bare[:1] in "&*!@`%":
        return "an anchor, alias, tag or reserved character"
    if "{" in bare or "}" in bare:
        return "a flow mapping"
    if re.search(r"[\[,]\s*[&*!]", bare):
        return "an anchor, alias or tag inside a flow sequence"
    return None


def expressions(text):
    """The bodies of `${{ ... }}` in a scalar, and whether one is left open."""
    found = [m.group(1) for m in EXPR.finditer(text)]
    # A body holding another `${{` means an earlier one was left open and the match ran on.
    return found, "${{" in EXPR.sub("", text) or any("${{" in body for body in found)


def lint(name, text, allowed):
    scalars, problems = parse(text)
    errors = [f"{name}:{p}" for p in problems]
    jobs = {}
    for s in scalars:
        exprs, unclosed = expressions(s.text)
        if unclosed:
            errors.append(f"{name}:{s.line}: an expression that is never closed")
        in_job = len(s.path) >= 2 and s.path[0] == "jobs"
        job = jobs.setdefault(s.path[1], {"secret": None, "env": None, "env_line": None, "refs": [], "with": []}) \
            if in_job else None
        uses_secret = any(SECRETS.search(e) for e in exprs)
        if uses_secret and not in_job:
            errors.append(f"{name}:{s.line}: a secret outside a job; secrets belong to a job with an allowed environment")
        if in_job and uses_secret and job["secret"] is None:
            job["secret"] = s.line
        if "secrets" in s.path:
            errors.append(f"{name}:{s.line}: secrets passed to a reusable workflow")
        if s.path[-1:] == ["run"] or (s.path[-2:-1] == ["run"]):
            if any(EVENT_TEXT.search(e) for e in exprs):
                errors.append(f"{name}:{s.line}: a run script expands github.event, github.head_ref or the github "
                              "context; pass the value through env: instead")
        if not in_job:
            continue
        rest = s.path[2:]
        if rest in (["environment"], ["environment", "name"]):
            value = QUOTED.sub(lambda m: m.group(0)[1:-1], re.sub(r"\s+#.*$", "", s.text.strip()))
            if exprs or not ENV_NAME.fullmatch(value):
                errors.append(f"{name}:{s.line}: an environment must be a plain name, not '{s.text.strip()}'")
                value = None
            job["env"], job["env_line"] = value, s.line
        if "steps" in rest and "with" in rest:
            key = rest[-1]
            if key == "ref":
                job["refs"].append((s.line, s.text.strip()))
            elif key in REFUSED_WITH:
                job["with"].append((s.line, key))
    for job_id, job in jobs.items():
        if job["secret"] is not None and job["env"] not in allowed:
            where = f"environment '{job['env']}'" if job["env"] else "no environment"
            errors.append(f"{name}:{job['secret']}: job '{job_id}' reads a secret with {where}; "
                          f"allowed: {sorted(allowed)}")
        if job["secret"] is None and job["env"] is None:
            continue
        for line, ref in job["refs"]:
            if not SAFE_REF.fullmatch(QUOTED.sub(lambda m: m.group(0)[1:-1], ref)):
                errors.append(f"{name}:{line}: job '{job_id}' holds a secret or environment and checks out "
                              f"'{ref}'; only ${{{{ github.sha }}}} is allowed")
        for line, key in job["with"]:
            errors.append(f"{name}:{line}: job '{job_id}' holds a secret or environment and sets '{key}'")
    return errors


def load_allowed(text):
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"{ALLOW_FILE}: {error}") from error
    names = data.get("secret_environments")
    if not isinstance(names, list) or not all(isinstance(n, str) and ENV_NAME.fullmatch(n) for n in names):
        raise ValueError(f"{ALLOW_FILE}: secret_environments must be a list of plain environment names")
    return set(names)


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True).stdout


def workflow_files(root, ref=None):
    """{path: text} for every workflow file, from the working tree or from a commit."""
    if ref is None:
        folder = Path(root) / WORKFLOWS
        paths = sorted(p for p in folder.iterdir() if p.suffix in (".yml", ".yaml")) if folder.is_dir() else []
        return {f"{WORKFLOWS}/{p.name}": p.read_bytes().decode("utf-8") for p in paths}
    commit = git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").decode().strip()
    names = git(root, "ls-tree", "-r", "-z", "--name-only", commit, "--", f"{WORKFLOWS}/").decode().split("\0")
    return {n: git(root, "show", f"{commit}:{n}").decode("utf-8")
            for n in sorted(names) if n.endswith((".yml", ".yaml"))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ref", help="check this commit's workflows, read through git")
    args = parser.parse_args(argv)
    try:
        allowed = load_allowed((ROOT / ALLOW_FILE).read_text(encoding="utf-8"))
        files = workflow_files(ROOT, args.ref)
    except (OSError, ValueError, UnicodeDecodeError, subprocess.CalledProcessError) as error:
        sys.exit(f"workflow_lint: {error}")
    errors = [e for name, text in files.items() for e in lint(name, text, allowed)]
    if not files:
        errors.append(f"no workflow files under {WORKFLOWS}")
    print(json.dumps({"files": sorted(files), "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

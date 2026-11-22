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
- A script (`run:`, or the `script` input of an action such as
  github-script) may expand only fields no one can choose:
  `github.sha`, `github.run_id`, `github.run_number`, `github.run_attempt`,
  `github.repository`, `github.repository_id`, `github.server_url`,
  `github.api_url`, `github.workspace`, `github.event_name`, `runner.temp`,
  `runner.os` and `runner.arch`. Anything else, including `github.event`,
  `github.ref_name` (a pushed branch name), `env`, `steps`, `needs`, `inputs`
  and `matrix`, reaches the script as a shell variable through `env:`, so it
  can never become shell code.

Context names, keys and action inputs are compared without regard to case,
as GitHub compares them. Every composite action definition
(`action.yml` or `action.yaml`, anywhere in the tree) gets the script rule
too. A script is a `run:` or `shell:` value, or a `script`, `run`, `command`,
`args` or `entrypoint` input. A backslash inside a double-quoted string is
refused, because YAML decodes its escapes (`\x73ecrets`, an escaped line
break) only after this reader has read the raw text.

The YAML is read as text with the standard library, because the repository
has no YAML parser. Anything this reader cannot follow fails, rather than
being guessed at. That covers anchors, aliases, merge keys, tags, flow
mappings, tabs in indentation, document markers, sequences not indented under
their key, explicit `?` keys, a value that does not start on its key's line
(unless it is a `|` or `>` block), flow sequences holding anything but plain
items, block-scalar indentation indicators, a lone CR or other Unicode line
breaks, and lines it cannot classify.

Not covered, and left to the maintainer's review of every workflow change
(lane C): a job that fetches and runs other code from inside a script, for
example `git fetch` of a pull request ref followed by a build. Only the
`with:` inputs are checked.

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
BLOCK = re.compile(r"[|>][-+]?[ ]*(#.*)?$")
QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'")
SECRETS = re.compile(r"\bsecrets\b", re.I)
SCRIPT_SAFE = re.compile(r"\s*(github\s*\.\s*(sha|run_id|run_number|run_attempt|repository|repository_id|server_url"
                         r"|api_url|workspace|event_name)|runner\s*\.\s*(temp|os|arch))\s*", re.I)
ENV_NAME = re.compile(r"[A-Za-z0-9_-]+")
SAFE_REF = re.compile(r"\$\{\{\s*github\s*\.\s*sha\s*\}\}", re.I)
REFUSED_WITH = ("repository", "run-id", "github-token")
# Values that a runner executes or hands to a shell: the script rule covers them all.
SCRIPT_KEYS = ("run", "shell")
SCRIPT_INPUTS = ("script", "run", "command", "args", "entrypoint")
DOUBLE_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"?", re.S)
LINE_BREAKS = re.compile("\r(?!\n)|[\x85\u2028\u2029]")


class Scalar:
    """One scalar value, with its position and the mapping path it sits under."""

    def __init__(self, line, path, text):
        self.line, self.path, self.text, self.flow = line, path, text, False


def unquote(key):
    """Keys compare without case, as GitHub compares action inputs and contexts."""
    return (key[1:-1] if key[:1] in "\"'" else key).lower()


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
            if "\\" in match.group("key"):
                errors.append(f"{number}: a backslash in a key")
                continue
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
                scalar.text, scalar.flow = value, value.startswith("[")
                scalars.append(scalar)
                owner = (column, scalar)
            continue
        if dash:
            problem = inline_problem(body)
            if problem:
                errors.append(f"{number}: {problem}")
                continue
            scalar = Scalar(number, [k for _, k, _ in stack] + ["-"], body)
            scalar.flow = body.startswith("[")
            scalars.append(scalar)
            owner = (column, scalar)
            continue
        # Includes a value that starts on the line after its key, an explicit `? key`,
        # and a key with a space in it: each could hide the lines below it.
        errors.append(f"{number}: cannot read this line")
    return scalars, errors


def inline_problem(value):
    """Anchors, aliases, tags, explicit keys and flow mappings at the start of a value."""
    if value[:1] in "&*!@`%?:|>":
        return "an anchor, alias, tag, explicit key or reserved character"
    if value[:1] == "{":
        return "a flow mapping"
    return None


def flow_problem(text):
    """A flow sequence may hold only plain or quoted scalars and expressions."""
    exprs, unclosed, bare = expressions(text)
    bare = QUOTED.sub("''", bare)
    bare = re.sub(r"\s+#[^\n]*", "", bare)
    if unclosed or not re.fullmatch(r"\[[^\[\]{}]*\]\s*", bare):
        return "a flow sequence that is not a plain list"
    # Any `:` left is a key: YAML allows `"run":"x"` with nothing after the colon.
    if ":" in bare or re.search(r"[\[,]\s*[&*!?|>]", bare):
        return "a flow sequence holding a mapping, anchor, alias or tag"
    return None


def expressions(text):
    """The bodies of `${{ ... }}` in a scalar, the text with each replaced by `x`,
    and whether one is left open. A `}}` inside a quoted string does not end one."""
    found, rest, i = [], [], 0
    while True:
        start = text.find("${{", i)
        if start < 0:
            rest.append(text[i:])
            return found, False, "".join(rest)
        rest.append(text[i:start] + "x")
        j, quote = start + 3, False
        while j < len(text):
            if text[j] == "'":
                quote = not quote  # '' inside a string toggles twice: an escaped quote
            elif not quote and text.startswith("}}", j):
                break
            j += 1
        else:
            return found, True, "".join(rest)
        found.append(text[start + 3:j])
        i = j + 2


def lint(name, text, allowed):
    text = text.removeprefix("\ufeff")
    if LINE_BREAKS.search(text):
        return [f"{name}: a lone CR or another Unicode line break; lines end with LF"]
    scalars, problems = parse(text)
    errors = [f"{name}:{p}" for p in problems]
    jobs = {}
    for s in scalars:
        # Only a YAML double-quoted scalar (or one inside a flow sequence) decodes escapes;
        # quotes inside a block or plain scalar, such as a shell script's, are literal.
        quoted = s.text.lstrip().startswith('"') or s.flow
        if quoted and any("\\" in q for q in DOUBLE_QUOTED.findall(s.text)):
            errors.append(f"{name}:{s.line}: a backslash in a double-quoted string; YAML would decode it after "
                          "this check, so use a single-quoted or plain string")
        exprs, unclosed, _ = expressions(s.text)
        if unclosed or any("${{" in e for e in exprs):
            errors.append(f"{name}:{s.line}: an expression that is never closed")
        if s.flow:
            problem = flow_problem(s.text)
            if problem:
                errors.append(f"{name}:{s.line}: {problem}")
        in_job = len(s.path) >= 2 and s.path[0] == "jobs"
        job = jobs.setdefault(s.path[1], {"secret": None, "env": None, "env_line": None, "refs": [], "with": []}) \
            if in_job else None
        uses_secret = any(SECRETS.search(e) for e in exprs)
        if uses_secret and not in_job:
            errors.append(f"{name}:{s.line}: a secret outside a job; secrets belong to a job with an allowed environment")
        if in_job and uses_secret and job["secret"] is None:
            job["secret"] = s.line
        if in_job and "secrets" in s.path:
            errors.append(f"{name}:{s.line}: secrets passed to a reusable workflow")
        if s.path[-1] in SCRIPT_KEYS or (s.path[-2:-1] == ["with"] and s.path[-1] in SCRIPT_INPUTS):
            unsafe = [e.strip() for e in exprs if not SCRIPT_SAFE.fullmatch(e)]
            if unsafe:
                errors.append(f"{name}:{s.line}: a script expands {unsafe}; only fixed run fields may be expanded "
                              "in a script, so pass this value through env: and read it as a shell variable")
        if not in_job:
            continue
        rest = s.path[2:]
        if rest in (["environment"], ["environment", "name"]):
            value = QUOTED.sub(lambda m: m.group(0)[1:-1], re.sub(r"\s+#.*$", "", s.text.strip()))
            if exprs or not ENV_NAME.fullmatch(value):
                errors.append(f"{name}:{s.line}: an environment must be a plain name, not '{s.text.strip()}'")
                value = None
            job["env"], job["env_line"] = (value.lower() if value else value), s.line
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
    return {n.lower() for n in names}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True).stdout


def wanted(path):
    """Workflow files GitHub runs, and every composite action definition: `uses: ./dir`
    runs the action.yml of any directory in the repository, not only .github/actions."""
    if path.startswith(WORKFLOWS + "/"):
        return "/" not in path[len(WORKFLOWS) + 1:] and path.endswith((".yml", ".yaml"))
    return path.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")


def workflow_files(root, ref=None):
    """{path: text} for every workflow and composite action, listed by git and read from
    the working tree, or read from a commit. A symlink in a commit reads as its target
    path, which this reader refuses, so a linked file fails rather than escapes."""
    if ref is None:
        names = git(root, "ls-files", "-z").decode().split("\0")
        base = Path(root)
        return {n: (base / n).read_bytes().decode("utf-8") for n in sorted(names)
                if wanted(n) and (base / n).is_file()}
    commit = git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").decode().strip()
    names = git(root, "ls-tree", "-r", "-z", "--name-only", commit).decode()
    return {n: git(root, "show", f"{commit}:{n}").decode("utf-8") for n in sorted(names.split("\0")) if wanted(n)}


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
    if not any(n.startswith(WORKFLOWS + "/") for n in files):
        errors.append(f"no workflow files under {WORKFLOWS}")
    print(json.dumps({"files": sorted(files), "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

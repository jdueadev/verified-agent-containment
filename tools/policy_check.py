#!/usr/bin/env python3
"""Decide which merge lane a change is in, and check the rules that never bend.

Usage:
  policy_check.py classify --base REF [--head REF] [--map-ref REF] [--reviews FILE --head-sha SHA]
                           [--fork] [--enforce]
  policy_check.py codeowners [--write]
  policy_check.py invariants [--ref REF]

classify   prints the lane of the diff between two commits. Lanes are defined in
           ci/lanes.toml. A ratchet raises the lane to C when the change removes
           or rewords a law, mutant, scenario or sabotage control, or weakens a
           row of claims.toml. With --enforce, a lane C change (or any change
           from a fork) fails unless the maintainer approved the head commit.
codeowners checks that .github/CODEOWNERS is exactly lane C (--write regenerates it).
invariants checks rules that hold on every commit: `sabotage` is not a default
           feature, the lane map parses, CODEOWNERS matches it, and the kernel
           stays pure (no_std, no unsafe, nothing beyond core, no build-time
           file or environment reads). With --ref it checks that commit, read
           through git, instead of the working tree, so `policy` can run it from
           the base branch against an untrusted head.

This script only reads the other commit's files through git. It never imports or
runs them, so it is safe to run from the base branch against an untrusted head.
"""
import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_tokens  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LANES_FILE = "ci/lanes.toml"
CODEOWNERS_FILE = ".github/CODEOWNERS"
HOST_MANIFEST = "crates/containment-host/Cargo.toml"
KERNEL_SRC = "crates/containment-kernel/src"
ORDER = {"A": 0, "B": 1, "C": 2}
SHRINK_FIELDS = ("files", "evidence", "depends_on")
FIXED_FIELDS = ("statement", "falsifier")
# Claim statuses, weakest first. A copy of claims_check.RANK, kept here so that
# `policy` imports nothing but the lexer: it runs from the base branch, and any
# module it imports runs inside the gate (#125). A test keeps the two equal.
RANK = {"proved": 5, "checked-bounded": 4, "tested": 3, "assumed": 2, "planned": 1, "stale": 0}


# ---------- lanes ----------

def load_lanes(text):
    data = tomllib.loads(text)
    lanes = data.get("lanes", {})
    unknown = set(lanes) - set(ORDER)
    if unknown or not isinstance(data.get("owner"), str) or not data["owner"].startswith("@"):
        raise ValueError(f"{LANES_FILE}: needs owner = \"@name\" and only lanes A, B, C (found {sorted(lanes)})")
    for lane, patterns in lanes.items():
        for pattern in patterns:
            if "*" in pattern.removesuffix("/**").replace("*", "", 1) or pattern.startswith(("/", "./")) \
                    or "?" in pattern or "[" in pattern:
                raise ValueError(f"{LANES_FILE}: {pattern!r} is not an exact file, dir/** or a single-* name")
    return data["owner"], {lane: list(lanes.get(lane, [])) for lane in ORDER}


def lane_match(path, pattern):
    """Match one repository path against a lane pattern. Paths are compared as
    written: a leading dot is part of the name, so `.x` never matches `x`."""
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-2])
    if "*" in pattern:
        head, _, tail = pattern.partition("*")
        middle = path[len(head):len(path) - len(tail)] if tail else path[len(head):]
        return (path.startswith(head) and path.endswith(tail) and len(path) >= len(head) + len(tail)
                and "/" not in middle)
    return path == pattern


def lane_of(path, lanes, doc_cited=()):
    """First match wins, checking C, then B, then A. Nothing matched is lane C."""
    for lane in ("C", "B", "A"):
        for pattern in lanes[lane]:
            if lane_match(path, pattern):
                if lane == "A" and path in doc_cited:
                    return "B", "cited as doc: evidence in claims.toml"
                return lane, pattern
    return "C", "unclassified path"


# ---------- reading two commits ----------

def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout


def git_bytes(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, check=True).stdout


def reader(ref):
    """Read files of one commit. A path the commit does not contain reads as None;
    any other git failure (an unknown ref, a broken repository) is raised. Treating
    every failure as "absent" would make the ratchets compare against nothing on
    the base side and escalate nothing, which fails open."""
    commit = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip()

    def get(path):
        try:
            # Bytes, decoded strictly, with only CRLF folded: text mode would turn a lone
            # CR into a newline, and rustc does not end a `//` comment at a lone CR, so
            # the ratchets would see code that the compiler skips (#125, stage 2 review).
            # A file that is not UTF-8 raises, which fails closed.
            return git_bytes("show", f"{commit}:{path}").decode("utf-8").replace("\r\n", "\n")
        except subprocess.CalledProcessError:
            if git("ls-tree", "--name-only", commit, "--", path).strip():
                raise
            return None
    return get


# ---------- inventories, parsed without running anything ----------

def law_blocks(text):
    """Each `law name:` with its body, up to the next top-level line."""
    out, lines, i = {}, (text or "").replace("\r\n", "\n").split("\n"), 0
    while i < len(lines):
        match = re.match(r"law ([a-z_0-9]+):", lines[i])
        if not match:
            i += 1
            continue
        j = i + 1
        while j < len(lines) and (not lines[j] or lines[j][0] in " \t"):
            j += 1
        out[match.group(1)] = "\n".join(line.rstrip() for line in lines[i:j]).strip()
        i = j
    return out


def mutant_entries(text):
    """name -> source of the entry, for BEND_MUTANTS and RUST_MUTANTS, read by ast."""
    out = {}
    if not text:
        return out
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("BEND_MUTANTS", "RUST_MUTANTS") and isinstance(node.value, (ast.List, ast.Tuple)):
            for element in node.value.elts:
                if isinstance(element, ast.Tuple) and element.elts and isinstance(element.elts[0], ast.Constant):
                    out[f"{node.targets[0].id}:{element.elts[0].value}"] = ast.dump(element)
    return out


def suite_entries(text):
    """name -> the layout-free keys of every entry with that name in SCENARIOS and
    SABOTAGE of harness.rs or live_suite.rs, read with the shared Rust lexer (never
    run). Returns the entries and the reasons a table could not be read; an
    unreadable table is never an empty one."""
    entries, problems = {}, []
    if not text:
        return entries, problems
    for const in ("SCENARIOS", "SABOTAGE"):
        try:
            rows = rust_tokens.const_array_entries(text, const)
        except rust_tokens.LexError as error:
            problems.append(f"{const} could not be read: {error}")
            continue
        for row in rows:
            first = row[1] if row[0].text == "(" and len(row) > 1 else row[0]
            name = rust_tokens.string_value(first)
            if name is None:
                problems.append(f"{const} has an entry with no literal name")
                continue
            # Several rows may share a name; keep every one, in order.
            entries.setdefault(f"{const}:{name}", []).append(rust_tokens.entry_key(row))
    return entries, problems


def claim_rows(text):
    return {c["id"]: c for c in tomllib.loads(text).get("claim", [])} if text else {}


# ---------- ratchets ----------

def ratchets(base_get, head_get):
    """Reasons the head weakens evidence that the base had. Any reason means lane C."""
    out = []
    base_laws, head_laws = law_blocks(base_get("formal/LAWS.bend")), law_blocks(head_get("formal/LAWS.bend"))
    for name, body in base_laws.items():
        if name not in head_laws:
            out.append(f"law {name} was removed")
        elif head_laws[name] != body:
            out.append(f"law {name} was reworded")
    base_mut, head_mut = (mutant_entries(g("tools/kernel_mutants.py")) for g in (base_get, head_get))
    for name, body in base_mut.items():
        if name not in head_mut:
            out.append(f"mutant {name} was removed")
        elif head_mut[name] != body:
            out.append(f"mutant {name} was changed")
    for path in ("crates/containment-host/src/harness.rs", "crates/containment-host/src/live_suite.rs"):
        (base_rows, _), (head_rows, head_problems) = suite_entries(base_get(path)), suite_entries(head_get(path))
        if base_rows and head_problems:
            out.extend(f"{path}: {problem}" for problem in head_problems)
        for name, keys in sorted(base_rows.items()):
            if name not in head_rows:
                if not head_problems:
                    out.append(f"{path}: {name} was removed")
            elif sorted(head_rows[name]) != sorted(keys):
                out.append(f"{path}: {name} was changed")
    try:
        base_claims, head_claims = claim_rows(base_get("claims.toml")), claim_rows(head_get("claims.toml"))
    except tomllib.TOMLDecodeError as error:
        return out + [f"claims.toml does not parse: {error}"]
    for cid, old in base_claims.items():
        new = head_claims.get(cid)
        if new is None:
            out.append(f"claim {cid} was removed")
            continue
        for field in FIXED_FIELDS:
            if old.get(field) != new.get(field):
                out.append(f"claim {cid}: {field} was reworded")
        for field in SHRINK_FIELDS:
            lost = [x for x in old.get(field, []) if x not in new.get(field, [])]
            if lost:
                out.append(f"claim {cid}: {field} lost {', '.join(lost)}")
        if RANK.get(new.get("status"), 99) > RANK.get(old.get("status"), 99):
            out.append(f"claim {cid}: status raised from {old.get('status')} to {new.get('status')}")
        if old.get("platforms", []) != new.get("platforms", []):
            out.append(f"claim {cid}: platforms was edited")
    for cid, new in head_claims.items():
        if cid not in base_claims and new.get("platforms"):
            out.append(f"claim {cid}: new row records platforms")
    return out


# ---------- spec immutability ----------

# Spec: the tests and known-bad inputs that judge the code (#125). Once a spec file
# is on the base branch it must be the same at head. New spec goes in new files.
# Equal means equal code: Python compares by ast, Rust by the lexer's code tokens, so
# reformatting or a changed comment is not an edit. Everything else compares as text.
SPEC_PATTERNS = ("tools/test_*.py", "crates/containment-kernel/tests/**", "ci/corpus/**")
KERNEL_TESTS = "crates/containment-kernel/tests/"


def spec_links(ref, paths):
    """Spec paths that are symbolic links at `ref`. A link to a file in a freer lane
    would let later edits to that file change an immutable test unseen."""
    spec = [p for p in paths if is_spec(p)]
    if not spec:
        return []
    out = git("ls-tree", "-z", f"{ref}^{{commit}}", "--", *spec)
    return sorted(entry.split("\t", 1)[1] for entry in out.split("\0")
                  if "\t" in entry and entry.split(" ", 1)[0] == "120000")


def is_spec(path):
    return any(lane_match(path, pattern) for pattern in SPEC_PATTERNS)


def declared_encoding(text):
    """The source encoding Python would use for this file (PEP 263), normalised."""
    import io
    import tokenize
    try:
        name, _ = tokenize.detect_encoding(io.BytesIO(text.encode("utf-8")).readline)
    except SyntaxError as error:
        return f"an unknown one ({error.msg})"
    return name.lower().replace("_", "-")


def python_ast(text):
    """The ast as the interpreter would build it. A coding declaration other than UTF-8
    is refused: `# coding: raw_unicode_escape` or `utf-7` can turn a comment into code
    on import while UTF-8 text shows only the comment (#125, stage 2 review). The bytes
    are parsed, as the interpreter reads them, so anything else that depends on the
    declaration is seen the same way."""
    declared = declared_encoding(text)
    if declared not in ("utf-8", "utf-8-sig"):
        raise ValueError(f"declares the source encoding {declared}, which is not UTF-8")
    try:
        return ast.parse(text.encode("utf-8"))
    except SyntaxError as error:
        raise ValueError(f"does not parse ({error.msg})") from error


def rust_tokens_strict(text):
    """Code tokens, refusing a lone CR: rustc ends a `//` comment only at a newline, so
    a CR in a comment can hide code from a reader that treats it as a line break."""
    if "\r" in text.replace("\r\n", ""):
        raise ValueError("contains a carriage return that does not end a line")
    try:
        return rust_tokens.code_tokens(text)
    except rust_tokens.LexError as error:
        raise ValueError(f"cannot be lexed ({error})") from error


def spec_form(path, text):
    """What has to stay equal. Raises ValueError when the text cannot be read, which the
    caller treats as an edit: an unreadable head file is never the same as its base.
    Corpus entries are data, often hostile on purpose, so they compare as text whatever
    their extension."""
    if path.startswith("ci/corpus/"):
        return text
    if path.endswith(".py"):
        return ast.dump(python_ast(text))
    if path.endswith(".rs"):
        return rust_tokens_strict(text)
    return text


def spec_ratchets(paths, base_get, head_get):
    """Reasons the head edits or removes spec that the base has. A rename is a removal:
    the diff is read with --no-renames, so the old path is gone at head."""
    out = []
    for path in sorted(p for p in paths if is_spec(p)):
        # Cargo also builds tests/<dir>/main.rs as a test target, which `spec` does not
        # run on its own. Only direct tests/<name>.rs files are spec there.
        rest = path[len(KERNEL_TESTS):] if path.startswith(KERNEL_TESTS) else None
        if rest is not None and ("/" in rest or not rest.endswith(".rs")) and head_get(path) is not None:
            out.append(f"spec {path} is not a direct {KERNEL_TESTS}<name>.rs file")
        old = base_get(path)
        if old is None:
            continue
        new = head_get(path)
        if new is None:
            out.append(f"spec {path} was removed")
            continue
        try:
            base_form = spec_form(path, old)
        except ValueError:
            # A base file that cannot be read can only stay byte-for-byte the same.
            base_form = None
        if base_form is None:
            same = new == old
        else:
            try:
                same = spec_form(path, new) == base_form
            except ValueError as error:
                out.append(f"spec {path} {error}")
                continue
        if not same:
            out.append(f"spec {path} was edited")
    return out


# ---------- data modules ----------

# Lane B Python modules that a base test imports. Importing a module runs its top-level
# code inside the importing test's process, where it could patch that test, so such a
# module must stay pure data: a docstring and assignments of literals, nothing that
# runs. A change that adds anything else is lane C (#125, stage 2).
DATA_MODULES = ("tools/kernel_mutants.py",)


def data_module_errors(path, text):
    """Why `text` is not pure data, or [] when it is. Unparsable text is not data."""
    try:
        tree = python_ast(text)
    except ValueError as error:
        return [f"{path} {error}"]
    out, seen = [], set()
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            continue
        # One plain upper-case name per assignment, each assigned once: a second
        # `BEND_MUTANTS = []` or `X = BEND_MUTANTS = []` would empty a list that the
        # mutant ratchet reads from its first assignment.
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and re.fullmatch(r"[A-Z][A-Z0-9_]*", node.targets[0].id) and node.targets[0].id not in seen:
            try:
                ast.literal_eval(node.value)
                seen.add(node.targets[0].id)
                continue
            except ValueError:
                pass
        out.append(f"{path}:{node.lineno} is not a single literal assignment of a new UPPER_CASE name, "
                   "so importing it could run code or replace data")
    return out


def data_module_ratchets(paths, head_get):
    out = []
    for path in sorted(set(paths) & set(DATA_MODULES)):
        text = head_get(path)
        if text is not None:
            out.extend(data_module_errors(path, text))
    return out


# ---------- classify ----------

def classify(paths, base_get, head_get, lanes, head_links=()):
    head_claims = head_get("claims.toml") or ""
    doc_cited = set(re.findall(r'"doc:([^#"]+)', head_claims)) | set(re.findall(r'"doc:([^#"]+)', base_get("claims.toml") or ""))
    by_path = {path: lane_of(path, lanes, doc_cited) for path in paths}
    escalations = ratchets(base_get, head_get) + spec_ratchets(paths, base_get, head_get)
    escalations += data_module_ratchets(paths, head_get)
    escalations += [f"spec {path} is a symbolic link" for path in head_links]
    lane = max([entry[0] for entry in by_path.values()] + ["A"], key=ORDER.get)
    if escalations:
        lane = "C"
    return {"lane": lane, "escalations": escalations,
            "paths": {path: {"lane": entry[0], "rule": entry[1]} for path, entry in sorted(by_path.items())}}


def approved(reviews, owner, head_sha):
    """True when the owner's latest review approves exactly this head commit.
    Without a head commit nothing is approved: a review whose commit is unknown
    must never match a head that is unknown too."""
    if not head_sha:
        return False
    latest = None
    flat = [r for page in reviews for r in (page if isinstance(page, list) else [page])]
    for review in flat:
        if ((review.get("user") or {}).get("login") or "").lower() == owner.lstrip("@").lower() \
                and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest = review
    return bool(latest) and latest["state"] == "APPROVED" and latest.get("commit_id") == head_sha


# ---------- CODEOWNERS ----------

def codeowners_text(owner, lanes):
    lines = [
        "# Generated from ci/lanes.toml by `python3 tools/policy_check.py codeowners --write`. Do not edit by hand.",
        "# These are the lane C paths: changes to them need the maintainer's review.",
        "# A path listed in no lane is also lane C; tools/policy_check.py enforces that part.",
        "",
    ]
    for pattern in lanes["C"]:
        lines.append(("/" + pattern[:-2] if pattern.endswith("/**") else "/" + pattern) + " " + owner)
    return "\n".join(lines) + "\n"


def codeowners_errors(owner, lanes, current):
    if current is None:
        return [f"{CODEOWNERS_FILE} is missing; run tools/policy_check.py codeowners --write"]
    if current.replace("\r\n", "\n") != codeowners_text(owner, lanes):
        return [f"{CODEOWNERS_FILE} does not match lane C in {LANES_FILE}; run tools/policy_check.py codeowners --write"]
    return []


# ---------- invariants ----------

def sabotage_default_errors(manifest_text):
    """`sabotage` must never be reachable from the default features."""
    features = tomllib.loads(manifest_text).get("features", {})
    seen, todo = set(), list(features.get("default", []))
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(features.get(name, []))
    return [f"{HOST_MANIFEST}: `sabotage` is enabled by the default features"] if "sabotage" in seen else []


# The kernel is lane B, but it is compiled into the host binary. Its laws, mutants
# and the differential test check its decisions, not its side effects, so the
# attributes that keep it pure are checked here on every commit (#83). Tokens, not
# text: a comment or a string that names `std` is not code.
KERNEL_ROOT_ATTRIBUTES = (("no_std",), ("forbid", "(", "unsafe_code", ")"))
# Identifiers the kernel may not contain at all, in any position: a call, an import,
# an alias, a path or an attribute argument (including inside cfg_attr). The kernel
# uses none of them, so refusing the name outright cannot be dodged by renaming
# (`use core::include as load`) or by moving it (`#[cfg_attr(all(), path = ..)]`).
KERNEL_FORBIDDEN_IDENTS = {
    # crates beyond core, and foreign code
    "std": "depends on more than `core`",
    "alloc": "depends on more than `core`",
    "extern": "declares foreign code or another crate",
    # build-time reads of files or the environment
    "include": "reads a file at build time",
    "include_str": "reads a file at build time",
    "include_bytes": "reads a file at build time",
    "env": "reads the environment at build time",
    "option_env": "reads the environment at build time",
    # source from elsewhere, and code that bypasses forbid(unsafe_code)
    "path": "loads source from elsewhere (`#[path]`)",
    "global_asm": "injects machine code without `unsafe`",
    "asm": "injects machine code",
    "naked_asm": "injects machine code",
    "link": "links foreign code",
    "link_section": "places data in a chosen link section",
    "no_mangle": "exports a symbol",
    "export_name": "exports a symbol",
    "used": "keeps a symbol for the linker",
    "linkage": "sets symbol linkage",
    "feature": "enables unstable features",
}


def _ident(kind, text):
    """A raw identifier (`r#include`) means the same name as `include`."""
    return text[2:] if kind == "ident" and text.startswith("r#") else text


def _leading_inner_attributes(toks):
    """The token lists of the `#![...]` attributes that open the file, which are the
    ones that apply to the whole crate. One inside `mod m { ... }` applies to `m` only."""
    attrs, i = [], 0
    while toks[i:i + 3] == ["#", "!", "["]:
        depth, j = 0, i + 2
        while j < len(toks):
            depth += toks[j] == "["
            depth -= toks[j] == "]"
            if depth == 0:
                break
            j += 1
        if j >= len(toks):
            break
        attrs.append(toks[i + 3:j])
        i = j + 1
    return attrs


def kernel_purity_errors(files):
    """`files` maps each kernel source path to its text; `lib.rs` is the crate root."""
    out = []
    root = f"{KERNEL_SRC}/lib.rs"
    if root not in files:
        return [f"{root}: missing, so the kernel's purity cannot be checked"]
    for path, text in sorted(files.items()):
        try:
            toks = [_ident(kind, tok) for kind, tok in rust_tokens.code_tokens(text) if kind != "doc"]
        except rust_tokens.LexError as error:
            out.append(f"{path}: cannot be read ({error}), so the kernel's purity cannot be checked")
            continue
        if path == root:
            leading = _leading_inner_attributes(toks)
            for attr in KERNEL_ROOT_ATTRIBUTES:
                if list(attr) not in leading:
                    out.append(f"{path}: the crate attribute #![{''.join(attr)}] is missing from the top of the file")
        for tok in sorted(set(toks) & set(KERNEL_FORBIDDEN_IDENTS)):
            out.append(f"{path}: uses `{tok}`, which {KERNEL_FORBIDDEN_IDENTS[tok]}")
    return out


def kernel_sources(ref=None):
    """Every .rs file under the kernel's src/, from the working tree or, with ref, from that commit."""
    if ref is None:
        base = ROOT / KERNEL_SRC
        return {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8") for p in sorted(base.rglob("*.rs"))}
    get = reader(ref)
    # -z: without it git quotes an unusual name, and a quoted name would be skipped.
    names = git("ls-tree", "-r", "-z", "--name-only", f"{ref}^{{commit}}", "--", f"{KERNEL_SRC}/").split("\0")
    return {name: get(name) for name in sorted(names) if name.endswith(".rs")}


def read(path):
    target = ROOT / path
    return target.read_text(encoding="utf-8") if target.exists() else None


def invariant_errors(get, kernel_files):
    """The rules that hold on every commit, over files read by `get`."""
    lanes_text = get(LANES_FILE)
    if lanes_text is None:
        return [f"{LANES_FILE}: missing"]
    owner, lanes = load_lanes(lanes_text)
    manifest = get(HOST_MANIFEST)
    manifest_errors = sabotage_default_errors(manifest) if manifest is not None else [f"{HOST_MANIFEST}: missing"]
    return codeowners_errors(owner, lanes, get(CODEOWNERS_FILE)) + manifest_errors + kernel_purity_errors(kernel_files)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("classify")
    c.add_argument("--base", required=True)
    c.add_argument("--head", default="HEAD")
    c.add_argument("--map-ref", help="commit to read ci/lanes.toml from (default: --base)")
    c.add_argument("--reviews")
    c.add_argument("--head-sha")
    c.add_argument("--fork", action="store_true")
    c.add_argument("--enforce", action="store_true")
    o = sub.add_parser("codeowners")
    o.add_argument("--write", action="store_true")
    i = sub.add_parser("invariants")
    i.add_argument("--ref", help="check this commit, read through git, instead of the working tree")
    args = parser.parse_args(argv)
    try:
        return run(parser, args)
    except subprocess.CalledProcessError as error:
        # Fail closed, but say why: the workflow shows stderr next to an empty result.
        sys.exit(f"policy: {' '.join(error.cmd[3:])} failed: {(error.stderr or '').strip()}")


def run(parser, args):
    if args.command == "classify" and (args.reviews or args.enforce) and not args.head_sha:
        parser.error("--reviews and --enforce need --head-sha: approval is only ever of one commit")

    if args.command == "classify":
        base_get, head_get = reader(args.base), reader(args.head)
        # The lane map comes from the target branch, never from the change: a
        # change cannot reclassify itself, and a path the target has since
        # promoted is judged by the newer rule. The diff and the ratchets still
        # compare against --base, the point the change started from.
        map_ref = args.map_ref or args.base
        lanes_text = reader(map_ref)(LANES_FILE)
        if lanes_text is None:
            sys.exit(f"policy: {map_ref} has no {LANES_FILE}; refusing to classify against another lane map")
        owner, lanes = load_lanes(lanes_text)
        if args.head_sha and git("rev-parse", "--verify", f"{args.head}^{{commit}}").strip() != args.head_sha:
            sys.exit(f"policy: --head {args.head} is not --head-sha {args.head_sha}; an approval is of one commit")
        paths = [p for p in git("diff", "--name-only", "--no-renames", args.base, args.head).splitlines() if p]
        # git quotes a name with unusual characters, and a quoted name matches no lane
        # pattern and no ratchet. Refuse rather than judge a path we cannot read.
        quoted = [p for p in paths if p.startswith('"')]
        if quoted:
            sys.exit(f"policy: paths with unusual characters cannot be classified: {quoted}")
        result = classify(paths, base_get, head_get, lanes, spec_links(args.head, paths))
        needs_owner = result["lane"] == "C" or args.fork
        reviews = json.loads(Path(args.reviews).read_text(encoding="utf-8")) if args.reviews else []
        result["fork"] = args.fork
        result["needs_maintainer"] = needs_owner
        result["approved"] = approved(reviews, owner, args.head_sha) if needs_owner else None
        result["enforced"] = args.enforce
        print(json.dumps(result, indent=2))
        if needs_owner and not result["approved"]:
            why = "it comes from a fork" if args.fork and result["lane"] != "C" else "it is lane C"
            print(f"policy: this change needs {owner}'s approval of the head commit because {why}.", file=sys.stderr)
            return 1 if args.enforce else 0
        return 0

    if args.command == "codeowners":
        owner, lanes = load_lanes(read(LANES_FILE))
        if args.write:
            (ROOT / CODEOWNERS_FILE).write_text(codeowners_text(owner, lanes), encoding="utf-8", newline="\n")
            return 0
        errors = codeowners_errors(owner, lanes, read(CODEOWNERS_FILE))
    elif args.ref:
        errors = invariant_errors(reader(args.ref), kernel_sources(args.ref))
    else:
        errors = invariant_errors(read, kernel_sources())
    print(json.dumps({"errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

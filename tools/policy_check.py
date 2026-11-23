#!/usr/bin/env python3
"""Decide which merge lane a change is in, and check the rules that never bend.

Usage:
  policy_check.py classify --base REF [--head REF] [--map-ref REF] [--reviews FILE --head-sha SHA]
                           [--fork] [--enforce]
  policy_check.py codeowners [--write]
  policy_check.py invariants [--ref REF]
  policy_check.py fresh-reviews --head-sha SHA --reviews FILE --activity FILE --pr FILE --timeline FILE

classify   prints the lane of the diff between two commits. Lanes are defined in
           ci/lanes.toml. A ratchet raises the lane to C when the change removes
           or rewords a law, mutant, scenario or sabotage control, or weakens a
           row of claims.toml, adds agent configuration below the root, or
           departs from written-once handovers (a rewrite, rename, re-used
           path, removal, or handover mixed with other work). With --enforce, a lane C change (or any change from a
           fork) fails unless the maintainer approved the head commit.
codeowners checks that .github/CODEOWNERS is exactly lane C (--write regenerates it).
invariants checks rules that hold on every commit: `sabotage` is not a default
           feature, the lane map parses, CODEOWNERS matches it, and the kernel
           stays pure (no_std, no unsafe, nothing beyond core, no build-time
           file or environment reads), and the tracked .claude/ holds only
           allow-listed regular files under plain ASCII names that no
           checkout folds together, with no agent names inside, dated flat
           handovers, prompt frontmatter keys from PROMPT_KEYS, no shell
           injection or carriage returns in prompts, and a settings.json with
           allowed keys.
           With --ref it checks that commit, read
           through git, instead of the working tree, so `policy` can run it from
           the base branch against an untrusted head.
fresh-reviews prints the PR's reviews (the API's JSON) with commit_id cleared on every
           review not submitted strictly after the head arrived on the PR, so that
           classify --reviews counts only an approval of the head the owner saw
           (#149). The arrival comes from the repository Activity log for the head
           ref (activity), the PR (pr) and its issue timeline (timeline). When it
           cannot be established, every review is cleared. Input that is not the
           API's JSON shape is refused: exit 1, last line "fresh-reviews: ...".

This script only reads the other commit's files through git. It never imports or
runs them, so it is safe to run from the base branch against an untrusted head.
"""
import argparse
import ast
import datetime
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import unicodedata
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


# ---------- agent configuration (#169) ----------

# Names that Claude Code or another agent tool reads as configuration or as
# instructions, at any depth: a nested CLAUDE.md or .claude/ steers a session that
# works in that directory. Compared folded (see _folded), because a
# case-insensitive checkout (Windows, macOS) opens `.Claude/` as `.claude/`.
AGENT_CONFIG_NAMES = (".claude", "claude.md", "claude.local.md", "agents.md", ".mcp.json")
# The sanctioned copies: the root rule files, and the root .claude/ directory,
# which `invariants` holds to CLAUDE_ALLOWED.
ROOT_AGENT_FILES = ("AGENTS.md", "CLAUDE.md")
CLAUDE_DIR = ".claude"
CLAUDE_ALLOWED = ("settings.json", "hooks/", "skills/", "agents/", "handover/")
# Top-level keys a tracked .claude/settings.json may use. Settings such as hooks,
# env, apiKeyHelper, statusLine and MCP servers take effect when a session starts,
# before anyone has reviewed the branch, so each key is added here by its own
# reviewed change. `permissions` is the first (#173), and only in a form that
# restricts: see PERMISSION_KEYS.
SETTINGS_KEYS = ("permissions",)
# What a shared `permissions` object may hold. `deny` and `ask` only restrict, and
# Claude Code evaluates deny first in every scope and mode. Everything else is
# refused: `allow` would run checkout code without a prompt in a trusted session
# (the tool tests import every tools/test_*.py; cargo test runs build.rs), and a
# project scalar such as `defaultMode` or `blockWritesOutsideWorkingDirectories`
# overrides the user's own value, so even a "restrictive" one can loosen it.
PERMISSION_KEYS = ("deny", "ask", "disableBypassPermissionsMode")
PERMISSION_RULE_LISTS = ("deny", "ask")
PERMISSION_RULES_MAX = 64
PERMISSION_RULE_MAX_CHARS = 200
CLAUDE_SETTINGS = ".claude/settings.json"
SETTINGS_MAX_BYTES = 64 * 1024
# Frontmatter keys a shared skill or agent prompt may use. The others
# (allowed-tools, hooks, model, permissionMode, mcpServers, ...) grant or run
# something before review, so each is added here by its own reviewed change.
PROMPT_KEYS = ("name", "description", "disable-model-invocation")
PROMPT_DIRS = (".claude/skills/", ".claude/agents/")
FRONTMATTER_KEY = re.compile(r"[A-Za-z0-9_-]+:(?: |$)")
# A skill's `!` + backquoted command, or a fenced block opened with ```!, runs when
# the skill loads, without a prompt.
SHELL_INJECTION = re.compile(r"!`|^[ \t]*(?:`{3,}|~{3,})[ \t]*!", re.M)
# Handovers are written once and kept as written. Every departure from that rule (a
# rewrite, a replacement, a re-used path, a handover mixed with other work, a
# removal) escalates with its own reason, so the maintainer sees it; the maintainer
# chose a flag over a hard failure (#169). One flat directory of dated names.
HANDOVER_DIR = ".claude/handover/"
HANDOVER_NAME = re.compile(r"HANDOVER-\d{4}-\d\d-\d\d-\d{4}\.md")
REGULAR_MODES = ("100644", "100755")
MODE_NAMES = {"120000": "symbolic link", "160000": "gitlink (submodule)", "040000": "directory"}
# Names Windows reserves for devices, with or without an extension (`NUL.txt` is NUL),
# and the characters it refuses in a name. A checkout there fails or opens a device.
WINDOWS_DEVICES = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$"}
                            | {f"{d}{n}" for d in ("com", "lpt") for n in "123456789¹²³"})
WINDOWS_INVALID = re.compile(r'[<>:"|?*\\\x00-\x1f]')


def _windows_safe(part):
    return not WINDOWS_INVALID.search(part) and part.split(".", 1)[0].rstrip(" ").casefold() not in WINDOWS_DEVICES


def _folded(name):
    """One path component as a Windows or macOS checkout would see it: NFKC, without
    the format characters (zero-width joiners and the like) that HFS+ ignores, case
    folded, without the trailing dots and spaces Windows drops, and without an NTFS
    `:stream` suffix."""
    name = "".join(c for c in unicodedata.normalize("NFKC", name) if unicodedata.category(c) != "Cf")
    return name.split(":", 1)[0].rstrip(" .").casefold()


def agent_config_escalations(paths):
    """Paths that add or change agent configuration outside the sanctioned root copies.
    The root .claude/ is sanctioned, but an agent name inside it is not."""
    out = []
    for path in sorted(paths):
        if path in ROOT_AGENT_FILES:
            continue
        parts = path.split("/")
        if parts[0] == CLAUDE_DIR:
            parts = parts[1:]
        hits = [part for part in parts if _folded(part) in AGENT_CONFIG_NAMES]
        if hits:
            out.append(f"agent config {path}: agent tools read {hits[0]!r} as configuration or instructions, "
                       "and only the root AGENTS.md, CLAUDE.md and .claude/ are sanctioned")
    return out


def tree_entries(ref, *pathspec):
    """{path: (mode, object id)} for every blob and gitlink of a commit."""
    out = git("ls-tree", "-r", "-z", "--full-tree", f"{ref}^{{commit}}", "--", *pathspec)
    entries = {}
    for item in out.split("\0"):
        if "\t" in item:
            meta, path = item.split("\t", 1)
            mode, _kind, oid = meta.split(" ")
            entries[path] = (mode, oid)
    return entries


def index_entries():
    """{path: (mode, object id)} for every tracked path in the index: what would be committed,
    not what happens to be on disk."""
    entries = {}
    for item in git("ls-files", "-s", "-z").split("\0"):
        if "\t" in item:
            meta, path = item.split("\t", 1)
            mode, oid, _stage = meta.split(" ")
            entries[path] = (mode, oid)
    return entries


def earlier_handovers(ref):
    """Every handover path that ever existed in the history of `ref`, folded. Full history:
    the default simplification would skip a side branch that added and deleted one."""
    names = git("log", "--full-history", "--format=", "--name-only", "-z", f"{ref}^{{commit}}", "--", HANDOVER_DIR)
    return frozenset(_folded(name) for name in names.split("\0") if name.strip())


def handover_escalations(paths, base_entries, head_entries, earlier=frozenset()):
    """Reasons a change departs from written-once handovers. Each one escalates; none
    fails on its own. A handover on the base keeps its bytes and mode (compared by
    object id, so a CRLF-only rewrite counts). A change that removes one adds none,
    so nothing replaces it under a new name. A removed handover's path is not used
    again. A change that adds a handover touches nothing else. Removing a handover is
    the redaction path."""
    out = []
    base = {p: e for p, e in base_entries.items() if p.startswith(HANDOVER_DIR)}
    head = {p: e for p, e in head_entries.items() if p.startswith(HANDOVER_DIR)}
    for path, entry in sorted(base.items()):
        if path in head and head[path] != entry:
            out.append(f"handover {path} was changed: handovers are written once")
    removed = sorted(p for p in base if p not in head)
    added = sorted(p for p in head if p not in base)
    added_by_oid = {head[p][1]: p for p in added}
    for path in removed:
        out.append(f"handover {path} was removed")
        if base[path][1] in added_by_oid:
            out.append(f"handover {path} was renamed to {added_by_oid[base[path][1]]}: handovers are written once")
    if removed and added:
        out.append(f"this change removes {', '.join(removed)} and adds {', '.join(added)}: "
                   "a handover is not replaced")
    for path in added:
        if _folded(path) in earlier or path.casefold() in earlier:
            out.append(f"handover {path} existed before: a removed handover is not written again")
    others = sorted(p for p in paths if not p.startswith(HANDOVER_DIR))
    if added and others:
        shown = ", ".join(others[:5]) + (", ..." if len(others) > 5 else "")
        out.append(f"a change that adds a handover also touches other paths: {shown}")
    return out


def _unique_object(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate key {sorted(k for k in keys if keys.count(k) > 1)[0]!r}")
    return dict(pairs)


def frontmatter_errors(path, text):
    """A shared skill or agent prompt: frontmatter keys from PROMPT_KEYS only, written
    plainly, and no command that runs when the prompt loads."""
    out = []
    if "\r" in text:
        # The reader folds CRLF, so a CR here ends no line for us, but YAML reads a
        # lone CR as a line break: `name: a<CR>allowed-tools: x` is two keys to it.
        out.append(f"{path}: contains a carriage return, which YAML reads as a line break")
    lines = text.lstrip("﻿").split("\n")
    if lines and lines[0].rstrip() == "---":
        # YAML lets the whole root mapping be indented, so the root's indent is that
        # of its first key, not column 0. A line at that indent is a root key; a deeper
        # one continues a value (a nested key there belongs to that value).
        root_indent = None
        for number, line in enumerate(lines[1:], 2):
            if line.rstrip() == "---":
                break
            content = line.lstrip(" ")
            if not content.strip() or content.startswith("#"):
                continue
            indent = len(line) - len(content)
            if content[0] == "\t":
                out.append(f"{path}:{number}: frontmatter is indented with a tab")
                continue
            if root_indent is None:
                root_indent = indent
            if indent > root_indent:
                continue
            if indent < root_indent or not FRONTMATTER_KEY.match(content):
                out.append(f"{path}:{number}: frontmatter line is not a plain `key: value`")
                continue
            key = content.split(":", 1)[0]
            if key not in PROMPT_KEYS:
                out.append(f"{path}:{number}: frontmatter key {key!r} is not allowed yet; each key is added "
                           "to PROMPT_KEYS by its own reviewed change")
        else:
            out.append(f"{path}: frontmatter is not closed with ---")
    if SHELL_INJECTION.search(text):
        out.append(f"{path}: runs a shell command when it loads (`!` before a backquote or a fence), "
                   "which no shared prompt may do yet")
    return out


def settings_errors(text):
    if text is None:
        return [f"{CLAUDE_SETTINGS}: cannot be read"]
    if len(text.encode("utf-8")) > SETTINGS_MAX_BYTES:
        return [f"{CLAUDE_SETTINGS}: is larger than {SETTINGS_MAX_BYTES} bytes"]
    try:
        # parse_constant: Python accepts NaN and Infinity, JavaScript's JSON.parse does
        # not, and a file Claude Code cannot parse would silently carry no rules.
        settings = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_no_constant)
    except (ValueError, RecursionError) as error:
        return [f"{CLAUDE_SETTINGS}: is not a JSON object ({type(error).__name__}: {error})"]
    if not isinstance(settings, dict):
        return [f"{CLAUDE_SETTINGS}: is not a JSON object"]
    out = [f"{CLAUDE_SETTINGS}: key {key!r} is not allowed yet; each settings key is added "
           "to SETTINGS_KEYS by its own reviewed change" for key in sorted(set(settings) - set(SETTINGS_KEYS))]
    if "permissions" in settings:
        out.extend(permission_errors(settings["permissions"]))
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def permission_errors(value):
    """A shared `permissions` object restricts and nothing else (#173)."""
    where = f"{CLAUDE_SETTINGS}: 'permissions'"
    if type(value) is not dict:
        return [f"{where} is not an object"]
    if not value:
        return [f"{where} is empty; it holds at least one of {', '.join(PERMISSION_KEYS)}"]
    out = [f"{where}: key {key!r} is not allowed; a shared permissions object holds only "
           f"{', '.join(PERMISSION_KEYS)}, which restrict" for key in sorted(set(value) - set(PERMISSION_KEYS))]
    if "disableBypassPermissionsMode" in value and value["disableBypassPermissionsMode"] != "disable":
        out.append(f"{where}: 'disableBypassPermissionsMode' must be exactly \"disable\"")
    for name in PERMISSION_RULE_LISTS:
        if name not in value:
            continue
        rules = value[name]
        if type(rules) is not list:
            out.append(f"{where}: {name!r} is not a list")
            continue
        if not rules:
            out.append(f"{where}: {name!r} is empty; leave it out instead")
            continue
        if len(rules) > PERMISSION_RULES_MAX:
            out.append(f"{where}: {name!r} has {len(rules)} rules, more than {PERMISSION_RULES_MAX}")
        seen = set()
        for index, rule in enumerate(rules):
            label = f"{where}: {name}[{index}]"
            if type(rule) is not str:
                out.append(f"{label} is not a string")
            elif not rule or len(rule) > PERMISSION_RULE_MAX_CHARS:
                out.append(f"{label} is empty or longer than {PERMISSION_RULE_MAX_CHARS} characters")
            elif not (rule.isascii() and rule.isprintable()):
                out.append(f"{label} is not printable ASCII")
            elif rule in seen:
                out.append(f"{label} repeats {rule!r}")
            else:
                seen.add(rule)
    return out


def claude_path_errors(entries, get):
    """The tracked root .claude/ holds only allow-listed regular files, under exact
    names that no case-insensitive checkout folds together. Inside it: no agent
    configuration names, flat dated handovers, plain skill and agent frontmatter, and
    a settings.json that uses only SETTINGS_KEYS."""
    out, seen = [], {}
    for path, (mode, _) in sorted(entries.items()):
        top = path.split("/", 1)[0]
        if _folded(top) != CLAUDE_DIR:
            continue
        folded = "/".join(_folded(part) for part in path.split("/"))
        if folded in seen:
            out.append(f"{path}: is the same file as {seen[folded]} on a case-insensitive checkout")
            continue
        seen[folded] = path
        if top != CLAUDE_DIR:
            out.append(f"{path}: {top!r} opens as {CLAUDE_DIR!r} on a case-insensitive checkout; "
                       f"only the exact name {CLAUDE_DIR!r} is allowed")
            continue
        if not path.isascii() or any(_folded(part) != part.casefold() or not _windows_safe(part)
                                     for part in path.split("/")):
            out.append(f"{path}: names under {CLAUDE_DIR}/ must be plain ASCII that every checkout "
                       "opens as written (no trailing dot or space, no Windows device name such as NUL, "
                       'none of <>:"|?*\\ or control characters)')
            continue
        if path == CLAUDE_DIR:
            out.append(f"{path}: is a {MODE_NAMES.get(mode, 'file')}, not a directory")
            continue
        rest = path[len(CLAUDE_DIR) + 1:]
        if not any(rest == a or (a.endswith("/") and rest.startswith(a)) for a in CLAUDE_ALLOWED):
            out.append(f"{path}: is not on the shared {CLAUDE_DIR}/ allow-list ({', '.join(CLAUDE_ALLOWED)})")
            continue
        if mode not in REGULAR_MODES:
            out.append(f"{path}: is a {MODE_NAMES.get(mode, 'mode ' + mode)}; only regular files are allowed "
                       f"under {CLAUDE_DIR}/")
            continue
        named = [part for part in rest.split("/") if _folded(part) in AGENT_CONFIG_NAMES]
        if named:
            out.append(f"{path}: agent tools read {named[0]!r} as configuration or instructions; "
                       f"not allowed inside {CLAUDE_DIR}/")
            continue
        if path.startswith(HANDOVER_DIR) and not HANDOVER_NAME.fullmatch(path[len(HANDOVER_DIR):]):
            out.append(f"{path}: a handover is {HANDOVER_DIR}HANDOVER-YYYY-MM-DD-HHMM.md, directly in the directory")
            continue
        if path.startswith(PROMPT_DIRS) and path.casefold().endswith(".md"):
            try:
                text = get(path)
            except ValueError as error:
                out.append(f"{path}: cannot be read ({error})")
                continue
            if text is None:
                out.append(f"{path}: is tracked but cannot be read")
                continue
            out.extend(frontmatter_errors(path, text))
    if CLAUDE_SETTINGS in entries and entries[CLAUDE_SETTINGS][0] in REGULAR_MODES:
        try:
            out.extend(settings_errors(get(CLAUDE_SETTINGS)))
        except ValueError as error:
            out.append(f"{CLAUDE_SETTINGS}: cannot be read ({error})")
    return out


# ---------- classify ----------

def classify(paths, base_get, head_get, lanes, head_links=(), handovers=({}, {}, frozenset())):
    head_claims = head_get("claims.toml") or ""
    doc_cited = set(re.findall(r'"doc:([^#"]+)', head_claims)) | set(re.findall(r'"doc:([^#"]+)', base_get("claims.toml") or ""))
    by_path = {path: lane_of(path, lanes, doc_cited) for path in paths}
    escalations = ratchets(base_get, head_get) + spec_ratchets(paths, base_get, head_get)
    escalations += data_module_ratchets(paths, head_get)
    escalations += [f"spec {path} is a symbolic link" for path in head_links]
    escalations += agent_config_escalations(paths) + handover_escalations(paths, *handovers)
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


# ---------- approval freshness (#149) ----------
#
# GitHub rewrites a review's commit_id to the new head when a push leaves the PR's
# diff unchanged, so commit_id alone cannot say which commit the owner saw. A review
# counts only if it was submitted strictly after the head arrived on the PR, judged on
# server time. Anything that cannot be established voids every review.

GITHUB_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
# Timeline events that move the arrival later with the head unchanged. A force-push is
# also in the push log; its timeline entry is a later server time for the same push.
ARRIVAL_EVENTS = ("reopened", "base_ref_changed", "head_ref_force_pushed")


def github_time(value):
    """A server time in the one form the REST API writes, or None for anything else."""
    if not isinstance(value, str) or not GITHUB_TIME.fullmatch(value):
        return None
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def flat_items(pages):
    """A list endpoint's items, from one page or from `gh --paginate --slurp` pages."""
    return [item for page in pages for item in (page if isinstance(page, list) else [page])]


def head_arrival(activity, pr, timeline, head_sha):
    """(when the head arrived on the PR, None), or (None, why it cannot be known).

    activity: the repository Activity log for the PR's head ref, newest first, as the API
    gives it. Its newest entry must be a push of exactly this head; otherwise the log lags,
    the head has moved, or the branch is gone. The arrival is the latest of that entry's
    time, the PR's creation, and any reopen, base change or force-push on the timeline."""
    def obj(value):
        return value if isinstance(value, dict) else {}
    head, base = obj(pr.get("head")), obj(pr.get("base"))
    if head.get("sha") != head_sha:
        return None, "the pull request's head is not --head-sha"
    head_repo, base_repo = obj(head.get("repo")).get("full_name"), obj(base.get("repo")).get("full_name")
    if not isinstance(head_repo, str) or head_repo != base_repo:
        return None, "the head is not in the base repository, so its push log is not read"
    if not isinstance(head.get("ref"), str) or not head["ref"]:
        return None, "the pull request has no head ref"
    ref = "refs/heads/" + head["ref"]
    pushes = flat_items(activity)
    if not pushes:
        return None, f"the activity log has no push to {ref}"
    times = []
    for entry in pushes:
        if not isinstance(entry, dict) or entry.get("ref") != ref:
            return None, f"the activity log has an entry that is not for {ref}"
        times.append(github_time(entry.get("timestamp")))
    if None in times or any(t > times[0] for t in times):
        return None, "the activity log has an entry without a server time, or is not newest first"
    if pushes[0].get("after") != head_sha:
        return None, f"the newest push to {ref} is not the head: the log lags, the head moved, or the branch is gone"
    candidates = [times[0], github_time(pr.get("created_at"))]
    for event in flat_items(timeline):
        if not isinstance(event, dict):
            return None, "the timeline has an entry that is not an object"
        if event.get("event") in ARRIVAL_EVENTS:
            candidates.append(github_time(event.get("created_at")))
    if None in candidates:
        return None, "the pull request, or a reopen, base change or force-push on its timeline, has no server time"
    return max(candidates), None


def fresh_reviews(reviews, arrived_at):
    """Every review, flattened. A review not submitted strictly after arrived_at, and
    every review when arrived_at is None, gets commit_id None: it can approve no commit.
    It stays in the list, so a stale approval is still the owner's latest decision and
    an earlier fresh one does not count again."""
    out = []
    for review in flat_items(reviews):
        submitted = github_time(review.get("submitted_at"))
        fresh = arrived_at is not None and submitted is not None and submitted > arrived_at
        out.append(dict(review) if fresh else dict(review, commit_id=None))
    return out


def review_freshness(reviews, activity, pr, timeline, head_sha):
    """(the reviews with only fresh ones still naming a commit, why all are void or None).
    The one entry point for the fresh-reviews command and the gate."""
    arrived_at, why = head_arrival(activity, pr, timeline, head_sha)
    return fresh_reviews(reviews, arrived_at), why


def fresh_reviews_inputs(args):
    """The parsed inputs of fresh-reviews, or SystemExit with a 'fresh-reviews: ' reason.
    Only input that cannot have come from the API is refused; anything the API could
    give voids the reviews instead, so a lane A change is never stopped by it."""
    if not COMMIT_SHA.fullmatch(args.head_sha or ""):
        sys.exit(f"fresh-reviews: --head-sha {args.head_sha!r} is not a commit id")
    shapes = {"reviews": list, "activity": list, "pr": dict, "timeline": list}
    data = {}
    for name, shape in shapes.items():
        path = getattr(args, name)
        if not path:
            sys.exit(f"fresh-reviews: --{name} is required")
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            sys.exit(f"fresh-reviews: --{name} {path} is not readable JSON ({type(error).__name__})")
        if not isinstance(value, shape) or (shape is list and not all(
                isinstance(page, dict) or (isinstance(page, list) and all(isinstance(i, dict) for i in page))
                for page in value)):
            sys.exit(f"fresh-reviews: --{name} is not a {'JSON object' if shape is dict else 'list of objects'}")
        data[name] = value
    return data


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
    # Every option is optional here and checked in code, so a missing one is a
    # 'fresh-reviews: ' refusal (exit 1), never an argparse error (#149).
    f = sub.add_parser("fresh-reviews")
    for name in ("head-sha", "reviews", "activity", "pr", "timeline"):
        f.add_argument(f"--{name}")
    args = parser.parse_args(argv)
    if args.command == "fresh-reviews":
        return fresh_reviews_main(args)
    try:
        return run(parser, args)
    except subprocess.CalledProcessError as error:
        # Fail closed, but say why: the workflow shows stderr next to an empty result.
        sys.exit(f"policy: {' '.join(error.cmd[3:])} failed: {(error.stderr or '').strip()}")


def fresh_reviews_main(args):
    data = fresh_reviews_inputs(args)
    kept, why = review_freshness(data["reviews"], data["activity"], data["pr"], data["timeline"], args.head_sha)
    if why:
        # Not a refusal, so not the 'fresh-reviews: ' prefix a refusal ends with.
        print(f"note: fresh-reviews voided every review, because {why}.", file=sys.stderr)
    print(json.dumps(kept, indent=2))
    return 0


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
        handovers = (tree_entries(args.base, HANDOVER_DIR), tree_entries(args.head, HANDOVER_DIR),
                     earlier_handovers(args.base))
        result = classify(paths, base_get, head_get, lanes, spec_links(args.head, paths), handovers)
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
        get = reader(args.ref)
        errors = invariant_errors(get, kernel_sources(args.ref)) + claude_path_errors(tree_entries(args.ref), get)
    else:
        errors = invariant_errors(read, kernel_sources()) + claude_path_errors(index_entries(), read)
    print(json.dumps({"errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

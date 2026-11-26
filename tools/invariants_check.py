#!/usr/bin/env python3
"""Check the rules that must hold on every commit.

The `sabotage` feature is never reachable from the host's default features, the
host's build conditions are a closed list, and the kernel stays pure: no_std, no
unsafe, `core` only, no build-time reads.

Usage: invariants_check.py [ROOT]
"""
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_tokens  # noqa: E402

HOST_MANIFEST = "crates/containment-host/Cargo.toml"
KERNEL_SRC = "crates/containment-kernel/src"


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


HOST_CRATE = "crates/containment-host"
HOST_SRC = f"{HOST_CRATE}/src"
# Build conditions are a closed list in the host (#121). `sabotage_default_errors`
# keeps the defects out of the default build, but only for defects behind a
# `weak.x()` gate on the zero-sized `Weakness`. A new `#[cfg(feature = "sabotage")]`
# block elsewhere is a defect with no `weaknesses!` entry and so no control; a
# `cfg(debug_assertions)` defect is live in every test build; another feature or a
# `cfg_attr(.., path = ..)` swaps code in unseen. This is a tripwire on the
# conditions only: it cannot see a defect written as ungated code.
HOST_CFG_NAMES = {"test", "kani"}  # kani: formal/kani proofs, declared in the workspace check-cfg
HOST_CFG_KEYS = {"target_arch"}
HOST_CFG_OPERATORS = {"any", "all", "not"}
HOST_SABOTAGE_FILES = {f"{HOST_SRC}/controller/weakness.rs", f"{HOST_SRC}/common.rs"}
HOST_CFG_FIX = "add the defect to `weaknesses!` in `controller/weakness.rs`"
HOST_FEATURES = {"default": [], "sabotage": []}


def _cfg_string(text):
    """The value of a plain (`"x"`) or raw (`r"x"`, `r#"x"#`) string with no escapes, else None."""
    raw = re.fullmatch(r'r(#*)"(.*)"\1', text, re.DOTALL)
    if raw:
        return raw.group(2)
    plain = re.fullmatch(r'"([^"\\]*)"', text)
    return plain.group(1) if plain else None


def _close(toks, i):
    """Index of the delimiter closing the one at toks[i], or None."""
    depth = 0
    for j in range(i, len(toks)):
        depth += toks[j].text in "([{" and toks[j].kind == "punct"
        depth -= toks[j].text in ")]}" and toks[j].kind == "punct"
        if depth == 0:
            return j
    return None


def _split_commas(toks):
    """toks split at top-level commas, empty parts (a trailing comma) dropped."""
    parts, current, depth = [], [], 0
    for tok in toks:
        if tok.kind == "punct" and tok.text in "([{":
            depth += 1
        elif tok.kind == "punct" and tok.text in ")]}":
            depth -= 1
        elif tok.kind == "punct" and tok.text == "," and depth == 0:
            parts.append(current)
            current = []
            continue
        current.append(tok)
    return [p for p in parts + [current] if p]


def _test_item_tokens(toks):
    """Indexes of the tokens inside the attributes of an item that also carries `#[test]`.
    Such an item is compiled only under cfg(test), so it cannot carry a defect into a binary."""
    attrs, i = [], 0
    while i < len(toks):
        if toks[i].text == "#" and i + 1 < len(toks) and toks[i + 1].text == "[":
            end = _close(toks, i + 1)
            if end is None:
                break
            attrs.append((i, end))
            i = end + 1
        else:
            i += 1
    inside, stack = set(), []
    for k, (lo, hi) in enumerate(attrs):
        stack.append((lo, hi))
        if k + 1 < len(attrs) and attrs[k + 1][0] == hi + 1:
            continue
        if any([t.text for t in toks[a + 2:b]] == ["test"] for a, b in stack):
            for a, b in stack:
                inside.update(range(a, b + 1))
        stack = []
    return inside


def _predicate_errors(pred, path, test_item):
    """Why the cfg predicate `pred` (a token list) is outside the closed list, if it is."""
    shown = " ".join(t.text for t in pred)
    if len(pred) == 1 and pred[0].kind == "ident" and pred[0].text in HOST_CFG_NAMES:
        return []
    if len(pred) >= 3 and pred[0].kind == "ident" and pred[0].text in HOST_CFG_OPERATORS \
            and pred[1].text == "(" and _close(pred, 1) == len(pred) - 1:
        return [e for part in _split_commas(pred[2:-1]) for e in _predicate_errors(part, path, test_item)]
    if len(pred) == 3 and pred[0].kind == "ident" and pred[1].text == "=" and pred[2].kind == "str":
        key, value = pred[0].text, _cfg_string(pred[2].text)
        if value is None:
            return [f"`{shown}` has a value the check cannot read (escapes or a byte string); write it as a plain string"]
        if key in HOST_CFG_KEYS:
            return []
        if key == "feature" and value == "sabotage":
            if path in HOST_SABOTAGE_FILES or test_item:
                return []
            return [f"`feature = \"sabotage\"` is allowed only in controller/weakness.rs, common.rs "
                    f"and on #[test] items, so a defect here has no control; {HOST_CFG_FIX}"]
        return [f"`{key} = \"{value}\"` is not an allowed build condition; {HOST_CFG_FIX}"]
    return [f"`{shown}` is not an allowed build condition (allowed: test, kani, target_arch = .., "
            f"feature = \"sabotage\" in the registry, and any/all/not of those); {HOST_CFG_FIX}"]


def host_cfg_errors(files):
    """`files` maps each host source path to its text. Every `cfg`, `cfg!` and `cfg_attr`
    predicate must be on the closed list above. Tokens, not text: comments, doc
    comments and strings do not count; raw identifiers and raw strings are normalised;
    every `cfg`/`cfg_attr` token is visited, so nesting inside any/all or cfg_attr cannot hide one."""
    out = []
    for path, text in sorted(files.items()):
        try:
            toks = [t._replace(text=_ident(t.kind, t.text)) for t in rust_tokens.tokenize(text)
                    if t.kind not in ("comment", "doc")]
        except rust_tokens.LexError as error:
            out.append(f"{path}: cannot be read ({error}), so its build conditions cannot be checked")
            continue
        test_items = _test_item_tokens(toks)
        for i, tok in enumerate(toks):
            if tok.kind != "ident" or tok.text not in ("cfg", "cfg_attr"):
                continue
            where = f"{path}:{text.count(chr(10), 0, tok.start) + 1}"
            bang = i + 1 < len(toks) and toks[i + 1].text == "!" and tok.text == "cfg"
            open_at = i + 2 if bang else i + 1
            end = _close(toks, open_at) if open_at < len(toks) and toks[open_at].text == "(" else None
            if end is None:
                out.append(f"{where}: `{tok.text}` is used in a form the check cannot read; {HOST_CFG_FIX}")
                continue
            args = _split_commas(toks[open_at + 1:end])
            if tok.text == "cfg_attr":
                if len(args) < 2:
                    out.append(f"{where}: `cfg_attr` without a predicate and an attribute cannot be read")
                    continue
                for attr in args[1:]:
                    if attr[0].text == "path":
                        out.append(f"{where}: `cfg_attr(.., path = ..)` swaps in other source under a build condition; {HOST_CFG_FIX}")
                args = args[:1]
            if len(args) != 1:
                out.append(f"{where}: `{tok.text}` must hold exactly one predicate")
                continue
            out.extend(f"{where}: {e}" for e in _predicate_errors(args[0], path, i in test_items))
    return out


def host_manifest_errors(manifest_text, has_build_script):
    """The host's features are exactly `default = []` and `sabotage = []`, and it has no build script."""
    data = tomllib.loads(manifest_text)
    out = []
    if data.get("features", {}) != HOST_FEATURES:
        out.append(f"{HOST_MANIFEST}: the features must be exactly `default = []` and `sabotage = []`; {HOST_CFG_FIX}")
    if has_build_script or data.get("package", {}).get("build", False) is not False:
        out.append(f"{HOST_CRATE}: has a build script, which can set build conditions the source check cannot see")
    return out


def errors(root):
    """Every violation under `root`, a checkout or a seeded case's tree."""
    root = Path(root)
    manifest = root / HOST_MANIFEST
    out = sabotage_default_errors(manifest.read_text(encoding="utf-8")) if manifest.exists() else [f"{HOST_MANIFEST}: missing"]
    if manifest.exists():
        out += host_manifest_errors(manifest.read_text(encoding="utf-8"), (root / HOST_CRATE / "build.rs").exists())
    base = root / KERNEL_SRC
    files = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(base.rglob("*.rs"))}
    out += kernel_purity_errors(files)
    host = root / HOST_SRC
    if not host.is_dir():
        return out + [f"{HOST_SRC}: missing, so the host's build conditions cannot be checked"]
    host_files = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(host.rglob("*.rs"))}
    return out + host_cfg_errors(host_files)


def main(argv):
    found = errors(argv[1] if len(argv) > 1 else Path(__file__).resolve().parent.parent)
    for line in found:
        print(f"invariants: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

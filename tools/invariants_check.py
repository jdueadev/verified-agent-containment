#!/usr/bin/env python3
"""Check the two rules that must hold on every commit.

The `sabotage` feature is never reachable from the host's default features, and
the kernel stays pure: no_std, no unsafe, `core` only, no build-time reads.

Usage: invariants_check.py [ROOT]
"""
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


def errors(root):
    """Every violation under `root`, a checkout or a seeded case's tree."""
    root = Path(root)
    manifest = root / HOST_MANIFEST
    out = sabotage_default_errors(manifest.read_text(encoding="utf-8")) if manifest.exists() else [f"{HOST_MANIFEST}: missing"]
    base = root / KERNEL_SRC
    files = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(base.rglob("*.rs"))}
    return out + kernel_purity_errors(files)


def main(argv):
    found = errors(argv[1] if len(argv) > 1 else Path(__file__).resolve().parent.parent)
    for line in found:
        print(f"invariants: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

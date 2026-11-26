#!/usr/bin/env python3
"""RS-UNWRAP: no new `unwrap` or `expect` in the host's non-test code.

A panic in the controller stops it (RS-PANIC makes that a fail-stop), so an
`unwrap` or `expect` on a value an agent can influence lets the agent stop the
controller. Which values an agent can influence is not decidable from the source,
so every non-test site counts.

The sites that exist today are listed in ci/unwrap_debt.toml. Each entry names a
file, the enclosing item (`fn`, `impl`, `mod`, `trait` path), the call and, for
`expect`, its message, with a count. The check fails when:
  - a (file, item, call, message) has more sites than the list allows: a new site;
  - it has fewer: the list is stale. `--update` lowers the counts to what is there
    and drops empty entries. It never adds an entry or raises a count, so a new site
    can only be allowed by editing the list by hand, in review.

Sites are found by tokens (tools/rust_tokens.py), so comments, strings and doc
comments never count and formatting never changes the result. The calls are the
identifiers `unwrap`, `expect`, `unwrap_err` and `expect_err` after `.` or `::`,
whatever the receiver's type. Code under `#[cfg(test)]`, `#[cfg(kani)]` (or an
`all(...)` holding one of them) or `#[test]` is exempt; everything else counts,
the `sabotage` feature and every target_arch included.

Usage: unwrap_check.py [--update] [ROOT]
"""
import json
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_tokens  # noqa: E402

HOST_SRC = "crates/containment-host/src"
DEBT = "ci/unwrap_debt.toml"
CALLS = ("unwrap", "expect", "unwrap_err", "expect_err")
FIX = ("handle the failure instead: return an error with `?`, `ok_or`/`map_err`, or match the "
       "`None`/`Err` case; a call that truly cannot fail still needs a hand-written entry in "
       f"{DEBT}, justified in review")
_OPEN, _CLOSE = "([{", ")]}"
_ITEM_START = {";", "{", "}", "]"}


def _partners(toks):
    partner, stack = {}, []
    for k, tok in enumerate(toks):
        if tok.kind == "punct" and tok.text in _OPEN:
            stack.append(k)
        elif tok.kind == "punct" and tok.text in _CLOSE:
            if not stack or _OPEN.index(toks[stack[-1]].text) != _CLOSE.index(tok.text):
                raise rust_tokens.LexError(f"unbalanced `{tok.text}` at offset {tok.start}")
            partner[stack.pop()] = k
    if stack:
        raise rust_tokens.LexError(f"unclosed `{toks[stack[-1]].text}` at offset {toks[stack[-1]].start}")
    return partner


def _test_only(attr):
    """Whether the attribute tokens (between `[` and `]`) make code test- or proof-only."""
    words = [t.text for t in attr]
    if words == ["test"]:
        return True
    if len(words) < 4 or words[:2] != ["cfg", "("] or words[-1] != ")":
        return False
    inner = words[2:-1]
    if inner in (["test"], ["kani"]):
        return True
    if inner[:2] != ["all", "("] or inner[-1] != ")":
        return False
    # `all(test, x)`: a bare `test` or `kani` among the top-level terms of all(...).
    depth, terms, current = 0, [], []
    for w in inner[2:-1]:
        if w in _OPEN:
            depth += 1
        elif w in _CLOSE:
            depth -= 1
        if depth == 0 and w == ",":
            terms.append(current)
            current = []
        else:
            current.append(w)
    terms.append(current)
    return any(term in (["test"], ["kani"]) for term in terms)


def _item_end(toks, partner, k, stop):
    """Index just past the item or statement starting at k: its first top-level `{...}`
    group, or the first top-level `;` or `,`, or stop (the enclosing closer)."""
    while k < stop:
        tok = toks[k]
        if tok.kind == "punct" and tok.text in _OPEN:
            if tok.text == "{":
                return partner[k] + 1
            k = partner[k] + 1
            continue
        if tok.kind == "punct" and tok.text in (";", ","):
            return k + 1
        k += 1
    return stop


def _impl_label(toks, k):
    """`impl Trait for Type` from the header tokens up to the body, generics dropped."""
    words, depth = ["impl"], 0
    for tok in toks[k + 1:]:
        if tok.text == "{" and depth == 0:
            break
        if tok.text == "<":
            depth += 1
        elif tok.text == ">":
            depth -= 1
        elif tok.text == ">>":
            depth -= 2
        elif depth == 0 and tok.kind == "ident" and tok.text != "where":
            words.append(tok.text)
        elif tok.text == "where":
            break
    return " ".join(words)


def sites(src):
    """[(line, item path, call, message)] for every non-test call site in src.
    Raises LexError when src cannot be read."""
    toks = [t for t in rust_tokens.tokenize(src) if t.kind not in ("comment", "doc")]
    partner = _partners(toks)
    exempt = [False] * len(toks)
    labels = {}  # index of a `{` -> item label

    def mark(lo, hi):
        for i in range(lo, hi):
            exempt[i] = True

    # File-level inner attribute `#![cfg(test)]` exempts the whole file.
    stack_close = [len(toks)]
    pending = None
    for k, tok in enumerate(toks):
        while k >= stack_close[-1]:
            stack_close.pop()
        if tok.kind == "punct" and tok.text == "{" :
            if pending is not None:
                labels[k] = pending
                pending = None
            stack_close.append(partner[k])
            continue
        if tok.kind == "punct" and tok.text == ";":
            pending = None
            continue
        if tok.text == "#" and k + 1 < len(toks):
            inner = toks[k + 1].text == "!"
            j = k + 2 if inner else k + 1
            if j < len(toks) and toks[j].text == "[" and j in partner:
                if _test_only(toks[j + 1:partner[j]]):
                    if inner:
                        mark(k, stack_close[-1])
                    else:
                        mark(k, _item_end(toks, partner, partner[j] + 1, stack_close[-1]))
            continue
        if tok.kind != "ident" or k + 1 >= len(toks):
            continue
        prev = toks[k - 1] if k else None
        if tok.text in ("fn", "mod", "trait") and toks[k + 1].kind == "ident":
            pending = f"{tok.text} {toks[k + 1].text}"
        elif tok.text == "impl" and (prev is None or prev.text in _ITEM_START
                                     or prev.text in ("unsafe", "default")):
            pending = _impl_label(toks, k)

    out, path_stack = [], []
    for k, tok in enumerate(toks):
        while path_stack and k > path_stack[-1][0]:
            path_stack.pop()
        if k in labels:
            path_stack.append((partner[k], labels[k]))
        if tok.kind != "ident" or tok.text not in CALLS or exempt[k]:
            continue
        before = toks[k - 1].text if k > 0 and toks[k - 1].kind == "punct" else None
        after = toks[k + 1].text if k + 1 < len(toks) else None
        # `.unwrap()` or `.unwrap::<T>()` is a call; `task.expect` is a field.
        # `Option::unwrap` is a path, called or passed as a function.
        if not ((before == "." and after in ("(", "::")) or before == "::"):
            continue
        message = ""
        if tok.text.startswith("expect") and k + 3 < len(toks) and toks[k + 1].text == "(" \
                and toks[k + 2].kind == "str" and (toks[k + 3].text == ")" or (
                    toks[k + 3].text == "," and k + 4 < len(toks) and toks[k + 4].text == ")")):
            message = rust_tokens.string_value(toks[k + 2]) or toks[k + 2].text
        item = "::".join(label for _, label in path_stack) or "<top>"
        out.append((src.count("\n", 0, tok.start) + 1, item, tok.text, message))
    return out


def scan(root):
    """{(file, item, call, message): [lines]} over the host source."""
    found = {}
    base = Path(root)
    for path in sorted((base / HOST_SRC).rglob("*.rs")):
        rel = path.relative_to(base).as_posix()
        for line, item, call, message in sites(path.read_text(encoding="utf-8")):
            found.setdefault((rel, item, call, message), []).append(line)
    return found


def load_debt(root):
    path = Path(root) / DEBT
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    debt = {}
    for entry in data.get("site", []):
        key = (entry["file"], entry["item"], entry["call"], entry.get("message", ""))
        if key in debt:
            raise ValueError(f"{DEBT}: duplicate entry {key}")
        if not isinstance(entry.get("count"), int) or entry["count"] < 1:
            raise ValueError(f"{DEBT}: entry {key} needs a positive count")
        debt[key] = entry["count"]
    return debt


def render_debt(debt):
    lines = [
        "# RS-UNWRAP debt: the `unwrap`/`expect` sites in containment-host's non-test code",
        "# that predate the rule. tools/unwrap_check.py fails on any site not listed here and",
        "# on any entry whose count is higher than the source. This list may only shrink:",
        "# `uv run tools/unwrap_check.py --update` lowers counts and never raises them.",
        "",
    ]
    for (file, item, call, message), count in sorted(debt.items()):
        lines += ["[[site]]", f"file = {json.dumps(file)}", f"item = {json.dumps(item)}",
                  f"call = {json.dumps(call)}"]
        if message:
            lines.append(f"message = {json.dumps(message)}")
        lines += [f"count = {count}", ""]
    return "\n".join(lines)


def errors(found, debt):
    out = []
    for key in sorted(set(found) | set(debt)):
        have, allowed = len(found.get(key, [])), debt.get(key, 0)
        file, item, call, message = key
        where = f"{file}: {item}: `{call}`" + (f"({message})" if message else "")
        if have > allowed:
            lines = ", ".join(str(n) for n in found[key])
            out.append(f"RS-UNWRAP: new `{call}` in {where} at line {lines} "
                       f"({have} found, {allowed} allowed); {FIX}")
        elif have < allowed:
            out.append(f"RS-UNWRAP: {DEBT} is stale for {where}: {allowed} listed, {have} found; "
                       f"shrink it with `uv run tools/unwrap_check.py --update`")
    return out


def main(argv):
    args = argv[1:]
    update = "--update" in args
    args = [a for a in args if a != "--update"]
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    try:
        found, debt = scan(root), load_debt(root)
    except (rust_tokens.LexError, ValueError, KeyError) as error:
        print(f"RS-UNWRAP: cannot read the source or {DEBT}: {error}", file=sys.stderr)
        return 1
    if update:
        grown = [e for e in errors(found, debt) if "new `" in e]
        if grown:
            print("\n".join(grown), file=sys.stderr)
            print("RS-UNWRAP: --update never allows a new site; nothing written", file=sys.stderr)
            return 1
        shrunk = {k: min(c, len(found.get(k, []))) for k, c in debt.items()}
        text = render_debt({k: c for k, c in shrunk.items() if c})
        (root / DEBT).write_text(text, encoding="utf-8", newline="\n")
        print(f"RS-UNWRAP: {DEBT} updated")
        return 0
    problems = errors(found, debt)
    for line in problems:
        print(line, file=sys.stderr)
    if not problems:
        print(f"RS-UNWRAP: {sum(debt.values())} listed sites, no new ones")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

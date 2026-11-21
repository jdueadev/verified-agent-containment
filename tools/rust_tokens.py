#!/usr/bin/env python3
"""A small Rust lexer for the checkers, so that what they read never depends on layout.

Checks that read Rust source (the suite inventories, the policy ratchets, and later
the mutant matcher and the staleness fingerprint) go through this one lexer instead
of regexes over text. Formatting changes whitespace, line breaks and trailing commas;
it never changes the sequence of code tokens, so anything computed from that
sequence survives `cargo fmt`.

Token kinds:
  ident     identifiers and keywords, including raw identifiers (`r#type`)
  lifetime  `'a`, `'static`, loop labels
  char      char and byte literals (`'x'`, `'\\u{41}'`, `b'x'`)
  str       string literals of every form (plain, byte, C, raw with any `#` count)
  number    integer and float literals with their suffixes
  punct     operators and delimiters, longest match first
  doc       doc comments (`///`, `//!`, `/** */`, `/*! */`): they become `#[doc]`
            attributes and doctests run them, so they count as code
  comment   every other comment

Anything this lexer cannot read raises LexError. A checker must treat that as a
failure, never as an empty or partial result.

Standard library only. It never imports or runs the code it reads, so policy_check.py
can use it on an untrusted head. It is part of the trusted base (lane C).
"""
import re
from typing import NamedTuple


class LexError(ValueError):
    """The source could not be read completely."""


class Token(NamedTuple):
    kind: str
    text: str
    start: int
    end: int


_PUNCT = sorted("""
<<= >>= ... ..= :: -> => == != <= >= && || += -= *= /= %= ^= &= |= << >> .. <-
""".split(), key=len, reverse=True)
_RAW_STR = re.compile(r'(?:b|c)?r(#*)"')
_CHAR_ESCAPE = re.compile(r"\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|[^\n])'")


def _ident_start(ch):
    return ch == "_" or ch.isalpha()


def _ident_char(ch):
    return ch == "_" or ch.isalnum()


def _scan_ident(src, i):
    j = i
    while j < len(src) and _ident_char(src[j]):
        j += 1
    return j


def _scan_quoted(src, i, quote):
    """i is just after the opening quote; return the index after the closing one."""
    j = i
    while j < len(src):
        if src[j] == "\\":
            j += 2
        elif src[j] == quote:
            return j + 1
        else:
            j += 1
    raise LexError(f"unterminated literal at offset {i - 1}")


def _scan_char(src, i):
    """i is at the opening apostrophe of a char literal; return the index after it, or
    None when the apostrophe starts a lifetime or label instead."""
    if src.startswith("\\", i + 1):
        escape = _CHAR_ESCAPE.match(src, i + 1)
        if not escape:
            raise LexError(f"malformed char literal at offset {i}")
        return escape.end()
    if i + 2 < len(src) and src[i + 2] == "'" and src[i + 1] not in "'\n":
        return i + 3
    return None


def _scan_block_comment(src, i):
    depth, j = 1, i + 2
    while depth:
        if j >= len(src):
            raise LexError(f"unterminated block comment at offset {i}")
        if src.startswith("/*", j):
            depth, j = depth + 1, j + 2
        elif src.startswith("*/", j):
            depth, j = depth - 1, j + 2
        else:
            j += 1
    return j


def _scan_number(src, i):
    j = _scan_ident(src, i)  # digits, `_`, radix prefix, exponent letter, suffix
    hexadecimal = src.startswith(("0x", "0X"), i)
    if j < len(src) and src[j] == "." and j + 1 < len(src) and src[j + 1].isdigit():
        j = _scan_ident(src, j + 1)
    if (not hexadecimal and src[j - 1] in "eE" and j + 1 < len(src)
            and src[j] in "+-" and src[j + 1].isdigit()):
        j = _scan_ident(src, j + 1)
    return j


def tokenize(src):
    """Every token in src, comments included, in order. Whitespace is dropped."""
    out, i, n = [], 0, len(src)
    while i < n:
        ch = src[i]
        if ch.isspace():
            i += 1
            continue
        start = i
        if src.startswith("//", i):
            end = src.find("\n", i)
            i = n if end < 0 else end
            text = src[start:i]
            doc = (text.startswith("///") and not text.startswith("////")) or text.startswith("//!")
            out.append(Token("doc" if doc else "comment", text, start, i))
            continue
        if src.startswith("/*", i):
            i = _scan_block_comment(src, i)
            text = src[start:i]
            doc = (text.startswith("/**") and not text.startswith("/***") and text != "/**/") \
                or text.startswith("/*!")
            out.append(Token("doc" if doc else "comment", text, start, i))
            continue
        raw = _RAW_STR.match(src, i)
        if raw:
            close = '"' + raw.group(1)
            end = src.find(close, raw.end())
            if end < 0:
                raise LexError(f"unterminated raw string at offset {start}")
            i = _scan_ident(src, end + len(close))  # optional suffix
            out.append(Token("str", src[start:i], start, i))
            continue
        if ch == '"' or (ch in "bc" and src.startswith('"', i + 1)):
            i = _scan_quoted(src, i + (1 if ch == '"' else 2), '"')
            i = _scan_ident(src, i)
            out.append(Token("str", src[start:i], start, i))
            continue
        if ch == "b" and src.startswith("'", i + 1):
            end = _scan_char(src, i + 1)
            if end is None:
                raise LexError(f"malformed byte literal at offset {start}")
            i = end
            out.append(Token("char", src[start:i], start, i))
            continue
        if ch == "'":
            end = _scan_char(src, i)
            if end is not None:
                i = end
                out.append(Token("char", src[start:i], start, i))
                continue
            k = i + 1 + (2 if src.startswith("r#", i + 1) else 0)
            if k < n and _ident_start(src[k]):
                i = _scan_ident(src, k)
                out.append(Token("lifetime", src[start:i], start, i))
                continue
            raise LexError(f"stray apostrophe at offset {start}")
        if src.startswith("r#", i) and i + 2 < n and _ident_start(src[i + 2]):
            i = _scan_ident(src, i + 2)
            out.append(Token("ident", src[start:i], start, i))
            continue
        if _ident_start(ch):
            i = _scan_ident(src, i)
            out.append(Token("ident", src[start:i], start, i))
            continue
        if ch.isdigit():
            i = _scan_number(src, i)
            out.append(Token("number", src[start:i], start, i))
            continue
        for op in _PUNCT:
            if src.startswith(op, i):
                i += len(op)
                break
        else:
            i += 1
        out.append(Token("punct", src[start:i], start, i))
    return out


_KEYWORDS = frozenset("""
as async await box break const continue crate dyn else enum extern false fn for if impl in let loop
match mod move mut pub ref return self Self static struct super trait true type unsafe use where while yield
""".split())


def drop_layout_commas(tokens):
    """tokens without the trailing commas rustfmt adds or removes when it splits a group.

    A comma before a closing delimiter is dropped only where it carries no meaning:
    before `]` or `}`, before `)` of a group that already has another element, and
    before `)` of a call-like group (one opened right after a non-keyword identifier,
    `)` or `]`). The comma of a one-element tuple, `(x,)`, is kept: `(x)` is a
    different expression. `>` does not make a group call-like, because in `a > (b,)`
    it is a comparison; a turbofish call `f::<T>(x,)` therefore keeps its comma. Nothing inside a macro invocation (`name!(...)`, `[...]` or
    `{...}`) is dropped, because a macro matcher can tell the two apart; if rustfmt
    adds such a comma, that counts as a change, which errs towards staleness."""
    out, groups = [], []
    for tok in tokens:
        if tok.kind == "punct" and tok.text in _OPEN:
            before = out[-1] if out else None
            call_like = before is not None and (
                (before.kind == "ident" and before.text not in _KEYWORDS)
                or (before.kind == "punct" and before.text in (")", "]")))
            # Inside a macro invocation every token is significant: a matcher can tell
            # `m!(x,)` from `m!(x)`. The whole token tree is kept as written.
            in_macro = bool(groups and groups[-1]["in_macro"]) or (
                before is not None and before.kind == "punct" and before.text == "!")
            groups.append({"commas": 0, "call_like": call_like, "in_macro": in_macro})
        elif tok.kind == "punct" and tok.text in _CLOSE and groups:
            group = groups.pop()
            if not group["in_macro"] and out and out[-1].kind == "punct" and out[-1].text == "," and (
                    tok.text in "]}" or group["call_like"] or group["commas"] >= 2):
                out.pop()
        elif tok.kind == "punct" and tok.text == "," and groups:
            groups[-1]["commas"] += 1
        out.append(tok)
    return out


def code_tokens(src):
    """(kind, text) of every token except plain comments, with layout-only trailing
    commas dropped. Whitespace, line breaks, plain comments and trailing commas cannot
    change it. rustfmt rewrites more than that (it wraps split match arms in braces,
    adds semicolons, reorders `use` items), so on whole files this is not
    format-invariant by itself; see #61, step 4."""
    return [(t.kind, t.text) for t in drop_layout_commas([t for t in tokenize(src) if t.kind != "comment"])]


def string_value(token):
    """The value of a plain string literal with no escapes, or None for any other token."""
    if token.kind != "str" or not token.text.startswith('"') or not token.text.endswith('"'):
        return None
    inner = token.text[1:-1]
    return None if "\\" in inner else inner


_OPEN, _CLOSE = "([{", ")]}"


def const_array_entries(src, name):
    """The top-level entries of `const <name>: ... = &[ ... ];`, each a list of tokens
    (comments dropped). Raises LexError when the declaration is missing or repeated,
    is not `= &[`, or is not closed. An empty array gives an empty list."""
    toks = [t for t in tokenize(src) if t.kind not in ("comment", "doc")]
    decls = [k for k in range(len(toks) - 2)
             if toks[k].kind == "ident" and toks[k].text == "const"
             and toks[k + 1].kind == "ident" and toks[k + 1].text == name
             and toks[k + 2].text == ":"]
    if len(decls) != 1:
        raise LexError(f"expected one `const {name}:` declaration, found {len(decls)}")
    k = decls[0] + 3
    while k < len(toks) and toks[k].text not in ("=", ";"):
        k += 1
    if k + 2 >= len(toks) or toks[k].text != "=" or toks[k + 1].text != "&" or toks[k + 2].text != "[":
        raise LexError(f"`const {name}` is not `= &[ ... ]`")
    entries, current, depth = [], [], 0
    for tok in toks[k + 3:]:
        if tok.kind == "punct" and tok.text in _OPEN:
            depth += 1
        elif tok.kind == "punct" and tok.text in _CLOSE:
            if depth == 0:
                if tok.text != "]":
                    raise LexError(f"`const {name}` has an unbalanced `{tok.text}`")
                if current:
                    entries.append(current)
                return entries
            depth -= 1
        elif tok.kind == "punct" and tok.text == "," and depth == 0:
            if current:
                entries.append(current)
            current = []
            continue
        current.append(tok)
    raise LexError(f"`const {name}` is not closed")


def entry_key(entry):
    """A layout-free identity for one array entry: its tokens, without the trailing
    commas rustfmt adds when it splits a tuple."""
    return tuple((t.kind, t.text) for t in drop_layout_commas(entry))


def macro_idents(src, name):
    """The comma-separated identifiers in the one invocation `<name>! { a, b, ... }`."""
    toks = [t for t in tokenize(src) if t.kind not in ("comment", "doc")]
    calls = [k for k in range(len(toks) - 2)
             if toks[k].kind == "ident" and toks[k].text == name
             and toks[k + 1].text == "!" and toks[k + 2].text == "{"
             and not (k > 0 and toks[k - 1].text == "!")]
    if len(calls) != 1:
        raise LexError(f"expected one `{name}! {{ ... }}` invocation, found {len(calls)}")
    out, k = [], calls[0] + 3
    while k < len(toks) and toks[k].text != "}":
        if toks[k].kind != "ident" or toks[k + 1].text not in (",", "}"):
            raise LexError(f"`{name}!` holds something other than a list of identifiers near offset {toks[k].start}")
        out.append(toks[k].text)
        k += 2 if toks[k + 1].text == "," else 1
    if k >= len(toks):
        raise LexError(f"`{name}!` is not closed")
    return out

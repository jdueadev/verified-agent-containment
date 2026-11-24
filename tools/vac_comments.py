import ast
import bisect
import importlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import tokenize
import tomllib
from pathlib import Path, PurePosixPath
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
rust_tokens = importlib.import_module("rust_tokens")
policy_check = importlib.import_module("policy_check")
vac_core = importlib.import_module("vac_core")

DEBT_FILE = "ci/comment_debt.toml"
MAIN = "origin/main"
DATA = ("results/**", "redteam/**", "examples/**", "ci/corpus/**", ".claude/handover/**", "**/fixtures/**",
        "target/**", "Cargo.lock", "docs/claims.md", ".github/CODEOWNERS")
FROZEN_SPEC_KINDS = ("docstring", "doc")
SHELL_SHEBANG = re.compile(r"#![ \t]*\S*/(?:env[ \t]+)?(?:ba)?sh(?=\s|$)")
OFFSET = re.compile(r"offset (\d+)")
TOML_LINE = re.compile(r"line (\d+)")
SHELL_CASE = re.compile(r"(?:case|esac)(?![\w-])")
JS_WORD = re.compile(r"[\w$#\\]+")
JS_FLAGS = re.compile(r"[A-Za-z]*")
REGEX_AFTER = frozenset(("return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                         "else", "yield", "await"))
SMART_QUOTES = "‘’‚‛“”„"
YAML_BLOCK = re.compile(r"[|>][-+]?(?=[ \t]|$)")
ENV_ASSIGN = re.compile(r"[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=")
ENV_VALUE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'[^'\n]*'|[^\s'\"][^\s'\"]*|")
BATCH_REM = re.compile(r"rem(?=[\s.:,;=/\\(+\[\]]|$)", re.I)
TOML_ESCAPES = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
UNREADABLE = "unreadable"


class Span(NamedTuple):
    path: str
    line: int
    kind: str
    text: str


class Unreadable(Exception):
    def __init__(self, line, reason):
        super().__init__(reason)
        self.line = line
        self.reason = reason


def glob_regex(pattern):
    parts = {"**/": "(?:.*/)?", "/**": "/.*", "*": "[^/]*"}
    return re.compile("".join(parts.get(p, re.escape(p)) for p in re.split(r"(\*\*/|/\*\*|\*)", pattern) if p))


DATA_PATTERNS = tuple(glob_regex(p) for p in DATA)


def is_data(path):
    return any(p.fullmatch(path) for p in DATA_PATTERNS)


class Scanner:
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.found = []
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, at):
        return bisect.bisect_right(self.starts, at)

    def fail(self, reason, at=None):
        raise Unreadable(self.line(self.i if at is None else at), reason)

    def eol(self, at):
        end = self.s.find("\n", at)
        return len(self.s) if end < 0 else end

    def take(self, end):
        self.found.append((self.line(self.i), "comment", self.s[self.i:end]))
        self.i = end

    def skip_quoted(self, quote, escape="\\", doubled=False, newline=True):
        j = self.i + 1
        while j < len(self.s):
            ch = self.s[j]
            if escape and ch == escape:
                j += 2
            elif ch == quote and doubled and self.s.startswith(quote, j + 1):
                j += 2
            elif ch == quote:
                self.i = j + 1
                return
            elif ch == "\n" and not newline:
                self.fail("a string runs past the end of its line")
            else:
                j += 1
        self.fail("a string is never closed")


def python_lexer(text):
    try:
        tree = policy_check.python_ast(text)
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (ValueError, SyntaxError, tokenize.TokenError) as error:
        line = getattr(error, "lineno", None) or getattr(error.__cause__, "lineno", None) or 1
        raise Unreadable(line, f"is not Python this lexer can read ({error})") from error
    lines = text.split("\n")
    found = [(t.start[0], "comment", t.string) for t in tokens if t.type == tokenize.COMMENT]
    owners = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    docs = {id(node.body[0]) for node in ast.walk(tree)
            if isinstance(node, owners) and node.body and is_docstring(node.body[0])}
    found += [(node.lineno, "docstring" if id(node) in docs else "string", lines[node.lineno - 1].strip())
              for node in ast.walk(tree) if bare_string(node)]
    return found


def bare_string(node):
    value = getattr(node, "value", None)
    return isinstance(node, ast.Expr) and (isinstance(value, ast.JoinedStr) or (
        isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes))))


def is_docstring(node):
    return bare_string(node) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


def rust_lexer(text):
    try:
        tokens = rust_tokens.tokenize(text)
    except rust_tokens.LexError as error:
        found = OFFSET.search(str(error))
        raise Unreadable(text.count("\n", 0, int(found.group(1))) + 1 if found else 1,
                         f"cannot be lexed ({error})") from error
    scanner = Scanner(text)
    return [(scanner.line(t.start), t.kind, t.text) for t in tokens if t.kind in ("comment", "doc")]


def toml_lexer(text):
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        found = TOML_LINE.search(str(error))
        raise Unreadable(int(found.group(1)) if found else 1, f"is not TOML ({error})") from error
    sc, s = Scanner(text), text
    while sc.i < len(s):
        if s.startswith(('"""', "'''"), sc.i):
            quote, j = s[sc.i], sc.i + 3
            while not s.startswith(quote * 3, j):
                if j >= len(s):
                    sc.fail("a multi-line string is never closed")
                j += 2 if quote == '"' and s[j] == "\\" else 1
            end = j + 3
            while end < len(s) and s[end] == quote and end - j < 5:
                end += 1
            sc.i = end
        elif s[sc.i] == '"':
            sc.skip_quoted('"', newline=False)
        elif s[sc.i] == "'":
            sc.skip_quoted("'", escape=None, newline=False)
        elif s[sc.i] == "#":
            sc.take(sc.eol(sc.i))
        else:
            sc.i += 1
    return sc.found


def bend_lexer(text):
    sc, s = Scanner(text), text
    while sc.i < len(s):
        if s.startswith("#{", sc.i):
            end = s.find("#}", sc.i + 2)
            if end < 0:
                sc.fail("a #{ comment is never closed")
            sc.take(end + 2)
        elif s[sc.i] == "#":
            sc.take(sc.eol(sc.i))
        elif s[sc.i] in "\"'":
            sc.skip_quoted(s[sc.i], newline=False)
        else:
            sc.i += 1
    return sc.found


class Shell(Scanner):
    WORD_BREAK = " \t\n;&|()"

    def run(self):
        self.pending = []
        self.code(None)
        if self.pending:
            self.fail("a heredoc is never closed")
        return self.found

    def code(self, close):
        s, depth, at_word = self.s, 0, True
        while self.i < len(s):
            ch = s[self.i]
            if ch == "\n":
                self.i += 1
                self.bodies()
                at_word = True
            elif ch == "\\":
                at_word = at_word and s.startswith("\\\n", self.i)
                self.i += 2
            elif ch == "'":
                self.skip_quoted("'", escape=None)
                at_word = False
            elif ch == '"':
                self.dquote()
                at_word = False
            elif ch == "$":
                self.dollar(False)
                at_word = False
            elif ch == "`":
                self.i += 1
                if close == "`":
                    return
                self.code("`")
                at_word = False
            elif ch == "#" and at_word:
                if close == "`":
                    self.fail("a comment inside backticks")
                self.take(self.eol(self.i))
            elif at_word and s.startswith("((", self.i):
                self.i += 2
                self.arith()
                at_word = False
            elif s.startswith("<<", self.i):
                self.heredoc()
                at_word = False
            elif ch == "(":
                depth += 1
                self.i += 1
                at_word = True
            elif ch == ")":
                self.i += 1
                if close == ")" and not depth:
                    return
                depth -= bool(depth)
                at_word = True
            elif close == ")" and at_word and SHELL_CASE.match(s, self.i):
                self.fail("a case statement inside $( ), whose ) this lexer cannot tell apart")
            else:
                at_word = ch in self.WORD_BREAK
                self.i += 1
        if close:
            self.fail(f"a {'$(' if close == ')' else '`'} is never closed")

    def dollar(self, quoted):
        s, nxt = self.s, self.s[self.i + 1:self.i + 2]
        if s.startswith("$((", self.i):
            self.i += 3
            self.arith()
        elif nxt == "(":
            self.i += 2
            self.code(")")
        elif nxt == "{":
            self.i += 2
            self.param(quoted)
        elif nxt == "'" and not quoted:
            self.i += 1
            self.skip_quoted("'")
        elif nxt == '"' and not quoted:
            self.i += 1
            self.dquote()
        elif nxt and nxt in "#?$!@*-":
            self.i += 2
        else:
            self.i += 1

    def dquote(self):
        s, opened = self.s, self.i
        self.i += 1
        while self.i < len(s):
            ch = s[self.i]
            if ch == '"':
                self.i += 1
                return
            if ch == "\\":
                self.i += 2
            elif ch == "$":
                self.dollar(True)
            elif ch == "`":
                self.i += 1
                self.code("`")
            elif ch == "\n" and self.pending:
                self.fail("a heredoc starts inside a string")
            else:
                self.i += 1
        self.fail("a string is never closed", opened)

    def param(self, quoted):
        s, opened = self.s, self.i
        while self.i < len(s):
            ch = s[self.i]
            if ch == "}":
                self.i += 1
                return
            if ch == "\\":
                self.i += 2
            elif ch == "'" and not quoted:
                self.skip_quoted("'", escape=None)
            elif ch == '"':
                self.dquote()
            elif ch == "$":
                self.dollar(quoted)
            elif ch == "`":
                self.i += 1
                self.code("`")
            else:
                self.i += 1
        self.fail("a ${ is never closed", opened)

    def arith(self):
        s, opened, depth = self.s, self.i, 0
        while self.i < len(s):
            ch = s[self.i]
            if ch == ")" and not depth:
                if s.startswith("))", self.i):
                    self.i += 2
                    return
                break
            if ch == "$":
                self.dollar(True)
            elif ch == "`":
                self.i += 1
                self.code("`")
            elif ch == '"':
                self.dquote()
            elif ch == "'":
                self.skip_quoted("'", escape=None)
            else:
                depth += (ch == "(") - (ch == ")")
                self.i += 1
        self.fail("an arithmetic (( is never closed", opened)

    def heredoc(self):
        s = self.s
        if s.startswith("<<<", self.i):
            self.i += 3
            return
        opened = self.i
        self.i += 2
        strip = s.startswith("-", self.i)
        self.i += strip
        while s[self.i:self.i + 1] in (" ", "\t"):
            self.i += 1
        word, quoted = [], False
        while self.i < len(s) and s[self.i] not in " \t\n;&|<>()":
            ch = s[self.i]
            if ch in "'\"":
                end = s.find(ch, self.i + 1)
                if end < 0 or "\n" in s[self.i:end]:
                    self.fail("a heredoc delimiter's quote is never closed")
                word.append(s[self.i + 1:end])
                quoted, self.i = True, end + 1
            elif ch == "\\":
                word.append(s[self.i + 1:self.i + 2])
                quoted, self.i = True, self.i + 2
            elif ch in "$`":
                self.fail("a heredoc delimiter with an expansion in it")
            else:
                word.append(ch)
                self.i += 1
        if not word:
            self.fail("a heredoc has no delimiter")
        self.pending.append(("".join(word), strip, quoted, opened))

    def joined(self, at, quoted):
        s, end = self.s, self.eol(at)
        line = s[at:end]
        while not quoted and (len(line) - len(line.rstrip("\\"))) % 2 and end < len(s):
            nxt = self.eol(end + 1)
            line, end = line[:-1] + s[end + 1:nxt], nxt
        return end, line

    def bodies(self):
        s = self.s
        pending, self.pending = self.pending, []
        for delimiter, strip, quoted, opened in pending:
            start = self.i
            while True:
                if self.i >= len(s):
                    self.fail(f"the heredoc {delimiter!r} is never closed", opened)
                end, line = self.joined(self.i, quoted)
                if (line.lstrip("\t") if strip else line) == delimiter:
                    body_end, self.i = self.i, min(end + 1, len(s))
                    break
                self.i = end + 1
            if not quoted:
                self.expand(start, body_end)

    def expand(self, start, end):
        resume, self.i = self.i, start
        while self.i < end:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
            elif ch == "$":
                self.dollar(True)
            elif ch == "`":
                self.i += 1
                self.code("`")
            else:
                self.i += 1
        if self.i != end:
            self.fail("an expansion runs past the end of its heredoc", start)
        self.i = resume


class Script(Scanner):
    def run(self):
        if self.s.startswith("#!"):
            self.take(self.eol(0))
        self.code(None)
        return self.found

    def code(self, close):
        s, depth, prev = self.s, 0, "op"
        while self.i < len(s):
            ch = s[self.i]
            if ch.isspace():
                self.i += 1
            elif s.startswith("//", self.i):
                self.take(self.eol(self.i))
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                if end < 0:
                    self.fail("a /* comment is never closed")
                self.take(end + 2)
            elif ch in "'\"":
                self.skip_quoted(ch, newline=False)
                prev = "value"
            elif ch == "`":
                self.template()
                prev = "value"
            elif ch == "/":
                if prev == "close":
                    self.ambiguous_slash(close)
                if prev == "op":
                    self.regex()
                else:
                    self.i += 1
                prev = "value" if prev == "op" else "op"
            elif ch.isalnum() or ch in "_$#\\":
                word = JS_WORD.match(s, self.i).group()
                self.i += len(word)
                prev = "op" if word in REGEX_AFTER and prev != "member" else "value"
            elif s.startswith(("++", "--"), self.i):
                self.i += 2
                prev = "close"
            elif ch == "{":
                depth += 1
                self.i += 1
                prev = "op"
            elif ch == "}":
                self.i += 1
                if close and not depth:
                    return
                depth -= bool(depth)
                prev = "close"
            else:
                self.i += 1
                prev = {")": "close", "]": "value", ".": "member"}.get(ch, "op")
        if close:
            self.fail("a ${ in a template literal is never closed")

    def ambiguous_slash(self, close):
        rest = self.s[self.i + 1:self.eol(self.i)]
        cut = min((at for at in (rest.find("//"), rest.find("/*")) if at >= 0), default=-1)
        if cut >= 0 and not set(rest[:cut]) & set("/\\'\"`{}"):
            rest = rest[:cut]
        if any(mark in rest for mark in ("'", '"', "`", "//", "/*")) or (close and any(b in rest for b in "{}")):
            self.fail("a / after ) or } that could start a regular expression or divide")

    def regex(self):
        s, j, in_class = self.s, self.i + 1, False
        while j < len(s) and s[j] != "\n":
            if s[j] == "\\":
                j += 2
                continue
            if s[j] == "/" and not in_class:
                self.i = JS_FLAGS.match(s, j + 1).end()
                return
            in_class = (in_class or s[j] == "[") and s[j] != "]"
            j += 1
        self.fail("a regular expression is never closed")

    def template(self):
        s, opened = self.s, self.i
        self.i += 1
        while self.i < len(s):
            if s[self.i] == "\\":
                self.i += 2
            elif s[self.i] == "`":
                self.i += 1
                return
            elif s.startswith("${", self.i):
                self.i += 2
                self.code("}")
            else:
                self.i += 1
        self.fail("a template literal is never closed", opened)


class PowerShell(Scanner):
    def run(self):
        self.code(None)
        return self.found

    def code(self, close):
        s, depth = self.s, 0
        while self.i < len(s):
            ch = s[self.i]
            if s.startswith("<#", self.i):
                end = s.find("#>", self.i + 2)
                if end < 0:
                    self.fail("a <# comment is never closed")
                self.take(end + 2)
            elif ch == "#" and (self.i == 0 or not (s[self.i - 1].isalnum() or s[self.i - 1] in "_-.:/\\$@`")):
                self.take(self.eol(self.i))
            elif s.startswith(("@'", '@"'), self.i) and not s[self.i + 2:self.eol(self.i)].strip():
                self.here(s[self.i + 1])
            elif ch == "'":
                self.skip_quoted("'", escape=None, doubled=True)
            elif ch == '"':
                self.dquote()
            elif ch == "`":
                self.i += 2
            elif s.startswith("${", self.i):
                end = s.find("}", self.i + 2)
                if end < 0:
                    self.fail("a ${ is never closed")
                self.i = end + 1
            elif ch in SMART_QUOTES:
                self.fail("a typographic quote, which PowerShell reads as a quote")
            elif ch == "(":
                depth += 1
                self.i += 1
            elif ch == ")":
                self.i += 1
                if close and not depth:
                    return
                depth -= bool(depth)
            else:
                self.i += 1
        if close:
            self.fail("a $( is never closed")

    def dquote(self):
        s, opened = self.s, self.i
        self.i += 1
        while self.i < len(s):
            ch = s[self.i]
            if ch == "`" or s.startswith('""', self.i):
                self.i += 2
            elif ch == '"':
                self.i += 1
                return
            elif s.startswith("$(", self.i):
                self.i += 2
                self.code(")")
            elif ch in SMART_QUOTES:
                self.fail("a typographic quote, which PowerShell reads as a quote")
            else:
                self.i += 1
        self.fail("a string is never closed", opened)

    def here(self, quote):
        s, opened = self.s, self.i
        body = self.eol(self.i) + 1
        end = s.find("\n" + quote + "@", body - 1)
        if end < 0:
            self.fail("a here-string is never closed")
        self.i = body
        while quote == '"' and self.i < end:
            if s[self.i] == "`":
                self.i += 2
            elif s.startswith("$(", self.i):
                self.i += 2
                self.code(")")
            else:
                self.i += 1
        if self.i > end:
            self.fail("an expansion runs past the end of its here-string", opened)
        self.i = end + 3


class Yaml:
    def __init__(self, text):
        self.lines = text.split("\n")
        self.found, self.block, self.quote, self.flow = [], None, None, 0

    def run(self):
        for n, line in enumerate(self.lines, 1):
            if self.block is None or not self.in_block(line):
                self.scan(n, line)
        if self.quote:
            raise Unreadable(self.quote[1], "a quoted scalar is never closed")
        if self.flow:
            raise Unreadable(len(self.lines), "a flow collection is never closed")
        return self.found

    def in_block(self, line):
        parent, content = self.block
        indent = len(line) - len(line.lstrip(" "))
        if not line.strip():
            return True
        if content is None and indent > parent:
            self.block = (parent, indent)
            return True
        if content is not None and indent >= content:
            return True
        self.block = None
        return False

    def scan(self, n, line):
        at_node, owner, node = True, None, 0
        if self.quote:
            i = self.close_quote(line, 0)
            if i is None:
                return
            at_node = False
        else:
            i = node = len(line) - len(line.lstrip(" "))
            if line[i:i + 1] == "\t" and line.strip():
                raise Unreadable(n, "a tab in indentation")
            if not self.flow and line.startswith(("---", "...")) and line[3:4] in ("", " ", "\t"):
                i = 3
        while i < len(line):
            ch, follows = line[i], line[i + 1:i + 2]
            if ch in " \t":
                i += 1
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                self.found.append((n, "comment", line[i:]))
                return
            elif not at_node:
                if ch == ":" and (follows in ("", " ", "\t") or (self.flow and follows in tuple(",[]{}"))):
                    owner, at_node = node, True
                elif self.flow and ch == ",":
                    at_node = True
                elif self.flow and ch in "]}":
                    self.flow -= 1
                i += 1
            elif ch in "-?:" and follows in ("", " ", "\t"):
                owner = i if ch == "-" else owner
                i += 1
            elif ch in "'\"":
                node, self.quote = i, (ch, n)
                i = self.close_quote(line, i + 1)
                if i is None:
                    return
                at_node = False
            elif ch in "|>":
                self.block_header(n, line, i, owner)
                return
            elif ch in "[{" or (self.flow and ch in ",]}"):
                self.flow += {"[": 1, "{": 1, "]": -1, "}": -1}.get(ch, 0)
                at_node = ch not in "]}"
                i += 1
            elif ch in "&!":
                while i < len(line) and line[i] not in " \t":
                    i += 1
            elif ch in "@`%":
                raise Unreadable(n, f"a plain scalar that starts with {ch!r}")
            else:
                node, at_node = i, False
                i += 1
        if self.flow < 0:
            raise Unreadable(n, "a ] or } that closes nothing")

    def block_header(self, n, line, i, owner):
        header = YAML_BLOCK.match(line, i)
        if self.flow or header is None or owner is None:
            raise Unreadable(n, "a block scalar this lexer cannot follow (indentation indicator, flow, or no key)")
        rest = line[header.end():].lstrip(" \t")
        if rest and not rest.startswith("#"):
            raise Unreadable(n, "text after a block scalar header")
        if rest:
            self.found.append((n, "comment", rest))
        self.block = (owner, None)

    def close_quote(self, line, start):
        quote, j = self.quote[0], start
        while j < len(line):
            if quote == '"' and line[j] == "\\":
                j += 2
            elif line[j] == quote and quote == "'" and line[j + 1:j + 2] == "'":
                j += 2
            elif line[j] == quote:
                self.quote = None
                return j + 1
            else:
                j += 1
        return None


def markup_lexer(text):
    sc = Scanner(text)
    while (start := text.find("<!--", sc.i)) >= 0:
        end = text.find("-->", start + 4)
        if end < 0:
            sc.fail("a <!-- comment is never closed", start)
        sc.i = start
        sc.take(end + 3)
    return sc.found


def line_lexer(find):
    def lexer(text):
        found = []
        for n, line in enumerate(text.split("\n"), 1):
            at = find(n, line)
            if at is not None:
                found.append((n, "comment", line[at:]))
        return found
    return lexer


def leading_hash(n, line):
    body = line.lstrip()
    return len(line) - len(body) if body.startswith("#") else None


def dockerfile_hash(n, line):
    if "<<" in line:
        raise Unreadable(n, "a heredoc in a Dockerfile, whose body this lexer cannot classify")
    return leading_hash(n, line)


def env_hash(n, line):
    body = line.lstrip(" \t")
    if not body or body.startswith("#"):
        return len(line) - len(body) if body else None
    assign = ENV_ASSIGN.match(line)
    if assign is None:
        raise Unreadable(n, "is not KEY=value")
    rest = line[ENV_VALUE.match(line, assign.end()).end():]
    tail = rest.lstrip(" \t")
    if not tail:
        return None
    if tail.startswith("#") and len(rest) > len(tail):
        return len(line) - len(tail)
    raise Unreadable(n, "a value with a space or a quote inside must be one quoted string")


def batch_rem(n, line):
    plain = line.lstrip(" \t@")
    if plain.startswith("::"):
        return len(line) - len(plain)
    i, quoted, at_command = 0, False, True
    while i < len(line):
        ch = line[i]
        if quoted:
            quoted = ch != '"'
        elif ch == '"':
            quoted, at_command = True, False
        elif ch == "^":
            i, at_command = i + 1, False
        elif at_command and BATCH_REM.match(line, i):
            return i
        elif ch in "&|(":
            at_command = True
        elif ch not in " \t@":
            at_command = False
        i += 1
    return None


LEXERS = {
    ".py": python_lexer,
    ".rs": rust_lexer,
    ".toml": toml_lexer,
    ".bend": bend_lexer,
    ".sh": lambda text: Shell(text).run(),
    ".bash": lambda text: Shell(text).run(),
    ".env": line_lexer(env_hash),
    ".yml": lambda text: Yaml(text).run(),
    ".yaml": lambda text: Yaml(text).run(),
    "Dockerfile": line_lexer(dockerfile_hash),
    ".gitignore": line_lexer(leading_hash),
    ".gitattributes": line_lexer(leading_hash),
    ".js": lambda text: Script(text).run(),
    ".mjs": lambda text: Script(text).run(),
    ".ps1": lambda text: PowerShell(text).run(),
    ".cmd": line_lexer(batch_rem),
    ".md": markup_lexer,
    ".html": markup_lexer,
}
CHECKED = tuple(LEXERS)


def lexer_key(path):
    name = PurePosixPath(path).name
    suffix = PurePosixPath(name).suffix.lower()
    return name if name in LEXERS else suffix if suffix in LEXERS else None


def lexer_for(path, text):
    key = lexer_key(path)
    if key:
        return LEXERS[key]
    if not PurePosixPath(path).suffix and SHELL_SHEBANG.match(text):
        return LEXERS[".sh"]
    return None


def is_checked(path):
    return not is_data(path) and (lexer_key(path) is not None or not PurePosixPath(path).suffix)


def shebang(span, text):
    return span.line == 1 and span.kind == "comment" and span.text.startswith("#!")


def safety_above_unsafe(span, text):
    if not (span.path.endswith(".rs") and span.kind == "comment" and span.text.startswith("// SAFETY:")):
        return False
    lines = text.split("\n")
    if span.line >= len(lines) or lines[span.line - 1].strip() != span.text.strip():
        return False
    try:
        return any(t.kind == "ident" and t.text == "unsafe" for t in rust_tokens.tokenize(lines[span.line]))
    except rust_tokens.LexError:
        return False


DIRECTIVES = (shebang, safety_above_unsafe)


def comment_spans(path, text):
    text = text.replace("\r\n", "\n")
    lexer = lexer_for(path, text)
    if lexer is None:
        return []
    try:
        raw = lexer(text)
    except Unreadable as error:
        return [Span(path, error.line, UNREADABLE, error.reason)]
    spans = sorted((Span(path, line, kind, body) for line, kind, body in raw), key=lambda span: span.line)
    return [span for span in spans if not any(exempt(span, text) for exempt in DIRECTIVES)]


def counted(path, data, frozen):
    if not is_checked(path):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Span(path, 1, UNREADABLE, "is not UTF-8")] if lexer_key(path) else []
    spans = comment_spans(path, text)
    return [s for s in spans if s.kind not in FROZEN_SPEC_KINDS] if path in frozen else spans


def git(root, *args, data=None):
    return subprocess.run(["git", "-C", str(root), *args], input=data, capture_output=True, env=vac_core.git_env())


def blobs(root, ref, paths):
    if any("\n" in p for p in paths):
        raise ValueError("a path with a line break in it")
    child = git(root, "cat-file", "--batch", data="".join(f"{ref}:{p}\n" for p in paths).encode())
    if child.returncode:
        raise ValueError(f"git cat-file failed: {child.stderr.decode(errors='replace').strip()}")
    out, at, found = child.stdout, 0, {}
    for path in paths:
        end = out.index(b"\n", at)
        header, at = out[at:end].split(), end + 1
        if header[-1] == b"missing":
            continue
        size = int(header[2])
        if header[1] == b"blob":
            found[path] = out[at:at + size]
        at += size + 1
    return found


def load_debt(text):
    data = tomllib.loads(text)
    files = data.get("files")
    if set(data) != {"files"} or not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        raise ValueError(f'{DEBT_FILE} must hold only files = ["path", ...]')
    return files


def toml_string(value):
    body = "".join(TOML_ESCAPES.get(ch) or (f"\\u{ord(ch):04X}" if ch < " " or ch == "\x7f" else ch) for ch in value)
    return f'"{body}"'


def debt_text(files):
    return "files = [\n" + "".join(f"  {toml_string(f)},\n" for f in sorted(set(files))) + "]\n"


class Tree:
    def __init__(self, root, base=MAIN):
        self.root, self.base, self.cache = Path(root), base, {}
        listed = git(self.root, "ls-files", "-z")
        if listed.returncode:
            raise ValueError(f"git ls-files failed: {listed.stderr.decode(errors='replace').strip()}")
        self.files = [p for p in listed.stdout.decode("utf-8").split("\0") if p]
        names = git(self.root, "ls-tree", "-r", "-z", "--name-only", f"{base}^{{commit}}")
        self.frozen = frozenset(p for p in names.stdout.decode("utf-8").split("\0")
                                if p and policy_check.is_spec(p)) if names.returncode == 0 else frozenset()

    def checked(self):
        return [p for p in self.files if is_checked(p)]

    def spans(self, path):
        if path not in self.cache:
            target = self.root / path
            if not target.is_file() or target.is_symlink():
                self.cache[path] = []
            else:
                try:
                    data = target.read_bytes()
                except OSError as error:
                    self.cache[path] = [Span(path, 1, UNREADABLE, f"cannot be read ({error})")]
                else:
                    self.cache[path] = counted(path, data, self.frozen)
        return self.cache[path]

    def debt(self):
        target = self.root / DEBT_FILE
        return load_debt(target.read_text(encoding="utf-8")) if target.is_file() else []

    def debt_ceiling(self):
        if git(self.root, "rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}").returncode:
            raise ValueError(f"{self.base} is missing; run git fetch origin main so the debt can be compared")
        found = blobs(self.root, self.base, [DEBT_FILE]).get(DEBT_FILE)
        if found is not None:
            return self.base, load_debt(found.decode("utf-8")), None
        if self.debt_existed():
            return f"{self.base}, which deleted it", [], None
        merge = git(self.root, "merge-base", "HEAD", self.base)
        if merge.returncode:
            raise ValueError(f"HEAD has no merge-base with {self.base}")
        base = merge.stdout.decode().strip()
        added = git(self.root, "log", "--format=%H", "--diff-filter=A", "--reverse", f"{base}..HEAD", "--", DEBT_FILE)
        if added.returncode:
            raise ValueError(f"git log failed: {added.stderr.decode(errors='replace').strip()}")
        first = added.stdout.decode().split()
        if not first:
            return "the working tree", self.debt(), base
        return first[0][:12], load_debt(blobs(self.root, first[0], [DEBT_FILE])[DEBT_FILE].decode("utf-8")), base

    def debt_existed(self):
        past = git(self.root, "log", "--format=%H", "-1", f"{self.base}^{{commit}}", "--", DEBT_FILE)
        if past.returncode:
            raise ValueError(f"git log failed: {past.stderr.decode(errors='replace').strip()}")
        return bool(past.stdout.split())


def describe(span):
    lines = span.text.strip().splitlines() or [""]
    shown = lines[0] if len(lines[0]) <= 120 else lines[0][:117] + "..."
    if span.kind == UNREADABLE:
        return f"unreadable: {span.text}; write it so the comment lexer can follow it"
    return f"{span.kind}: {shown}"


def new_comments(tree, changed=None):
    debt = set(tree.debt())
    wanted = None if changed is None else set(changed)
    return [span for path in tree.checked() if wanted is None or path in wanted
            for span in tree.spans(path) if path not in debt or span.kind == UNREADABLE]


def debt_errors(tree):
    entries = tree.debt()
    if not entries:
        return []
    where, ceiling, start = tree.debt_ceiling()
    allowed = set(ceiling)
    errors = [f"{p} is not in {DEBT_FILE} at {where}; the list only shrinks, so remove the file's comments instead"
              for p in entries if p not in allowed]
    if start is not None:
        before = blobs(tree.root, start, entries)
        errors += [f"{p} had no comments at {start[:12]}, where the list started; only a file that had comments "
                   "then can be listed" for p in entries if p in before and not counted(p, before[p], tree.frozen)]
    errors += [f"{p} has no comments left; remove it with vac comments --debt-write"
               for p in entries if not tree.spans(p)]
    return errors


def skip_reason(root, path):
    target = Path(root) / path
    if is_data(path):
        return "is data, never checked"
    if not target.is_file():
        return "is not a file"
    if lexer_for(path, target.read_bytes().decode("utf-8", errors="replace")) is None:
        return f"has no comment lexer; checked: {', '.join(CHECKED)} and extensionless sh or bash scripts"
    return None


def listing(root, paths, as_json, out=sys.stdout, err=sys.stderr):
    tree = Tree(root)
    chosen = [PurePosixPath(p).as_posix().removeprefix("./") for p in paths] or tree.checked()
    total, files = 0, 0
    for path in chosen:
        reason = skip_reason(root, path) if paths else None
        if reason:
            print(f"vac: {path} {reason}", file=err)
            continue
        spans = tree.spans(path)
        files += bool(spans)
        total += len(spans)
        for span in spans:
            print(json.dumps(span._asdict()) if as_json else f"{span.path}:{span.line}: {describe(span)}", file=out)
    if not as_json:
        print(f"vac: {total} comment spans in {files} files", file=out)
    return 0


def debt_write(root, out=sys.stdout):
    tree = Tree(root)
    target = tree.root / DEBT_FILE
    if target.is_symlink():
        print(f"vac: {DEBT_FILE} is a symbolic link; replace it with a regular file", file=out)
        return 1
    if target.is_file():
        try:
            old = tree.debt()
        except ValueError as error:
            print(f"vac: {error}", file=out)
            return 1
        candidates = old
    else:
        try:
            where, ceiling, start = tree.debt_ceiling()
        except ValueError as error:
            print(f"vac: {error}", file=out)
            return 1
        old = []
        candidates = tree.checked() if start is not None else ceiling
        if start is None:
            print(f"vac: {DEBT_FILE} is absent; the ceiling is {where}, so only the files it lists can be listed again",
                  file=out)
    blocked = [s for p in candidates for s in tree.spans(p) if s.kind == UNREADABLE]
    if blocked:
        for span in blocked:
            print(f"vac: {span.path}:{span.line}: {describe(span)}", file=out)
        print(f"vac: {DEBT_FILE} is unchanged while a file cannot be read", file=out)
        return 1
    keep = [p for p in candidates if tree.spans(p)]
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, staged = tempfile.mkstemp(dir=target.parent, prefix=".comment_debt.", suffix=".toml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(debt_text(keep))
        os.replace(staged, target)
    except BaseException:
        Path(staged).unlink(missing_ok=True)
        raise
    removed = sorted(set(old) - set(keep))
    print(f"vac: {DEBT_FILE} lists {len(set(keep))} files" + (f"; removed {', '.join(removed)}" if removed else ""),
          file=out)
    return 0

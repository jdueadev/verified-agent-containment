import importlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
comments = importlib.import_module("vac_comments")
core = importlib.import_module("vac_core")
registry = importlib.import_module("vac_rules")
ROOT = Path(__file__).resolve().parent.parent
UNREADABLE = "unreadable"
DEBT = comments.DEBT_FILE

CORPUS = {
    "python": (
        ("hash in strings", "a.py", "x = \"# no\" + '# no' + f\"{'#'}\"\n", []),
        ("trailing comment", "a.py", "x = 1  # yes\n", [(1, "comment", "# yes")]),
        ("hash in a triple-quoted value", "a.py", 'x = """\n# not a comment\n"""\n', []),
        ("module, class and function docstrings", "a.py",
         '"""Module."""\nclass A:\n    "Class."\n    def f(self):\n        \'\'\'Function.\'\'\'\n        return 1\n',
         [(1, "docstring", '"""Module."""'), (3, "docstring", '"Class."'), (5, "docstring", "'''Function.'''")]),
        ("bare strings that are not docstrings", "a.py", 'x = 1\n"loose"\nif x:\n    "nested"\n',
         [(2, "string", '"loose"'), (4, "string", '"nested"')]),
        ("a bare f-string", "a.py", 'x = 1\nf"loose {x}"\n', [(2, "string", 'f"loose {x}"')]),
        ("a leading bytes literal is no docstring", "a.py", 'b"loose"\nx = 1\n', [(1, "string", 'b"loose"')]),
        ("a leading f-string is no docstring", "a.py", 'f"loose"\nx = 1\n', [(1, "string", 'f"loose"')]),
        ("a leading bytes literal in a function is no docstring", "a.py", 'def f():\n    b"loose"\n',
         [(2, "string", 'b"loose"')]),
        ("shebang on line 1 is exempt", "a.py", "#!/usr/bin/env python3\nx = 1\n", []),
        ("a shebang below line 1 counts", "a.py", "x = 1\n#!/bin/sh\n", [(2, "comment", "#!/bin/sh")]),
        ("a coding cookie counts", "a.py", "# -*- coding: utf-8 -*-\nx = 1\n",
         [(1, "comment", "# -*- coding: utf-8 -*-")]),
        ("noqa is no exception", "a.py", "import os  # noqa: F401\n", [(1, "comment", "# noqa: F401")]),
        ("generated is no exception", "a.py", "# @generated\nx = 1\n", [(1, "comment", "# @generated")]),
        ("unparseable", "a.py", "def (:\n", UNREADABLE),
    ),
    "rust": (
        ("line, doc and inner doc", "a.rs", "//! Crate.\n/// Item.\nfn f() {} // after\n",
         [(1, "doc", "//! Crate."), (2, "doc", "/// Item."), (3, "comment", "// after")]),
        ("slashes in strings", "a.rs", 'let a = "// no"; let b = r#"/* no */"#;\n', []),
        ("nested block comment", "a.rs", "/* a /* b */ c */ fn f() {}\n", [(1, "comment", "/* a /* b */ c */")]),
        ("SAFETY above unsafe is exempt", "a.rs", "// SAFETY: x\nunsafe { f() };\n", []),
        ("SAFETY above safe code counts", "a.rs", "// SAFETY: x\nf();\n", [(1, "comment", "// SAFETY: x")]),
        ("SAFETY above unsafe in a string counts", "a.rs", '// SAFETY: x\nlet s = "unsafe";\n',
         [(1, "comment", "// SAFETY: x")]),
        ("SAFETY after code counts", "a.rs", "f(); // SAFETY: x\nunsafe { g() };\n", [(1, "comment", "// SAFETY: x")]),
        ("SAFETY two lines above counts", "a.rs", "// SAFETY: x\n\nunsafe { f() };\n",
         [(1, "comment", "// SAFETY: x")]),
        ("a lowercase safety note counts", "a.rs", "// Safety: x\nunsafe { f() };\n", [(1, "comment", "// Safety: x")]),
        ("SAFETY in a doc comment counts", "a.rs", "/// SAFETY: x\nunsafe fn f() {}\n", [(1, "doc", "/// SAFETY: x")]),
        ("unterminated string", "a.rs", 'let a = "x;\n', UNREADABLE),
    ),
    "toml": (
        ("hash in basic and literal strings", "a.toml", "a = \"x # y\"\nb = 'x # y'\n", []),
        ("trailing comment", "a.toml", "a = 1 # c\n", [(1, "comment", "# c")]),
        ("multi-line literal", "a.toml", "a = '''\n# not\n'''\n", []),
        ("multi-line basic", "a.toml", 'a = """\n# not\n"""\n', []),
        ("multi-line basic with an escaped quote", "a.toml", 'a = """x\\""" # not"""\n', []),
        ("multi-line basic ending in extra quotes", "a.toml", 'a = """x\\"""" # c\n', [(1, "comment", "# c")]),
        ("multi-line literal ending in extra quotes", "a.toml", "a = '''x'''' # c\n", [(1, "comment", "# c")]),
        ("comment line", "a.toml", "# c\n[t]\n", [(1, "comment", "# c")]),
        ("not TOML", "a.toml", "a = = 1\n", UNREADABLE),
    ),
    "yaml": (
        ("hash in quoted scalars", "a.yml", "a: \"x # y\"\nb: 'it''s # y'\n", []),
        ("trailing comment", "a.yml", "a: b # c\n", [(1, "comment", "# c")]),
        ("hash with no space before it", "a.yml", "url: https://x.test/#frag\n", []),
        ("block scalar body is data", "a.yaml", "run: |\n  # shell\n  echo hi\nnext: 1 # c\n", [(4, "comment", "# c")]),
        ("nested block scalar ends at a sibling key", "a.yml",
         "steps:\n  - run: |\n      # data\n    shell: bash # c\n", [(4, "comment", "# c")]),
        ("an empty block scalar before a sibling key", "a.yml", "steps:\n  - run: |\n    shell: bash # c\n",
         [(3, "comment", "# c")]),
        ("a quote inside a plain scalar opens nothing", "a.yml", "a: echo 'x # y'\n", [(1, "comment", "# y'")]),
        ("double-quoted scalar across lines", "a.yml", 'a: "x\n  # y"\nb: 1\n', []),
        ("comment after a block header", "a.yml", "run: | # c\n  echo\n", [(1, "comment", "# c")]),
        ("flow sequence", "a.yml", 'a: [x, "y # z"] # c\n', [(1, "comment", "# c")]),
        ("tab indentation", "a.yml", "a:\n\tb: 1\n", UNREADABLE),
        ("indentation indicator", "a.yml", "a: |2\n  x\n", UNREADABLE),
        ("unclosed quote", "a.yml", 'a: "x\n', UNREADABLE),
    ),
    "shell": (
        ("hash in quotes", "a.sh", "echo \"# no\" '# no'\n", []),
        ("hash inside a word", "a.sh", "echo a#b\nx=#y\n", []),
        ("comment after a separator", "a.sh", "true;# c\n", [(1, "comment", "# c")]),
        ("a line continuation joins the next word", "a.sh", "echo a\\\n#b\n", []),
        ("an escaped backslash ends the word", "a.sh", "echo a\\\\\n# c\n", [(2, "comment", "# c")]),
        ("a line continuation keeps the word break before it", "a.sh", "echo \\\n# c\n", [(2, "comment", "# c")]),
        ("$# is a parameter", "a.sh", "[ $# -eq 0 ] && echo none\n", []),
        ("${#a} is a length", "a.sh", 'echo ${#a} "${#b}"\n', []),
        ("a spaced hash inside ${ }", "a.sh", "echo ${x:- #b}\n", []),
        ("ANSI-C quoting", "a.bash", "echo $'it\\'s # x'\n", []),
        ("quoted heredoc body is data", "a.sh", "cat <<'EOF'\n# data\nEOF\n# c\n", [(4, "comment", "# c")]),
        ("quoted heredoc body expands nothing", "a.sh", "cat <<'EOF'\n$(echo # x)\nEOF\n", []),
        ("a comment in a substitution inside a string", "a.sh", 'x="$(echo a # c\n)"\n', [(1, "comment", "# c")]),
        ("unquoted heredoc body is data", "a.sh", "cat <<EOF\n## heading $x\nEOF\n", []),
        ("a comment in a substitution inside a heredoc", "a.sh", "cat <<EOF\n$(echo hi # c\n)\nEOF\n",
         [(2, "comment", "# c")]),
        ("tab-stripped heredoc", "a.sh", "cat <<-EOF\n\t# data\n\tEOF\necho # c\n", [(4, "comment", "# c")]),
        ("heredoc in a substitution in a string", "a.sh", 'body="$(cat <<EOF\n# data\nEOF\n)"\n# c\n',
         [(5, "comment", "# c")]),
        ("a here-string is not a heredoc", "a.sh", 'grep -q x <<<"$v" # c\n', [(1, "comment", "# c")]),
        ("arithmetic shift is not a heredoc", "a.sh", "echo $((1 << 2)) # c\n", [(1, "comment", "# c")]),
        ("a comment inside $( )", "a.sh", "x=$(echo a # c\n)\n", [(1, "comment", "# c")]),
        ("shebang is exempt", "a.sh", "#!/bin/sh\necho hi # c\n", [(2, "comment", "# c")]),
        ("case inside $( ) fails closed", "a.sh", "x=$(case a in a) echo;; esac)\n", UNREADABLE),
        ("unclosed heredoc", "a.sh", "cat <<EOF\nx\n", UNREADABLE),
        ("unclosed string", "a.sh", 'echo "x\n', UNREADABLE),
    ),
    "bend": (
        ("line comment", "a.bend", "# c\ndef main: 1\n", [(1, "comment", "# c")]),
        ("hash in a string", "a.bend", 'def main: "# no"\n', []),
        ("block comment", "a.bend", "#{\nx\n#}\ndef main: 1\n", [(1, "comment", "#{\nx\n#}")]),
        ("unclosed block comment", "a.bend", "#{ x\n", UNREADABLE),
    ),
    "env": (
        ("comment line", "pins.env", "# c\nA=1\n", [(1, "comment", "# c")]),
        ("hash in quoted values", "pins.env", "A=\"x # y\"\nB='x # y'\n", []),
        ("hash inside a value", "pins.env", "A=x#y\n", []),
        ("trailing comment", "pins.env", "A=x # c\n", [(1, "comment", "# c")]),
        ("unquoted space", "pins.env", "A=x y\n", UNREADABLE),
        ("a hash right after a quoted value", "pins.env", 'A="x"#y\n', UNREADABLE),
        ("not an assignment", "pins.env", "echo hi\n", UNREADABLE),
    ),
    "javascript": (
        ("slashes in strings", "a.mjs", "const a = \"// no\", b = '/* no */';\n", []),
        ("a URL in a string", "a.js", 'fetch("https://x.test/a");\n', []),
        ("line and block comments", "a.mjs", "f(); // c\n/* d */\n",
         [(1, "comment", "// c"), (2, "comment", "/* d */")]),
        ("template literal with an expression", "a.mjs", 'const t = `a ${"}"} // in template`; // c\n',
         [(1, "comment", "// c")]),
        ("a URL in a template", "a.mjs", "const u = `file://${dir}/`;\n", []),
        ("a backtick inside a template expression", "a.mjs", 'const t = `${ "`" } // not a comment`;\n', []),
        ("regex holding slashes", "a.mjs", "const r = /\\/\\/ no/g; // c\n", [(1, "comment", "// c")]),
        ("regex with slashes in a class", "a.mjs", "const r = /[///]/;\n", []),
        ("regex after a paren", "a.mjs", "s.replace(/'/g, \"\");\n", []),
        ("regex after a keyword", "a.mjs", "return /\\/\\//.test(s);\n", []),
        ("a member named like a keyword divides", "a.js", "const v = object.in / 2;\n", []),
        ("an optional-chained member named like a keyword divides", "a.js", "const v = object?.in / 2;\n", []),
        ("division then a comment", "a.mjs", "const v = a / b; // c\n", [(1, "comment", "// c")]),
        ("an ambiguous slash fails closed", "a.mjs", "const v = (a) / b; // c\n", UNREADABLE),
        ("a plain ambiguous slash is division", "a.mjs", "const v = (a) / 2;\n", []),
        ("hashbang is exempt", "a.mjs", "#!/usr/bin/env -S node --name=it's\nf(); // c\n", [(2, "comment", "// c")]),
        ("private field", "a.mjs", "class A { #x = 1; f() { return this.#x; } }\n", []),
        ("unclosed block comment", "a.mjs", "/* x\n", UNREADABLE),
    ),
    "powershell": (
        ("line and block comments", "a.ps1", "<# block #>\nWrite-Host hi # c\n",
         [(1, "comment", "<# block #>"), (2, "comment", "# c")]),
        ("hash in strings", "a.ps1", "Write-Host \"a # b\" 'it''s # x'\n", []),
        ("a comment inside a subexpression", "a.ps1", '"$(Get-X # c\n)"\n', [(1, "comment", "# c")]),
        ("single-quoted here-string is data", "a.ps1", "$a = @'\nit's # data\n'@\n# c\n", [(4, "comment", "# c")]),
        ("double-quoted here-string expands", "a.ps1", '@"\n$(Get-X # c\n)\n"@\n', [(2, "comment", "# c")]),
        ("hash inside a word", "a.ps1", "Write-Host a#b\n", []),
        ("unclosed block comment", "a.ps1", "<# x\n", UNREADABLE),
        ("typographic quote", "a.ps1", "Write-Host \u2018x\u2019\n", UNREADABLE),
    ),
    "cmd": (
        ("rem and ::", "a.cmd", "@echo off\nrem c\nREM d\n:: e\n",
         [(2, "comment", "rem c"), (3, "comment", "REM d"), (4, "comment", ":: e")]),
        ("rem after &", "a.cmd", "echo x&rem c\n", [(1, "comment", "rem c")]),
        ("rem inside quotes", "a.cmd", 'echo "a & rem b"\n', []),
        ("remark and labels", "a.cmd", "echo remark\n:label\n", []),
        ("rem as an argument", "a.cmd", "echo rem to continue\n", []),
        ("rem after an at sign inside a word", "a.cmd", "echo a@rem b\n", []),
        ("rem after a pipe", "a.cmd", "echo x|rem c\n", [(1, "comment", "rem c")]),
        ("@rem", "a.cmd", "@rem c\n", [(1, "comment", "rem c")]),
        ("CRLF lines", "a.cmd", "rem c\r\necho x\r\n", [(1, "comment", "rem c")]),
    ),
    "markup": (
        ("html comment in markdown", "README.md", "# Title\n<!-- c -->\n", [(2, "comment", "<!-- c -->")]),
        ("multi-line comment", "a.md", "<!--\nx\n-->\n", [(1, "comment", "<!--\nx\n-->")]),
        ("html page", "page.html", "<p>a # b // c</p>\n<!-- d -->\n", [(2, "comment", "<!-- d -->")]),
        ("unclosed comment", "a.md", "<!-- x\n", UNREADABLE),
    ),
    "dockerfile": (
        ("comment line and a hash in a word", "Dockerfile", "# c\nFROM x\nRUN echo a#b\n", [(1, "comment", "# c")]),
        ("an indented comment line", "Dockerfile", "  # c\nFROM x\n", [(1, "comment", "# c")]),
        ("a hash after a space is no Dockerfile comment", "Dockerfile", "RUN x # c\n", []),
        ("a hash inside a quoted value", "Dockerfile", 'LABEL description="part #1"\n', []),
        ("heredoc fails closed", "Dockerfile", "RUN cat <<EOF\nx\nEOF\n", UNREADABLE),
    ),
    "git": (
        ("gitignore", ".gitignore", "# c\n\\#file\na#b\n", [(1, "comment", "# c")]),
        ("gitattributes", ".gitattributes", "*.cmd -text # trailing\n# c\n", [(2, "comment", "# c")]),
    ),
    "unchecked": (
        ("extensionless bash script", "scripts/run", "#!/bin/bash\necho a # c\n", [(2, "comment", "# c")]),
        ("extensionless env sh script", "scripts/go", "#!/usr/bin/env sh\n# c\n", [(2, "comment", "# c")]),
        ("extensionless text", "LICENSE", "# x\n", []),
        ("unknown extension", "notes.txt", "# x\n", []),
        ("extensionless python script", "scripts/tool", "#!/usr/bin/env python3\n# x\n", []),
    ),
}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


class Repo:
    def __init__(self, test):
        self.root = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.root)
        git(self.root, "init", "-q", "-b", "work")

    def write(self, files):
        for path, text in files.items():
            target = self.root / path
            if text is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))

    def commit(self, files):
        self.write(files)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", "c")
        return git(self.root, "rev-parse", "HEAD")

    def main_here(self):
        git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")

    def check(self, rule_id, changed=None):
        rule = next(r for r in registry.RULES if r.id == rule_id)
        return rule.check(core.Ctx(root=self.root, changed=changed))


def where(found):
    return [(f.path, f.line) for f in found]


class CorpusTests(unittest.TestCase):
    def test_every_corpus_case(self):
        for syntax, cases in CORPUS.items():
            for name, path, source, expected in cases:
                with self.subTest(syntax=syntax, case=name):
                    got = comments.comment_spans(path, source)
                    if expected == UNREADABLE:
                        self.assertEqual([s.kind for s in got], [UNREADABLE], got)
                    else:
                        self.assertEqual([(s.line, s.kind, s.text) for s in got], expected)

    def test_every_lexed_syntax_is_listed_as_checked(self):
        lexed = {comments.lexer_key(path) for cases in CORPUS.values() for _, path, _, _ in cases} - {None}
        self.assertEqual(lexed - set(comments.CHECKED), set())
        self.assertLessEqual({".py", ".rs", ".toml", ".bend", ".sh", ".bash", ".env", ".yml", ".yaml", "Dockerfile",
                              ".gitignore", ".gitattributes", ".js", ".mjs", ".ps1", ".cmd", ".md", ".html"},
                             set(comments.CHECKED))

    def test_spans_name_their_path(self):
        self.assertEqual({s.path for s in comments.comment_spans("x/a.sh", "# a\n# b\n")}, {"x/a.sh"})


class DataPathTests(unittest.TestCase):
    def test_data_paths_are_never_checked(self):
        for path in ("results/a.py", "redteam/site/x.html", "examples/live/a.sh", "ci/corpus/x/y.py",
                     ".claude/handover/HANDOVER-1.md", "web/fixtures/a.html", "a/b/fixtures/c.py", "fixtures/x.py",
                     "target/debug/x.rs", "Cargo.lock", "docs/claims.md", ".github/CODEOWNERS"):
            with self.subTest(path=path):
                self.assertTrue(comments.is_data(path))
                self.assertFalse(comments.is_checked(path))

    def test_neighbours_of_data_paths_are_checked(self):
        for path in ("tools/x.py", "docs/claims2.md", "results.md", "mytarget/x.rs", "ci/corpusx.py",
                     "tools/fixtures.py", ".claude/skills/x/SKILL.md"):
            with self.subTest(path=path):
                self.assertFalse(comments.is_data(path))
                self.assertTrue(comments.is_checked(path))

    def test_a_comment_under_a_data_path_never_fails(self):
        repo = Repo(self)
        repo.commit({"results/a.py": "# c\n", "redteam/b.sh": "# c\n", "tools/fixtures/c.py": "# c\n"})
        repo.main_here()
        self.assertEqual(repo.check("NC-1"), [])


class NoNewCommentTests(unittest.TestCase):
    def test_an_unlisted_comment_fails_with_its_line_and_text(self):
        repo = Repo(self)
        repo.commit({"a.py": "x = 1\n"})
        repo.main_here()
        repo.commit({"a.py": "x = 1\n# why\n"})
        found = repo.check("NC-1")
        self.assertEqual([(f.path, f.line, f.message) for f in found], [("a.py", 2, "comment: # why")])

    def test_a_listed_file_is_debt_not_a_failure(self):
        repo = Repo(self)
        repo.commit({"a.py": "# why\n", "b.py": "# also\n", DEBT: comments.debt_text(["a.py"])})
        repo.main_here()
        self.assertEqual(where(repo.check("NC-1")), [("b.py", 1)])

    def test_changed_limits_the_files_checked(self):
        repo = Repo(self)
        repo.commit({"a.py": "# why\n", "b.py": "# also\n"})
        repo.main_here()
        self.assertEqual(where(repo.check("NC-1", changed=("b.py",))), [("b.py", 1)])
        self.assertEqual(repo.check("NC-1", changed=("c.py",)), [])

    def test_an_unreadable_file_fails(self):
        repo = Repo(self)
        repo.commit({"a.sh": "cat <<EOF\nnever closed\n"})
        repo.main_here()
        found = repo.check("NC-1")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].message.startswith("unreadable:"), found[0].message)

    def test_a_listed_file_that_cannot_be_read_still_fails(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", DEBT: comments.debt_text(["a.py"])})
        repo.main_here()
        repo.commit({"a.py": "def (:\n"})
        found = repo.check("NC-1")
        self.assertEqual(where(found), [("a.py", 1)])
        self.assertTrue(found[0].message.startswith("unreadable:"), found[0].message)

    def test_a_listed_file_keeps_its_comments_exempt(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", DEBT: comments.debt_text(["a.py"])})
        repo.main_here()
        self.assertEqual(repo.check("NC-1"), [])

    def test_a_checked_file_that_is_not_utf8_fails_and_a_binary_blob_does_not(self):
        repo = Repo(self)
        repo.commit({"a.py": b"x = '\xff'\n", "blob": b"\x00\xff\xfe"})
        repo.main_here()
        self.assertEqual([(f.path, f.message) for f in repo.check("NC-1")],
                         [("a.py", "unreadable: is not UTF-8; write it so the comment lexer can follow it")])

    def test_frozen_spec_keeps_its_docstrings_but_not_its_comments(self):
        repo = Repo(self)
        repo.commit({"tools/test_old.py": '"""Doc."""\n# why\n',
                     "tools/helper.py": '"""Doc."""\n',
                     "crates/containment-kernel/tests/k.rs": "/// doc\n// why\nfn f() {}\n"})
        repo.main_here()
        repo.commit({"tools/test_new.py": '"""Doc."""\n'})
        self.assertEqual(sorted(where(repo.check("NC-1"))),
                         [("crates/containment-kernel/tests/k.rs", 2), ("tools/helper.py", 1),
                          ("tools/test_new.py", 1), ("tools/test_old.py", 2)])

    def test_without_the_base_no_spec_is_frozen(self):
        repo = Repo(self)
        repo.commit({"tools/test_old.py": '"""Doc."""\n'})
        self.assertEqual(where(repo.check("NC-1")), [("tools/test_old.py", 1)])

    def test_a_malformed_debt_file_fails(self):
        repo = Repo(self)
        repo.commit({DEBT: "files = 3\n"})
        repo.main_here()
        self.assertEqual(where(repo.check("NC-1")), [(DEBT, 0)])


class DebtTests(unittest.TestCase):
    def test_the_list_may_shrink(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "b.py": "# b\n", DEBT: comments.debt_text(["a.py", "b.py"])})
        repo.main_here()
        repo.commit({"b.py": "x = 1\n", DEBT: comments.debt_text(["a.py"])})
        self.assertEqual(repo.check("NC-2"), [])

    def test_adding_a_file_fails(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "b.py": "x = 1\n", DEBT: comments.debt_text(["a.py"])})
        repo.main_here()
        repo.commit({"b.py": "# b\n", DEBT: comments.debt_text(["a.py", "b.py"])})
        found = repo.check("NC-2")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].message.startswith("b.py is not in"), found[0].message)

    def test_a_listed_file_without_comments_fails(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "b.py": "# b\n", DEBT: comments.debt_text(["a.py", "b.py"])})
        repo.main_here()
        repo.commit({"b.py": "x = 1\n"})
        found = repo.check("NC-2")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].message.startswith("b.py has no comments left"), found[0].message)

    def test_a_listed_file_that_is_gone_fails(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", DEBT: comments.debt_text(["a.py"])})
        repo.main_here()
        repo.commit({"a.py": None})
        self.assertEqual(len(repo.check("NC-2")), 1)

    def test_a_bootstrap_lists_only_files_that_had_comments(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "c.py": "x = 1\n"})
        repo.main_here()
        repo.commit({"c.py": "# c\n", DEBT: comments.debt_text(["a.py", "c.py"])})
        found = repo.check("NC-2")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].message.startswith("c.py had no comments at"), found[0].message)

    def test_an_uncommitted_first_list_is_judged_against_the_base(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "c.py": "x = 1\n"})
        repo.main_here()
        repo.write({"c.py": "# c\n", DEBT: comments.debt_text(["a.py", "c.py"])})
        found = repo.check("NC-2")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].message.startswith("c.py had no comments at"), found[0].message)

    def test_the_first_list_may_name_a_file_the_base_lacks(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n"})
        repo.main_here()
        repo.commit({"d.py": "# d\n", DEBT: comments.debt_text(["a.py", "d.py"])})
        self.assertEqual(repo.check("NC-2"), [])

    def test_once_committed_the_list_never_grows_even_before_main_has_it(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n"})
        repo.main_here()
        first = repo.commit({DEBT: comments.debt_text(["a.py"])})
        repo.commit({"e.py": "# e\n", DEBT: comments.debt_text(["a.py", "e.py"])})
        found = repo.check("NC-2")
        self.assertEqual([f.message.split(";")[0] for f in found], [f"e.py is not in {DEBT} at {first[:12]}"])

    def test_a_list_deleted_and_added_again_keeps_its_first_ceiling(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n"})
        repo.main_here()
        repo.commit({DEBT: comments.debt_text(["a.py"])})
        repo.commit({DEBT: None})
        repo.commit({"e.py": "# e\n", DEBT: comments.debt_text(["a.py", "e.py"])})
        self.assertEqual(len(repo.check("NC-2")), 1)

    def test_a_list_deleted_on_main_leaves_no_debt_at_all(self):
        repo = Repo(self)
        fork = repo.commit({"a.py": "# a\n", "b.py": "x = 1\n", DEBT: comments.debt_text(["a.py"])})
        repo.commit({DEBT: None})
        repo.main_here()
        git(repo.root, "checkout", "-q", "-b", "head", fork)
        repo.commit({"b.py": "# b\n", DEBT: comments.debt_text(["a.py", "b.py"])})
        self.assertEqual([f.message.split(";")[0] for f in repo.check("NC-2")],
                         [f"a.py is not in {DEBT} at origin/main, which deleted it",
                          f"b.py is not in {DEBT} at origin/main, which deleted it"])

    def test_a_missing_main_fails(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", DEBT: comments.debt_text(["a.py"])})
        found = repo.check("NC-2")
        self.assertEqual(len(found), 1)
        self.assertIn("origin/main is missing", found[0].message)


class CommandTests(unittest.TestCase):
    def test_listing_prints_each_span(self):
        repo = Repo(self)
        repo.commit({"a.py": "x = 1\n# why\n", "b.py": "x = 1\n"})
        repo.main_here()
        out = io.StringIO()
        self.assertEqual(comments.listing(repo.root, [], True, out=out), 0)
        self.assertEqual([json.loads(line) for line in out.getvalue().splitlines()],
                         [{"path": "a.py", "line": 2, "kind": "comment", "text": "# why"}])

    def test_listing_says_why_a_path_is_skipped(self):
        repo = Repo(self)
        repo.commit({"results/a.py": "# c\n", "notes.txt": "# c\n"})
        repo.main_here()
        err = io.StringIO()
        comments.listing(repo.root, ["results/a.py", "notes.txt", "gone.py"], False, out=io.StringIO(), err=err)
        lines = err.getvalue().splitlines()
        self.assertEqual([line.split()[1] for line in lines], ["results/a.py", "notes.txt", "gone.py"])
        self.assertIn("is data", lines[0])
        self.assertIn("no comment lexer", lines[1])
        self.assertIn("not a file", lines[2])

    def test_debt_write_creates_then_only_removes(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "b.py": "# b\n", "c.py": "x = 1\n", "results/d.py": "# d\n"})
        repo.main_here()
        comments.debt_write(repo.root, out=io.StringIO())
        self.assertEqual(comments.load_debt((repo.root / DEBT).read_text()), ["a.py", "b.py"])
        repo.commit({"b.py": "x = 1\n", "c.py": "# c\n"})
        comments.debt_write(repo.root, out=io.StringIO())
        self.assertEqual(comments.load_debt((repo.root / DEBT).read_text()), ["a.py"])

    def test_debt_write_refuses_a_symlink_in_place_of_the_list(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n"})
        outside = repo.root / "outside.toml"
        outside.write_text("files = []\n", encoding="utf-8")
        link = repo.root / DEBT
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)
        out = io.StringIO()
        self.assertEqual(comments.debt_write(repo.root, out=out), 1)
        self.assertEqual(outside.read_text(encoding="utf-8"), "files = []\n")
        self.assertIn("symbolic link", out.getvalue())

    def test_debt_write_refuses_while_a_listed_file_cannot_be_read(self):
        repo = Repo(self)
        repo.commit({"a.py": "# a\n", "b.py": "# b\n", DEBT: comments.debt_text(["a.py", "b.py"])})
        repo.main_here()
        repo.commit({"b.py": "def (:\n"})
        out = io.StringIO()
        self.assertEqual(comments.debt_write(repo.root, out=out), 1)
        self.assertEqual(comments.load_debt((repo.root / DEBT).read_text(encoding="utf-8")), ["a.py", "b.py"])
        self.assertIn("b.py:1", out.getvalue())

    def test_the_debt_file_has_no_comments_of_its_own(self):
        text = comments.debt_text(["b.py", "a.py", "a.py"])
        self.assertEqual(comments.comment_spans(DEBT, text), [])
        self.assertEqual(comments.load_debt(text), ["a.py", "b.py"])

    def test_the_debt_file_round_trips_an_awkward_path(self):
        paths = ["notes-\U0001f600.py", 'odd"name.py', "back\\slash.py", "hash#.py", "café.py"]
        text = comments.debt_text(paths)
        self.assertEqual(comments.load_debt(text), sorted(paths))
        self.assertEqual(comments.comment_spans(DEBT, text), [])

    def test_vac_comments_runs_from_the_command_line(self):
        fixture = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fixture)
        (fixture / "a.sh").write_text("echo hi # c\n", encoding="utf-8")
        child = subprocess.run([sys.executable, str(ROOT / "tools/vac.py"), "comments", "--json",
                                "tools/vac_comments.py", "tools/test_vac_comments.py", str(fixture / "a.sh")],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual((child.returncode, child.stderr), (0, ""))
        self.assertEqual([json.loads(line) for line in child.stdout.splitlines()],
                         [{"path": (fixture / "a.sh").as_posix(), "line": 1, "kind": "comment", "text": "# c"}])

    def test_debt_write_takes_no_path(self):
        child = subprocess.run([sys.executable, str(ROOT / "tools/vac.py"), "comments", "--debt-write", "a.py"],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(child.returncode, 2)


class RegistryTests(unittest.TestCase):
    def test_both_rules_run_at_every_stage_on_every_path(self):
        rules = {r.id: r for r in registry.RULES}
        for rule_id in ("NC-1", "NC-2"):
            with self.subTest(rule=rule_id):
                self.assertEqual(rules[rule_id].stages, frozenset(core.STAGES))
                self.assertEqual(rules[rule_id].watches, ("**",))
                self.assertIn(209, rules[rule_id].refs)


if __name__ == "__main__":
    unittest.main()

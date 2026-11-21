#!/usr/bin/env python3
"""Unit tests for tools/rust_tokens.py: one group per Rust literal and comment form,
plus the property the checks rely on: layout never changes the code tokens."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_tokens as rt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def kinds(src):
    return [(t.kind, t.text) for t in rt.tokenize(src)]


class CommentTests(unittest.TestCase):
    def test_line_and_block_comments(self):
        self.assertEqual(kinds("a // x\nb /* y */ c"),
                         [("ident", "a"), ("comment", "// x"), ("ident", "b"), ("comment", "/* y */"), ("ident", "c")])

    def test_nested_block_comment(self):
        self.assertEqual(kinds("/* a /* b */ c */ x"), [("comment", "/* a /* b */ c */"), ("ident", "x")])

    def test_doc_comments_are_their_own_kind(self):
        # Doc comments become #[doc] attributes and doctests run them, so they are code.
        for src in ["/// outer", "//! inner", "/** outer */", "/*! inner */"]:
            with self.subTest(src=src):
                self.assertEqual(kinds(src), [("doc", src)])

    def test_four_slashes_and_empty_block_are_plain_comments(self):
        for src in ["//// not doc", "/**/", "/*** not doc */"]:
            with self.subTest(src=src):
                self.assertEqual(kinds(src), [("comment", src)])

    def test_unterminated_block_comment_is_an_error(self):
        with self.assertRaises(rt.LexError):
            rt.tokenize("/* a /* b */")


class StringTests(unittest.TestCase):
    def test_comment_markers_inside_strings(self):
        self.assertEqual(kinds('"a // b /* c"'), [("str", '"a // b /* c"')])

    def test_escapes(self):
        self.assertEqual(kinds(r'"a \" b \\" x'), [("str", r'"a \" b \\"'), ("ident", "x")])

    def test_byte_and_c_strings(self):
        self.assertEqual(kinds('b"x" c"y"'), [("str", 'b"x"'), ("str", 'c"y"')])

    def test_raw_strings_with_hashes(self):
        self.assertEqual(kinds('r"a\\" x'), [("str", 'r"a\\"'), ("ident", "x")])
        self.assertEqual(kinds('r#"a "b" // c"# x'), [("str", 'r#"a "b" // c"#'), ("ident", "x")])
        self.assertEqual(kinds('br##"a"#b"## x'), [("str", 'br##"a"#b"##'), ("ident", "x")])

    def test_raw_identifier_is_not_a_raw_string(self):
        self.assertEqual(kinds("r#type"), [("ident", "r#type")])

    def test_multi_line_string(self):
        self.assertEqual(kinds('"a\nb"'), [("str", '"a\nb"')])

    def test_unterminated_strings_are_errors(self):
        for src in ['"abc', 'r#"abc"', 'b"abc']:
            with self.subTest(src=src), self.assertRaises(rt.LexError):
                rt.tokenize(src)

    def test_string_value(self):
        self.assertEqual(rt.string_value(rt.tokenize('"canary_exfil"')[0]), "canary_exfil")
        self.assertIsNone(rt.string_value(rt.tokenize('b"x"')[0]))
        self.assertIsNone(rt.string_value(rt.tokenize('"a\\n"')[0]))


class CharAndLifetimeTests(unittest.TestCase):
    def test_chars(self):
        for src in ["'a'", "'\"'", "'\\''", "'\\n'", "'\\x7f'", "'\\u{1F600}'", "'\\u{0_0_4_1}'", "b'x'", "'é'"]:
            with self.subTest(src=src):
                self.assertEqual(kinds(src), [("char", src)])

    def test_lifetimes_and_labels(self):
        self.assertEqual(kinds("&'a str"), [("punct", "&"), ("lifetime", "'a"), ("ident", "str")])
        self.assertEqual(kinds("'static"), [("lifetime", "'static")])
        self.assertEqual(kinds("'outer: loop"), [("lifetime", "'outer"), ("punct", ":"), ("ident", "loop")])

    def test_malformed_chars_are_errors(self):
        for src in ["'\\u{41'", "'\\x7'", "''"]:
            with self.subTest(src=src), self.assertRaises(rt.LexError):
                rt.tokenize(src)


class NumberAndPunctTests(unittest.TestCase):
    def test_numbers(self):
        for src in ["0", "1_000", "0xff_u8", "1.5e-3", "2f64", "0b1010"]:
            with self.subTest(src=src):
                self.assertEqual(kinds(src), [("number", src)])

    def test_range_is_not_a_float(self):
        self.assertEqual(kinds("1..2"), [("number", "1"), ("punct", ".."), ("number", "2")])

    def test_multi_char_punctuation(self):
        self.assertEqual([t.text for t in rt.tokenize("a::b -> c => d ..= e != f <<= g")],
                         ["a", "::", "b", "->", "c", "=>", "d", "..=", "e", "!=", "f", "<<=", "g"])

    def test_adjacent_tokens_stay_distinct(self):
        self.assertNotEqual(rt.code_tokens("a b"), rt.code_tokens("ab"))


class LayoutInvarianceTests(unittest.TestCase):
    def test_code_tokens_ignore_layout_and_plain_comments(self):
        a = 'const X: &[(&str, &str)] = &[("a", "b"), ("c", "d")];'
        b = 'const X: &[(&str, &str)] = &[\n    // note\n    (\n        "a",\n        "b",\n    ),\n    ("c", /* x */ "d"),\n];'
        self.assertEqual(rt.code_tokens(a), rt.code_tokens(b))

    def test_one_element_tuple_comma_is_kept(self):
        self.assertNotEqual(rt.code_tokens("let t = (x,);"), rt.code_tokens("let t = (x);"))
        self.assertNotEqual(rt.code_tokens("let (a,) = t;"), rt.code_tokens("let (a) = t;"))
        self.assertNotEqual(rt.code_tokens("fn f() -> (u8,) {}"), rt.code_tokens("fn f() -> (u8) {}"))

    def test_a_comparison_before_a_tuple_keeps_the_tuple_comma(self):
        # `>` may be a comparison, not the end of generic arguments.
        self.assertNotEqual(rt.code_tokens("a > (b,)"), rt.code_tokens("a > (b)"))

    def test_layout_commas_are_dropped(self):
        for split, flat in [("f(\n    long_argument,\n)", "f(long_argument)"),
                            ("[\n    a,\n]", "[a]"),
                            ("(a, b,)", "(a, b)"),
                            ("S { a: 1, }", "S { a: 1 }")]:
            with self.subTest(flat=flat):
                self.assertEqual(rt.code_tokens(split), rt.code_tokens(flat))

    def test_commas_inside_macro_invocations_are_kept(self):
        # A macro matcher can tell `m!(x,)` from `m!(x)`, so neither may stand for the other.
        for with_comma, without in [("m!(x,)", "m!(x)"), ("v![a, b,]", "v![a, b]"),
                                    ("m!{ (a,) }", "m!{ (a) }"), ('("n", pick!(x,))', '("n", pick!(x))')]:
            with self.subTest(without=without):
                self.assertNotEqual(rt.code_tokens(with_comma), rt.code_tokens(without))

    def test_code_tokens_keep_doc_comments(self):
        self.assertNotEqual(rt.code_tokens("/// one\nfn f() {}"), rt.code_tokens("/// two\nfn f() {}"))

    def test_every_rust_file_in_the_repository_lexes(self):
        files = sorted((ROOT / "crates").rglob("*.rs"))
        self.assertTrue(files)
        for path in files:
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                tokens = rt.tokenize(path.read_text(encoding="utf-8"))
                self.assertTrue(tokens)


class ConstArrayTests(unittest.TestCase):
    SRC = ('// const SABOTAGE: not this one\n'
           'const SABOTAGE: &[(&str, &str, &[&str])] = &[\n'
           '    ("first", "s1", &["c1"]), /* ("ghost", "x", &[]) */\n'
           '    (\n        "second",\n        "s2",\n        &["c2", "c3"],\n    ),\n'
           '];\n')

    def test_entries_are_found_by_tokens(self):
        entries = rt.const_array_entries(self.SRC, "SABOTAGE")
        self.assertEqual([rt.string_value(e[1]) for e in entries], ["first", "second"])

    def test_entry_keys_ignore_layout_and_trailing_commas(self):
        flat = 'const SABOTAGE: &[(&str, &str, &[&str])] = &[("first", "s1", &["c1"]), ("second", "s2", &["c2", "c3"])];'
        self.assertEqual([rt.entry_key(e) for e in rt.const_array_entries(self.SRC, "SABOTAGE")],
                         [rt.entry_key(e) for e in rt.const_array_entries(flat, "SABOTAGE")])

    def test_entry_key_changes_with_any_field(self):
        other = self.SRC.replace('"s2"', '"s9"')
        self.assertNotEqual(rt.entry_key(rt.const_array_entries(self.SRC, "SABOTAGE")[1]),
                            rt.entry_key(rt.const_array_entries(other, "SABOTAGE")[1]))

    def test_missing_repeated_unclosed_are_errors(self):
        for src in ["const OTHER: &[&str] = &[\"a\"];", self.SRC + self.SRC, 'const SABOTAGE: &[&str] = &["a",']:
            with self.subTest(src=src[:30]), self.assertRaises(rt.LexError):
                rt.const_array_entries(src, "SABOTAGE")


def _exact(src):
    """Every token except plain comments, trailing commas included."""
    return [(t.kind, t.text) for t in rt.tokenize(src) if t.kind != "comment"]


class SpliceTests(unittest.TestCase):
    """splice_once: the Rust mutant matcher (#61, step 3)."""

    def assertSplices(self, src, old, new, expected):
        # Exact tokens, commas included: code_tokens would let an invalid `{ x, }` pass.
        self.assertEqual(_exact(rt.splice_once(src, old, new)), _exact(expected))

    def test_reflowed_list_with_trailing_comma(self):
        self.assertSplices("const P: &[A] = &[\n    A::X,\n    A::Y,\n];",
                           "const P: &[A] = &[A::X, A::Y];", "const P: &[A] = &[];", "const P: &[A] = &[];")

    def test_pattern_ending_inside_a_list(self):
        self.assertSplices("const P: &[A] = &[A::X, A::Y, A::Z];", "    A::Y,\n    A::Z,\n];", "    A::Y,\n];",
                           "const P: &[A] = &[A::X, A::Y,];")

    def test_arm_body_wrapped_in_a_block(self):
        src = "match m {\n    M::A => {\n        f(x)\n    }\n    M::B => g,\n}"
        self.assertSplices(src, "M::A => f(x),\n    M::B => g,", "M::A | M::B => g,", "match m { M::A | M::B => g, }")
        self.assertSplices(src, "M::B => g,", "M::B => h,", "match m { M::A => { f(x) } M::B => h, }")

    def test_last_arm_wrapped_in_a_block(self):
        src = "match m { M::A => f(x), M::B => {\n    g\n} }"
        self.assertSplices(src, "M::A => f(x),\n    M::B => g,", "M::A | M::B => g,", "match m { M::A | M::B => g, }")

    def test_a_match_inside_a_block_keeps_its_braces(self):
        self.assertSplices("match m { M::A => {\n    a && b\n} M::B => c, }", "a && b", "b",
                           "match m { M::A => { b } M::B => c, }")

    def test_a_block_with_a_statement_is_not_unwrapped(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once("match m { M::A => { f(); g } }", "M::A => g,", "M::A => h,")

    def test_cutting_an_arm_block_apart_is_an_error(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once("match m { M::A => { f(x) } M::B => y, }", "M::A => f", "M::A => g")

    def test_comments_and_whitespace_are_ignored(self):
        self.assertSplices("f(a /* note */,\n  // more\n  b)", "f(a, b)", "f(b, a)", "f(b, a)")

    def test_bytes_outside_the_match_are_kept(self):
        src = "// head\nlet a = x + 1;   // tail\n"
        self.assertEqual(rt.splice_once(src, "x + 1", "x - 1"), "// head\nlet a = x - 1;   // tail\n")

    def test_a_trailing_comma_must_end_the_matched_expression(self):
        # `A => b,` must not match the front of `A => b.c(),`.
        with self.assertRaises(rt.MatchError):
            rt.splice_once("match m { A => b.c(), }", "A => b,", "A => d,")

    def test_no_match_and_two_matches_are_errors(self):
        for src in ["let a = y + 1;", "let a = x + 1; let b = x + 1;"]:
            with self.subTest(src=src), self.assertRaises(rt.MatchError):
                rt.splice_once(src, "x + 1", "x - 1")

    def test_string_contents_are_compared_exactly(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once('f("a b")', 'f("a  b")', 'f("")')

    def test_macro_bodies_are_not_unwrapped(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once("m! { (a) => { b } }", "(a) => b", "(a) => c")

    def test_a_trailing_comma_needs_a_list_around_it(self):
        # A block tail, a parenthesised expression or an index is not a list: `x,` must not
        # match there, or a mutant could land on a lookalike (review of #66).
        for src, old in [("fn stop() { revoke(); kill() }", "kill(),"), ("let v = (x);", "x,"),
                         ("let v = a[x];", "x,"), ("fn f() { x }", "x, }")]:
            with self.subTest(src=src), self.assertRaises(rt.MatchError):
                rt.splice_once(src, old, "y,")

    def test_a_trailing_comma_matches_where_rustfmt_drops_one(self):
        self.assertSplices("f(a, kill())", "kill(),", "k(),", "f(a, k(),)")
        self.assertSplices("g(kill())", "kill(),", "k(),", "g(k(),)")
        self.assertSplices("let v = &[kill()];", "kill(),", "k(),", "let v = &[k(),];")

    WRAPPED = "match m { M::R => {\n    a && b\n}\nM::H => c, }"

    def test_taking_in_a_wrapped_arm_puts_its_comma_back(self):
        self.assertSplices(self.WRAPPED, "M::R => a && b", "M::R => b", "match m { M::R => b, M::H => c, }")

    def test_a_whole_arm_body_with_its_comma_takes_in_the_braces(self):
        self.assertSplices(self.WRAPPED, "a && b,", "b,", "match m { M::R => b, M::H => c, }")

    def test_macro_rules_bodies_are_not_unwrapped(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once("macro_rules! m { (a) => { b }; }", "(a) => b", "(a) => c")

    def test_empty_pattern_is_an_error(self):
        with self.assertRaises(rt.MatchError):
            rt.splice_once("let a = 1;", "  // nothing\n", "x")


def _token_change(before, after):
    """The canonical tokens removed and inserted between two versions of a file."""
    a = [(t.kind, t.text) for t in rt._canonical(rt.tokenize(before))[0]]
    b = [(t.kind, t.text) for t in rt._canonical(rt.tokenize(after))[0]]
    head = 0
    while head < min(len(a), len(b)) and a[head] == b[head]:
        head += 1
    tail = 0
    while tail < min(len(a), len(b)) - head and a[-1 - tail] == b[-1 - tail]:
        tail += 1
    return a[head:len(a) - tail], b[head:len(b) - tail]


class KernelMutantTests(unittest.TestCase):
    """Every Rust mutant matches the kernel once, before and after rustfmt."""

    LIB = ROOT / "crates/containment-kernel/src/lib.rs"

    @classmethod
    def setUpClass(cls):
        import kernel_mutants
        cls.mutants = kernel_mutants.RUST_MUTANTS
        cls.lib = cls.LIB.read_text(encoding="utf-8")

    def test_every_mutant_makes_the_same_edit_as_the_byte_replacement(self):
        self.assertTrue(self.mutants)
        for name, old, new in self.mutants:
            with self.subTest(mutant=name):
                self.assertEqual(_exact(rt.splice_once(self.lib, old, new)),
                                 _exact(self.lib.replace(old, new, 1)))

    def _rustfmt(self, max_width, text=None):
        """lib.rs (or text) formatted by the rustfmt of the toolchain rust-toolchain.toml
        pins, with the repository's rustfmt.toml guard bypassed. A parse error fails the
        test. Skipped locally when rustfmt is missing; in CI that is a failure, so this
        test can never pass by not running."""
        import os
        import re
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("rustfmt"):
            if os.environ.get("CI") == "true":
                self.fail("rustfmt is missing in CI")
            self.skipTest("rustfmt is not installed")
        edition = re.search(r'^edition = "(\d+)"', (ROOT / "Cargo.toml").read_text(encoding="utf-8"), re.M).group(1)
        channel = re.search(r'^channel = "([^"]+)"', (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"), re.M).group(1)
        with tempfile.TemporaryDirectory() as tmp:
            config, target = Path(tmp) / "rustfmt.toml", Path(tmp) / "lib.rs"
            config.write_text(f'edition = "{edition}"\n' + (f"max_width = {max_width}\n" if max_width else ""))
            target.write_bytes((self.lib if text is None else text).encode("utf-8"))
            run = subprocess.run(["rustfmt", f"+{channel}", "--config-path", str(config), str(target)],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr[-2000:])
            return target.read_text(encoding="utf-8")

    def test_every_mutant_survives_rustfmt(self):
        for max_width in (None, 40):
            formatted = self._rustfmt(max_width)
            # Not vacuous: rustfmt really rewrote the file.
            self.assertNotEqual(formatted, self.lib)
            for name, old, new in self.mutants:
                with self.subTest(max_width=max_width, mutant=name):
                    mutated = rt.splice_once(formatted, old, new)
                    self.assertEqual(_token_change(formatted, mutated),
                                     _token_change(self.lib, self.lib.replace(old, new, 1)))
                    self._rustfmt(max_width, mutated)  # the mutant still parses


class MutationCheckTests(unittest.TestCase):
    def test_importing_does_not_run_the_check(self):
        import mutation_check
        self.assertTrue(callable(mutation_check.main))

    def test_a_missing_target_names_the_mutant(self):
        import mutation_check
        with self.assertRaises(SystemExit) as ctx:
            mutation_check.rust_mutant("fn f() {}", "lost", "x + 1", "x - 1")
        self.assertIn("lost", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

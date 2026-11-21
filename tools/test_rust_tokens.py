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

    def test_layout_commas_are_dropped(self):
        for split, flat in [("f(\n    long_argument,\n)", "f(long_argument)"),
                            ("[\n    a,\n]", "[a]"),
                            ("(a, b,)", "(a, b)"),
                            ("m!(\n    x,\n)", "m!(x)"),
                            ("S { a: 1, }", "S { a: 1 }")]:
            with self.subTest(flat=flat):
                self.assertEqual(rt.code_tokens(split), rt.code_tokens(flat))

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


if __name__ == "__main__":
    unittest.main()

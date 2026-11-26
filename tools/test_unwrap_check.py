"""Unit tests for tools/unwrap_check.py (RS-UNWRAP)."""
import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rust_tokens  # noqa: E402
import unwrap_check as u  # noqa: E402

ROOT = HERE.parent


def calls(src):
    return [(item, call, message) for _, item, call, message in u.sites(src)]


class Sites(unittest.TestCase):
    def test_comments_strings_and_docs_do_not_count(self):
        src = '''
/// let x = y.unwrap();
fn f() {
    // a.unwrap()
    /* b.expect("x") */
    let s = "c.unwrap()";
    let r = r#"d.expect("y")"#;
}
'''
        self.assertEqual(calls(src), [])

    def test_method_calls_and_paths_count(self):
        src = '''
fn f(a: Option<u8>, b: Result<u8, ()>) {
    let x = a.unwrap();
    let y = b.expect("why");
    let z = b.unwrap_err();
    let w = b.expect_err(MSG);
    let v: Vec<u8> = vec![a].into_iter().map(Option::unwrap).collect();
    let t = a.unwrap::<>();
}
'''
        self.assertEqual(calls(src), [
            ("fn f", "unwrap", ""), ("fn f", "expect", "why"), ("fn f", "unwrap_err", ""),
            ("fn f", "expect_err", ""), ("fn f", "unwrap", ""), ("fn f", "unwrap", "")])

    def test_fields_and_lookalikes_do_not_count(self):
        src = '''
fn f(task: Task, a: Option<u8>) -> bool {
    task.expect == "complete" && a.unwrap_or(0) == 1 && a.unwrap_or_default() == 0
}
fn unwrap() {}
'''
        self.assertEqual(calls(src), [])

    def test_test_and_proof_code_is_exempt(self):
        src = '''
fn live(a: Option<u8>) -> u8 { a.unwrap() }
#[cfg(test)]
mod tests {
    fn helper(a: Option<u8>) -> u8 { a.unwrap() }
    #[test]
    fn t() { Some(1).expect("x"); }
}
#[test]
fn loose() { Some(1).unwrap(); }
#[cfg(kani)]
mod proofs { fn p() { Some(1).unwrap(); } }
#[cfg(all(test, feature = "x"))]
fn both() { Some(1).unwrap(); }
fn after(a: Option<u8>) -> u8 { a.expect("counted") }
'''
        self.assertEqual(calls(src), [("fn live", "unwrap", ""), ("fn after", "expect", "counted")])

    def test_non_test_cfgs_still_count(self):
        src = '''
#[cfg(feature = "sabotage")]
fn s() { Some(1).unwrap(); }
#[cfg(any(test, feature = "x"))]
fn a() { Some(1).unwrap(); }
#[cfg(not(test))]
fn n() { Some(1).unwrap(); }
#[cfg(target_arch = "aarch64")]
fn arm() { Some(1).unwrap(); }
'''
        self.assertEqual([item for item, _, _ in calls(src)], ["fn s", "fn a", "fn n", "fn arm"])

    def test_a_test_attribute_on_a_statement_exempts_only_that_statement(self):
        src = '''
fn f(a: Option<u8>) {
    #[cfg(test)]
    let x = a.unwrap();
    let y = a.unwrap();
}
'''
        self.assertEqual(calls(src), [("fn f", "unwrap", "")])

    def test_inner_test_attribute_exempts_the_file(self):
        self.assertEqual(calls("#![cfg(test)]\nfn f() { Some(1).unwrap(); }\n"), [])

    def test_items_are_named_by_path(self):
        src = '''
mod m {
    impl<T: Clone> Drop for Holder<T> where T: Copy {
        fn drop(&mut self) { self.0.lock().expect("lock"); }
    }
    fn g() -> impl Iterator<Item = u8> { std::iter::once(Some(1).unwrap()) }
}
fn macro_body() { let v = json!({ "x": y.unwrap() }); }
'''
        self.assertEqual(calls(src), [
            ("mod m::impl Drop for Holder::fn drop", "expect", "lock"),
            ("mod m::fn g", "unwrap", ""), ("fn macro_body", "unwrap", "")])

    def test_layout_does_not_change_the_sites(self):
        a = 'fn f(a: Option<u8>) -> u8 { a.expect("x") }'
        b = 'fn f(\n    a: Option<u8>,\n) -> u8 {\n    a\n        .expect(\n            "x",\n        )\n}\n'
        self.assertEqual(calls(a), [("fn f", "expect", "x")])
        self.assertEqual(calls(a), calls(b))

    def test_unreadable_source_is_an_error(self):
        with self.assertRaises(rust_tokens.LexError):
            u.sites('fn f() { let s = "unterminated; }')
        with self.assertRaises(rust_tokens.LexError):
            u.sites("fn f() { (] }")


class Ratchet(unittest.TestCase):
    """The rule on a copy of the real tree: today it passes, a seeded site fails it,
    and a removed site makes the list stale until --update shrinks it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(ROOT / u.HOST_SRC, self.root / u.HOST_SRC)
        (self.root / "ci").mkdir()
        shutil.copy(ROOT / u.DEBT, self.root / u.DEBT)

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return u.main(["unwrap_check.py", *args, str(self.root)])

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, old)
        path.write_text(text.replace(old, new), encoding="utf-8")

    def test_the_tree_passes_today(self):
        self.assertEqual(self.run_check(), 0)

    def test_a_seeded_unwrap_on_agent_input_fails(self):
        # The gateway's request handler: the body is what the agent sent.
        gateway = u.HOST_SRC + "/controller/gateway.rs"
        text = (self.root / gateway).read_text(encoding="utf-8")
        fn = text.index("fn gateway_decide")
        body = text.index("{", fn) + 1
        (self.root / gateway).write_text(
            text[:body] + "\n    let _seeded: u8 = \"7\".parse().unwrap();" + text[body:], encoding="utf-8")
        self.assertEqual(self.run_check(), 1)
        self.assertEqual(self.run_check("--update"), 1)

    def test_moving_a_site_to_another_item_fails(self):
        common = u.HOST_SRC + "/common.rs"
        self.edit(common, '.expect("HMAC accepts any key length")', '.unwrap()')
        self.assertEqual(self.run_check(), 1)

    def test_a_removed_site_must_be_shrunk_from_the_list(self):
        common = u.HOST_SRC + "/common.rs"
        self.edit(common, '.expect("HMAC accepts any key length")', '.unwrap_or_else(|_| unreachable!())')
        self.assertEqual(self.run_check(), 1)
        before = (self.root / u.DEBT).read_text(encoding="utf-8")
        self.assertEqual(self.run_check("--update"), 0)
        after = (self.root / u.DEBT).read_text(encoding="utf-8")
        self.assertIn("HMAC accepts any key length", before)
        self.assertNotIn("HMAC accepts any key length", after)
        self.assertEqual(self.run_check(), 0)

    def test_the_list_is_what_update_would_write(self):
        text = (ROOT / u.DEBT).read_text(encoding="utf-8")
        self.assertEqual(u.render_debt(u.load_debt(ROOT)), text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for tools/claims_check.py."""
import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims_check as cc


class PathMatchingTests(unittest.TestCase):
    def test_exact_file_does_not_match_submodule_directory(self):
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller.rs", "crates/containment-host/src/controller.rs"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller.rs"))

    def test_directory_prefix_matches_children_only(self):
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller"))
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller/"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller.rs", "crates/containment-host/src/controller"))

    def test_single_star_stays_within_directory(self):
        pat = "crates/containment-host/src/*.rs"
        self.assertTrue(cc.path_matches("crates/containment-host/src/main.rs", pat))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/gateway.rs", pat))

    def test_doublestar_matches_zero_or_more_directories(self):
        pat = "crates/containment-host/src/**/*.rs"
        self.assertTrue(cc.path_matches("crates/containment-host/src/main.rs", pat))
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", pat))
        self.assertTrue(cc.path_matches("crates/containment-host/src/a/b/c.rs", pat))
        self.assertFalse(cc.path_matches("crates/containment-host/src/hud.html", pat))

    def test_question_and_character_classes(self):
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/reset.rs", "crates/containment-host/src/controller/?????.rs"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/enforcer.rs", "crates/containment-host/src/controller/?????.rs"))
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller/[eg]*.rs"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/reset.rs", "crates/containment-host/src/controller/[eg]*.rs"))
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller/[!r]*.rs"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/reset.rs", "crates/containment-host/src/controller/[!r]*.rs"))
        self.assertTrue(cc.path_matches("crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/controller/[^r]*.rs"))
        self.assertFalse(cc.path_matches("crates/containment-host/src/controller/reset.rs", "crates/containment-host/src/controller/[^r]*.rs"))

    def test_ci7_uncovered_sources_accepts_globs(self):
        claims = [{"id": "X-1", "files": ["crates/containment-host/src/**/*.rs"]}]
        tracked = [
            "crates/containment-host/src/main.rs",
            "crates/containment-host/src/controller/gateway.rs",
            "crates/containment-host/src/hud.html",
        ]
        self.assertEqual(cc.uncovered_sources(claims, tracked=tracked), ["crates/containment-host/src/hud.html"])


class BuildStampAndFullRunTests(unittest.TestCase):
    def _write_suites(self, root: Path, attack_overrides=None, live_overrides=None):
        h1 = "a" * 64
        h2 = "b" * 64
        attack = {
            "build": {
                "honest": {"sabotage": False, "binary_sha256": h1},
                "sabotage": {"sabotage": True, "binary_sha256": h2},
            },
            "timed_repeat": 30,
            "cgroup_limits_waived": False,
            "controls_cgroup_limits_waived": False,
        }
        live = {
            "build": {
                "honest": {"sabotage": False, "binary_sha256": h1},
                "sabotage": {"sabotage": True, "binary_sha256": h2},
            },
        }
        if attack_overrides:
            attack.update(attack_overrides)
        if live_overrides:
            live.update(live_overrides)
        (root / "attack-suite.json").write_text(json.dumps(attack), encoding="utf-8")
        (root / "live-suite.json").write_text(json.dumps(live), encoding="utf-8")

    def test_valid_full_unwaived_suites_pass(self):
        with tempfile.TemporaryDirectory() as td:
            self._write_suites(Path(td))
            self.assertEqual(cc.build_errors(Path(td)), [])

    def test_rejects_short_repeat_and_bool_repeat(self):
        for bad_repeat in (1, 29, True, None):
            with tempfile.TemporaryDirectory() as td:
                self._write_suites(Path(td), attack_overrides={"timed_repeat": bad_repeat})
                errs = cc.build_errors(Path(td))
                self.assertTrue(any("timed_repeat" in e for e in errs), f"repeat={bad_repeat!r}: {errs}")

    def test_rejects_waived_limits(self):
        for key in ("cgroup_limits_waived", "controls_cgroup_limits_waived"):
            with tempfile.TemporaryDirectory() as td:
                self._write_suites(Path(td), attack_overrides={key: True})
                errs = cc.build_errors(Path(td))
                self.assertTrue(any(key in e for e in errs), f"{key}: {errs}")

    def test_rejects_same_binary_or_non_string_hash(self):
        same = "c" * 64
        with tempfile.TemporaryDirectory() as td:
            self._write_suites(
                Path(td),
                live_overrides={"build": {"honest": {"sabotage": False, "binary_sha256": same}, "sabotage": {"sabotage": True, "binary_sha256": same}}},
            )
            errs = cc.build_errors(Path(td))
            self.assertTrue(any("same binary" in e for e in errs), errs)

        with tempfile.TemporaryDirectory() as td:
            self._write_suites(
                Path(td),
                live_overrides={"build": {"honest": {"sabotage": False, "binary_sha256": 12345}, "sabotage": {"sabotage": True, "binary_sha256": same}}},
            )
            errs = cc.build_errors(Path(td))
            self.assertTrue(any("no SHA-256" in e for e in errs), errs)


class ProvenanceTests(unittest.TestCase):
    TRACKED = ["results/wsl2/lab-cd7172f/attack-suite.json", "results/linux-vm/attack-suite-d81a32e.json"]

    def claim(self, commit, result="pass"):
        return [{"id": "H-X", "platforms": [{"name": "wsl2", "commit": commit, "result": result}]}]

    def test_passing_platform_with_artifacts_is_accepted(self):
        self.assertEqual(cc.provenance_errors(self.claim("cd7172f"), self.TRACKED), [])
        self.assertEqual(cc.provenance_errors(self.claim("d81a32e", "pass (note)"), self.TRACKED), [])

    def test_passing_platform_at_an_unused_commit_fails(self):
        errs = cc.provenance_errors(self.claim("abc1234"), self.TRACKED)
        self.assertTrue(any("CI-9 H-X" in e and "abc1234" in e for e in errs), errs)

    def test_passing_platform_needs_a_commit_id(self):
        self.assertTrue(cc.provenance_errors(self.claim("HEAD"), self.TRACKED))
        self.assertTrue(cc.provenance_errors(self.claim(""), self.TRACKED))

    def test_failed_platform_needs_no_artifacts(self):
        self.assertEqual(cc.provenance_errors(self.claim("abc1234", "fail: reason"), self.TRACKED), [])

    def test_unlistable_results_is_an_error_not_a_pass(self):
        self.assertTrue(cc.provenance_errors(self.claim("cd7172f"), []))

    def test_repository_claims_have_provenance(self):
        claims = tomllib.loads((cc.ROOT / "claims.toml").read_text(encoding="utf-8"))["claim"]
        self.assertEqual(cc.provenance_errors(claims), [])


class NarrowedClaimsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claims = tomllib.loads((cc.ROOT / "claims.toml").read_text(encoding="utf-8"))["claim"]

    def test_every_tracked_host_source_is_covered(self):
        self.assertEqual(cc.uncovered_sources(self.claims), [])

    def test_narrowed_mapping_limits_blast_radius(self):
        hud_ids = {h["id"] for h in cc.affected_claims(self.claims, ["crates/containment-host/src/hud.rs"])}
        self.assertEqual(hud_ids, {"L-OPS-05"})

        diff_hits = cc.affected_claims(self.claims, ["crates/containment-host/src/differential.rs"])
        self.assertEqual({h["id"] for h in diff_hits}, {"R-DIFF-01"})
        self.assertTrue(all(not h["needs_lab"] for h in diff_hits))

        enforcer_ids = {h["id"] for h in cc.affected_claims(self.claims, ["crates/containment-host/src/controller/enforcer.rs"])}
        self.assertIn("H-ACT-01", enforcer_ids)
        self.assertNotIn("H-CTL-02", enforcer_ids)
        self.assertNotIn("H-LIVE-01", enforcer_ids)
        self.assertNotIn("H-CLS-01", enforcer_ids)

        gateway_ids = {h["id"] for h in cc.affected_claims(self.claims, ["crates/containment-host/src/controller/gateway.rs"])}
        self.assertIn("H-GW-01", gateway_ids)
        self.assertIn("H-LIVE-01", gateway_ids)
        self.assertNotIn("H-ACT-01", gateway_ids)
        self.assertNotIn("H-CTL-02", gateway_ids)
        self.assertNotIn("H-LEASE-01", gateway_ids)


class SuiteInventoryTests(unittest.TestCase):
    """CI-2 reads scenario and sabotage names out of harness.rs and live_suite.rs.
    The names must not depend on line layout, and a block that yields no names,
    or an entry that yields no name, is an error rather than an empty inventory
    (an empty inventory makes "every control is cited" pass vacuously)."""

    ONE_LINE = '''
const SABOTAGE: &[(&str, &str, &str, &[&str])] = &[
    ("live_canary_unchecked", "canary_exfil", "canary_never_reached_any_upstream", &["canary_found_in_workspace"]),
    ("live_write_unchecked", "write_to_read_host", "read_host_got_no_write", &["write_was_attempted"]),
];
'''
    # The same block as `cargo fmt` lays it out: one field per line, trailing commas.
    REFLOWED = '''
const SABOTAGE: &[(&str, &str, &str, &[&str])] = &[
    (
        "live_canary_unchecked",
        "canary_exfil",
        "canary_never_reached_any_upstream",
        &["canary_found_in_workspace"],
    ),
    (
        "live_write_unchecked",
        "write_to_read_host",
        "read_host_got_no_write",
        &["write_was_attempted"],
    ),
];
'''
    NAMES = ["live_canary_unchecked", "live_write_unchecked"]

    def names(self, src, const="SABOTAGE"):
        return cc.const_array_names(src, const, "fixture.rs")

    def test_one_line_tuples(self):
        self.assertEqual(self.names(self.ONE_LINE), self.NAMES)

    def test_reflowed_tuples_give_the_same_names(self):
        self.assertEqual(self.names(self.REFLOWED), self.NAMES)

    def test_the_old_layout_bound_regex_misses_the_reflowed_block(self):
        # Records the hole this replaces: the previous pattern found nothing here.
        import re
        block = self.REFLOWED.split("const SABOTAGE")[1].split("];")[0]
        self.assertEqual(re.findall(r'\("([a-z_]+)",\s*"[a-z_]+",', block), [])

    def test_plain_string_entries_one_per_line_with_trailing_comma(self):
        src = 'const SCENARIOS: &[&str] = &[\n    "benign",\n    "canary_exfil",\n];\n'
        self.assertEqual(self.names(src, "SCENARIOS"), ["benign", "canary_exfil"])

    def test_two_field_tuples_several_per_line(self):
        src = 'const SABOTAGE: &[(&str, &str)] = &[\n    ("ignore_expiry", "monitor_crash"), ("no_kill", "process_escape"),\n];\n'
        self.assertEqual(self.names(src), ["ignore_expiry", "no_kill"])

    def test_commas_and_brackets_inside_strings_and_comments_do_not_split(self):
        src = ('const SABOTAGE: &[(&str, &str)] = &[\n'
               '    // a comment with ], ( and , in it\n'
               '    ("first", "a, b ] c"), /* ), ( */ ("second", "x"),\n'
               '];\n')
        self.assertEqual(self.names(src), ["first", "second"])

    def test_a_mention_in_a_comment_is_not_the_declaration(self):
        src = '// const SABOTAGE lists the controls\n' + self.ONE_LINE
        self.assertEqual(self.names(src), self.NAMES)

    def test_comment_markers_inside_strings_are_string_contents(self):
        src = 'const SABOTAGE: &[(&str, &str)] = &[\n    ("first", "https://example.test"),\n    ("second", "a /* b"),\n];\n'
        self.assertEqual(self.names(src), ["first", "second"])

    def test_nested_block_comment_before_an_entry(self):
        src = 'const SABOTAGE: &[(&str, &str)] = &[\n    /* outer /* inner */ tail */ ("first", "x"),\n];\n'
        self.assertEqual(self.names(src), ["first"])

    def test_a_declaration_inside_a_block_comment_does_not_count(self):
        commented = '/*\nconst SABOTAGE: &[(&str, &str)] = &[\n    ("ghost", "x"),\n];\n*/\n'
        with self.assertRaises(cc.InventoryError):
            self.names(commented)
        self.assertEqual(self.names(commented + self.ONE_LINE), self.NAMES)

    def test_char_literals_raw_strings_and_lifetimes_elsewhere_in_the_file(self):
        rest = ("const QUOTE: char = '\"';\n"
                "const ESCAPED: char = '\\'';\n"
                "const SLASHES: &str = r#\"a \"b\" // not a comment\"#;\n"
                "const BYTES: &[u8] = br\"x\\\";\n"
                "fn borrow<'a>(s: &'a str) -> &'a str { s }\n")
        self.assertEqual(self.names(rest + self.ONE_LINE + rest), self.NAMES)

    def test_empty_block_is_an_error(self):
        with self.assertRaises(cc.InventoryError):
            self.names("const SABOTAGE: &[(&str, &str)] = &[];\n")

    def test_entry_without_a_literal_name_is_an_error(self):
        for entry in ['(NAME, "monitor_crash")', '(concat!("ignore", "_expiry"), "x")', '("Bad-Name", "x")']:
            with self.subTest(entry=entry), self.assertRaises(cc.InventoryError):
                self.names(f"const SABOTAGE: &[(&str, &str)] = &[\n    {entry},\n];\n")

    def test_missing_or_repeated_declaration_is_an_error(self):
        with self.assertRaises(cc.InventoryError):
            self.names("const OTHER: &[&str] = &[\"a\"];\n")
        with self.assertRaises(cc.InventoryError):
            self.names(self.ONE_LINE + self.ONE_LINE)

    def test_unclosed_block_is_an_error(self):
        with self.assertRaises(cc.InventoryError):
            self.names('const SABOTAGE: &[(&str, &str)] = &[\n    ("a", "b"),\n')

    def test_repository_inventory_is_complete(self):
        # Counts at the time this check was written; growing them is fine.
        _laws, _bend, _rust, sabotage, scenarios, live_scenarios, live_sabotage = cc.load_inventory()
        self.assertGreaterEqual(len(sabotage), 29)
        self.assertGreaterEqual(len(scenarios), 31)
        self.assertGreaterEqual(len(live_scenarios), 11)
        self.assertGreaterEqual(len(live_sabotage), 8)


if __name__ == "__main__":
    unittest.main()

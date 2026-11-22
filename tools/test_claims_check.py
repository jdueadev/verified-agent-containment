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
                "const LETTER: char = '\\u{0_0_0_0_4_1}';\n"
                "const BYTE: u8 = b'\\x7f';\n"
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

    def test_registry_and_controls_must_match_both_ways(self):
        self.assertEqual(cc.registry_errors(["a", "b"], ["b", "a"]), [])
        missing = cc.registry_errors(["a", "b"], ["a"])
        self.assertTrue(len(missing) == 1 and "no sabotage control: b" in missing[0], missing)
        unknown = cc.registry_errors(["a"], ["a", "ghost"])
        self.assertTrue(len(unknown) == 1 and "ghost" in unknown[0], unknown)

    BASE_MUTANTS = '"""Docstring."""\nBEND_MUTANTS = [("b1", "x", "y")]\nRUST_MUTANTS = [("r1", "x", "y")]\n'

    def test_mutants_are_read_as_data(self):
        self.assertEqual(cc.mutant_names(self.BASE_MUTANTS), (["b1"], ["r1"]))
        # Other literal data, such as the web demo's SHOWCASE table, is allowed.
        self.assertEqual(cc.mutant_names(self.BASE_MUTANTS + 'SHOWCASE = [("b1", "t", "e", "law")]\n'), (["b1"], ["r1"]))
        with self.assertRaises(cc.InventoryError):
            cc.mutant_names('BEND_MUTANTS = []\nRUST_MUTANTS = [("r1", "x", "y")]\n')

    def test_anything_but_literal_assignments_is_an_error(self):
        # The mutation runner imports the module, so any statement could change what it
        # runs without this reader seeing it, through an alias as easily as directly.
        for extra in ['BEND_MUTANTS += [("b2", "x", "y")]', 'RUST_MUTANTS.append(("r2", "x", "y"))',
                      'alias = BEND_MUTANTS\nalias.append(("b2", "x", "y"))',
                      'BEND_MUTANTS = BEND_MUTANTS + [("b2", "x", "y")]', 'RUST_MUTANTS[0] = ("r9", "x", "y")',
                      'RUST_MUTANTS: list = []', 'for RUST_MUTANTS in [[]]:\n    pass',
                      'def f():\n    global BEND_MUTANTS\n    BEND_MUTANTS = []', 'import os',
                      'ALL = BEND_MUTANTS + RUST_MUTANTS', 'BEND_MUTANTS = [("b1", "x", "y")]']:
            with self.subTest(extra=extra), self.assertRaises(cc.InventoryError):
                cc.mutant_names(self.BASE_MUTANTS + extra + "\n")

    def test_repository_mutants_match_the_imported_module(self):
        import kernel_mutants
        bend, rust = cc.mutant_names((cc.ROOT / "tools/kernel_mutants.py").read_text(encoding="utf-8"))
        self.assertEqual(bend, [m[0] for m in kernel_mutants.BEND_MUTANTS])
        self.assertEqual(rust, [m[0] for m in kernel_mutants.RUST_MUTANTS])

    def test_repository_inventory_is_complete(self):
        # Counts at the time this check was written; growing them is fine.
        _laws, _bend, _rust, sabotage, scenarios, live_scenarios, live_sabotage = cc.load_inventory()
        self.assertGreaterEqual(len(sabotage), 29)
        self.assertGreaterEqual(len(scenarios), 31)
        self.assertGreaterEqual(len(live_scenarios), 11)
        self.assertGreaterEqual(len(live_sabotage), 8)




class PendingLabEvidenceTests(unittest.TestCase):
    """A lab scenario or control the committed results have never run is pending: the
    claim is stale (a warning on main, an error under --strict). One that ran and failed
    is an error in both modes. Run on this repository, with one result removed or failed."""

    def run_main(self, change, *args):
        import contextlib
        import io
        import json
        from unittest import mock
        real = cc.load_results

        def patched():
            results = list(real())
            change(results)
            return tuple(results)
        out = io.StringIO()
        with mock.patch.object(cc, "load_results", patched), contextlib.redirect_stdout(out):
            code = cc.main(list(args))
        return code, json.loads(out.getvalue())

    def test_a_control_that_never_ran_makes_its_claim_stale_not_broken(self):
        drop = lambda r: r[3].pop("ignore_expiry")  # sabotage_ok
        code, report = self.run_main(drop)
        self.assertEqual(report["errors"], [])
        self.assertEqual(code, 0)
        self.assertTrue(any("sabotage:ignore_expiry has not run in the lab yet" in w and "H-LEASE-01" in w
                            for w in report["stale"]), report["stale"])
        code, report = self.run_main(drop, "--strict")
        self.assertEqual(code, 1)
        self.assertTrue(any("has not run in the lab yet" in e for e in report["errors"]))

    def test_a_scenario_that_never_ran_is_pending_too(self):
        code, report = self.run_main(lambda r: r[2].pop("monitor_crash"))
        self.assertEqual(code, 0)
        self.assertTrue(any("scenario:monitor_crash has not run in the lab yet" in w for w in report["stale"]))

    def test_a_control_that_ran_and_missed_is_an_error_in_both_modes(self):
        failed = lambda r: r[3].__setitem__("ignore_expiry", False)
        for args in ((), ("--strict",)):
            with self.subTest(args=args):
                code, report = self.run_main(failed, *args)
                self.assertEqual(code, 1)
                self.assertIn("CI-3 H-LEASE-01: sabotage:ignore_expiry was not caught or did not pass in results/",
                              report["errors"])

    def test_a_kind_without_lab_results_is_never_pending(self):
        # Mutants come from check, not the lab: a missing one is an error, never "pending".
        code, report = self.run_main(lambda r: r[0].clear())
        self.assertEqual(code, 1)
        self.assertTrue(any("was not caught or did not pass" in e for e in report["errors"]))

    def test_a_checked_bounded_claim_with_an_unrun_lab_reference_is_pending(self):
        from unittest import mock
        original = cc.tomllib.loads
        extra = {"id": "X-BOUND-01", "statement": "s", "layer": "host", "status": "checked-bounded",
                 "evidence": ["tla:host#ClassifierCannotForceStop", "scenario:never_ran_anywhere"],
                 "falsifier": "f", "files": []}
        planned = dict(extra, id="X-PLAN-01", status="planned")

        def loads(text):
            data = original(text)
            if "claim" in data:
                data["claim"] = data["claim"] + [dict(extra), dict(planned)]
            return data
        with mock.patch.object(cc.tomllib, "loads", loads):
            code, report = self.run_main(lambda r: None)
        self.assertTrue(any("X-BOUND-01" in w and "scenario:never_ran_anywhere has not run in the lab yet" in w
                            for w in report["stale"]), report["stale"])
        self.assertFalse(any("X-PLAN-01" in w for w in report["stale"]), "a planned claim was marked pending")

    def test_strict_mode_holds_the_ci_lab_run_to_ci_8(self):
        import json
        import shutil
        head = cc.subprocess.run(["git", "-C", str(cc.ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                                 check=True).stdout.strip()
        ci_dir = cc.ROOT / "results/ci"
        lab = ci_dir / f"lab-{head}"
        if lab.exists():
            self.skipTest("a CI lab run for HEAD is already committed")
        created_ci = not ci_dir.exists()
        lab.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, ci_dir if created_ci else lab)
        attack = json.loads((cc.ROOT / "results/attack-suite.json").read_text(encoding="utf-8"))
        (lab / "attack-suite.json").write_text(json.dumps(dict(attack, timed_repeat=1)), encoding="utf-8")
        (lab / "live-suite.json").write_text((cc.ROOT / "results/live-suite.json").read_text(encoding="utf-8"),
                                             encoding="utf-8")
        _, report = self.run_main(lambda r: None, "--strict")
        self.assertTrue(any(e.startswith(f"CI-8 results/ci/lab-{head}/attack-suite.json: timed_repeat is 1")
                            for e in report["errors"]), report["errors"])

    def test_a_live_control_that_never_ran_is_pending(self):
        code, report = self.run_main(lambda r: r[6].pop("live_canary_unchecked"))
        self.assertEqual(code, 0)
        self.assertTrue(any("live-sabotage:live_canary_unchecked has not run in the lab yet" in w for w in report["stale"]))

    def test_the_newest_ci_lab_run_counts_and_cannot_hide_a_failure(self):
        import json
        import shutil
        head = cc.subprocess.run(["git", "-C", str(cc.ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                                 check=True).stdout.strip()
        ci_dir = cc.ROOT / "results/ci"
        lab = ci_dir / f"lab-{head}"
        if lab.exists():
            self.skipTest("a CI lab run for HEAD is already committed")
        created_ci = not ci_dir.exists()
        lab.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, ci_dir if created_ci else lab)
        attack = json.loads((cc.ROOT / "results/attack-suite.json").read_text(encoding="utf-8"))
        (lab / "live-suite.json").write_text((cc.ROOT / "results/live-suite.json").read_text(encoding="utf-8"), encoding="utf-8")
        (lab / "attack-suite.json").write_text(json.dumps(attack), encoding="utf-8")
        self.assertEqual(cc.latest_ci_lab(), lab)
        # With a CI run that caught everything, nothing changes.
        code, report = self.run_main(lambda r: None)
        self.assertEqual((code, report["errors"]), (0, []))
        # A control the CI run missed fails, even though the root lab's run caught it.
        missed = dict(attack, sabotage=[dict(c, detected=False) if c["weakness"] == "ignore_expiry" else c
                                        for c in attack["sabotage"]])
        (lab / "attack-suite.json").write_text(json.dumps(missed), encoding="utf-8")
        code, report = self.run_main(lambda r: None)
        self.assertEqual(code, 1)
        self.assertIn("CI-3 H-LEASE-01: sabotage:ignore_expiry was not caught or did not pass in results/",
                      report["errors"])

    def test_a_pending_claim_is_marked_in_the_rendered_table(self):
        import contextlib
        import io
        from unittest import mock as m
        real = cc.load_results

        def patched():
            results = list(real())
            results[3].pop("ignore_expiry")
            return tuple(results)
        written = {}
        with m.patch.object(cc, "load_results", patched), \
                m.patch.object(cc.Path, "write_text", lambda self, text, **kw: written.__setitem__(str(self), text)), \
                contextlib.redirect_stdout(io.StringIO()):
            cc.main(["--write"])
        table = next(text for path, text in written.items() if path.endswith("docs/claims.md"))
        row = next(line for line in table.splitlines() if line.startswith("| H-LEASE-01 |"))
        self.assertIn("pending lab: sabotage:ignore_expiry", row)



if __name__ == "__main__":
    unittest.main()

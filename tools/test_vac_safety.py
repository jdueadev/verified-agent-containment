import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

safety = importlib.import_module("vac_safety")

CLAIMS = '''
[[claim]]
id = "K-1"
status = "proved"
evidence = ["law:tighten", "mutant:lower", "rust-mutant:rlower", "scenario:escape", "live-sabotage:canary"]

[[claim]]
id = "P-1"
status = "planned"
evidence = ["law:someday", "mutant:draft"]
'''


def getter(files):
    return lambda path: files.get(path)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.core = safety.core(getter({"claims.toml": CLAIMS}))

    def test_core_holds_only_refs_of_claims_that_carry_weight(self):
        self.assertIn("law:tighten", self.core["refs"])
        self.assertNotIn("law:someday", self.core["refs"])
        self.assertEqual(self.core["claims"], {"K-1": "proved"})

    def test_each_kind_of_cited_evidence_is_core(self):
        for reason in ("law tighten was removed", "law tighten was reworded", "mutant lower was removed",
                       "mutant rlower was changed", "claim K-1: statement was reworded",
                       "crates/containment-host/src/harness.rs: escape was removed",
                       "crates/containment-host/src/live_suite.rs: canary was changed",
                       "spec crates/containment-kernel/tests/laws.rs was edited"):
            with self.subTest(reason=reason):
                self.assertTrue(safety.core_reason(reason, self.core))

    def test_uncited_evidence_is_waivable(self):
        for reason in ("law someday was removed", "mutant draft was removed", "claim P-1: evidence lost law:someday",
                       "crates/containment-host/src/harness.rs: unused was removed", "spec tools/test_x.py was edited"):
            with self.subTest(reason=reason):
                self.assertFalse(safety.core_reason(reason, self.core))

    def test_an_unreadable_suite_is_core(self):
        self.assertTrue(safety.core_reason("crates/containment-host/src/harness.rs: SCENARIOS is not a list", self.core))

    def test_lowering_a_core_claim_is_caught_and_raising_is_not(self):
        lowered = CLAIMS.replace('status = "proved"', 'status = "tested"', 1)
        self.assertEqual(len(safety.status_drops(self.core, getter({"claims.toml": lowered}))), 1)
        self.assertEqual(safety.status_drops(self.core, getter({"claims.toml": CLAIMS})), [])
        gone = CLAIMS.split("[[claim]]\nid = \"P-1\"")[0].replace('id = "K-1"', 'id = "K-2"')
        self.assertEqual(len(safety.status_drops(self.core, getter({"claims.toml": gone}))), 1)


class MutationTests(unittest.TestCase):
    def test_a_core_law_no_mutant_breaks_is_a_gap(self):
        c = {"refs": {"law:a", "law:b"}, "claims": {}}
        report = {"bend": [{"mutant": "m", "rejected": True, "laws_violated": ["a"]}]}
        self.assertEqual(safety.law_kill_gaps(c, report), ["b"])

    def test_a_mutant_that_stops_being_rejected_or_vanishes_regresses(self):
        base = {"bend": [{"mutant": "m1", "rejected": True}, {"mutant": "m2", "rejected": True}], "rust": []}
        head = {"bend": [{"mutant": "m1", "rejected": False}, {"mutant": "m3", "rejected": True}], "rust": []}
        self.assertEqual(safety.mutation_regressions(base, head), ["bend:m1", "bend:m2"])

    def test_a_lost_mutant_is_caught_when_the_other_language_shares_its_name(self):
        base = {"bend": [{"mutant": "same", "rejected": True}], "rust": [{"mutant": "same", "rejected": True}]}
        head = {"bend": [], "rust": [{"mutant": "same", "rejected": True}]}
        self.assertEqual(safety.mutation_regressions(base, head), ["bend:same"])

    def test_an_added_mutant_is_not_a_regression(self):
        base = {"bend": [{"mutant": "m1", "rejected": True}]}
        head = {"bend": [{"mutant": "m1", "rejected": True}, {"mutant": "m9", "rejected": True}]}
        self.assertEqual(safety.mutation_regressions(base, head), [])


class WaiverFileTests(unittest.TestCase):
    ROW = {"reason": "spec tools/test_x.py was edited", "issue": 7, "receipt": "a" * 64, "head": "b" * 40}

    def test_rows_round_trip(self):
        text = safety.waiver_toml([self.ROW])
        self.assertEqual(safety.load_waivers(text), [self.ROW])

    def test_a_reason_outside_the_bmp_round_trips(self):
        row = dict(self.ROW, reason="spec \U0001f600 tools/test_x.py was edited")
        text = safety.waiver_toml([row])
        self.assertEqual(safety.load_waivers(text), [row])

    def test_a_reason_with_a_control_character_is_refused_before_it_is_written(self):
        for reason in ("spec\x7fx was edited", "spec\nx was edited"):
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    safety.waiver_toml([dict(self.ROW, reason=reason)])

    def test_each_malformed_field_is_refused(self):
        bad = [("reason", 5), ("issue", "7"), ("issue", True), ("receipt", "short"), ("head", "short")]
        for field, value in bad:
            with self.subTest(field=field, value=value):
                text = "[[waiver]]\n" + "".join(f"{k} = {json.dumps(value if k == field else v)}\n" for k, v in self.ROW.items())
                with self.assertRaises(ValueError):
                    safety.load_waivers(text)

    def test_no_file_means_no_waivers(self):
        self.assertEqual(safety.load_waivers(None), [])


if __name__ == "__main__":
    unittest.main()

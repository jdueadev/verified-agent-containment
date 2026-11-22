#!/usr/bin/env python3
"""Unit tests for tools/policy_check.py. Each rule has a case that makes it fire."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc

ROOT = Path(__file__).resolve().parent.parent
OWNER, LANES = pc.load_lanes((ROOT / "ci/lanes.toml").read_text(encoding="utf-8"))

LAWS = "law keep_me:\n  a == a\n\ndef helper():\n  1\n\nlaw fail_closed:\n  x == y\n  finished\n"
MUTANTS = 'BEND_MUTANTS = [\n    ("one", "a", "b"),\n    ("two", "c", "d"),\n]\nRUST_MUTANTS = [("r1", "x")]\n'
HARNESS = 'const SCENARIOS: &[&str] = &["monitor_crash", "exfil_race"];\nconst SABOTAGE: &[(&str, &str)] = &[("ignore_expiry", "monitor_crash")];\n'
CLAIMS = '''
[[claim]]
id = "K-1"
statement = "The kernel fails closed."
layer = "bend-kernel"
status = "tested"
evidence = ["law:fail_closed", "mutant:one"]
falsifier = "A state that stays live"
depends_on = ["K-0"]
platforms = [{ name = "wsl2", commit = "abc1234", result = "pass" }]
files = ["formal/kernel.bend", "formal/LAWS.bend"]
'''
BASE = {"formal/LAWS.bend": LAWS, "tools/kernel_mutants.py": MUTANTS,
        "crates/containment-host/src/harness.rs": HARNESS, "claims.toml": CLAIMS}


def tree(**changes):
    files = dict(BASE)
    files.update(changes)
    return files.get


def reasons(**changes):
    return pc.ratchets(BASE.get, tree(**changes))


class LaneTests(unittest.TestCase):
    def lane(self, path, doc_cited=()):
        return pc.lane_of(path, LANES, doc_cited)[0]

    def test_unclassified_path_is_lane_c(self):
        self.assertEqual(pc.lane_of("brand/new/file.txt", LANES), ("C", "unclassified path"))
        self.assertEqual(self.lane("LICENSE-MIT"), "C")

    def test_leading_dot_is_part_of_the_name(self):
        self.assertEqual(self.lane("CONTRIBUTING.md"), "A")
        self.assertEqual(pc.lane_of(".CONTRIBUTING.md", LANES), ("C", "unclassified path"))
        self.assertEqual(pc.lane_of("./CONTRIBUTING.md", LANES), ("C", "unclassified path"))
        self.assertEqual(self.lane(".github/workflows/x.yaml"), "C")
        self.assertEqual(pc.lane_of("github/workflows/x.yml", LANES), ("C", "unclassified path"))

    def test_single_star_stays_in_one_file_name(self):
        self.assertTrue(pc.lane_match("tools/test_x.py", "tools/test_*.py"))
        self.assertFalse(pc.lane_match("tools/test_a/b.py", "tools/test_*.py"))
        self.assertFalse(pc.lane_match("tools/test_.pyc", "tools/test_*.py"))
        self.assertTrue(pc.lane_match("results/attack-suite.json", "results/attack-suite*"))
        self.assertFalse(pc.lane_match("results/attack-suite/x", "results/attack-suite*"))
        self.assertFalse(pc.lane_match("scripts", "scripts/**"))

    def test_the_attack_harness_is_a_verifier(self):
        for path in ("crates/containment-host/src/harness.rs", "crates/containment-host/src/live_suite.rs",
                     "crates/containment-host/src/redteam.rs", "crates/containment-kernel/tests/laws.rs"):
            self.assertEqual(self.lane(path), "C", path)

    def test_rules_and_verifiers_are_lane_c(self):
        for path in (".github/workflows/check.yml", "ci/lanes.toml", "scripts/check.sh", "tools/claims_check.py",
                     "tools/policy_check.py", "tools/test_policy_check.py", "AGENTS.md", ".github/CODEOWNERS",
                     "results/wsl2/lab-cd7172f/attack-suite.json", "results/attack-suite.json",
                     "results/formal-verdict.json", "docs/decisions/0001-agent-workflow.md",
                     "results/ci/lab-0123456/attack-suite.json", "tools/lab_record.py"):
            self.assertEqual(self.lane(path), "C", path)

    def test_source_and_claims_are_lane_b(self):
        for path in ("crates/containment-host/src/controller.rs", "formal/LAWS.bend", "claims.toml", "Cargo.toml",
                     "docs/claims.md", "results/differential.json", "tools/kernel_mutants.py", "README.md"):
            self.assertEqual(self.lane(path), "B", path)

    def test_docs_and_demos_are_lane_a(self):
        for path in ("docs/reference.md", "web/template.html", "examples/live/policy.toml", "CONTRIBUTING.md"):
            self.assertEqual(self.lane(path), "A", path)

    def test_doc_cited_as_evidence_is_at_least_b(self):
        self.assertEqual(self.lane("docs/reference.md", doc_cited={"docs/reference.md"}), "B")

    def test_every_tracked_file_has_a_deliberate_lane(self):
        tracked = [p for p in pc.git("ls-files").splitlines() if p]
        unclassified = [p for p in tracked if pc.lane_of(p, LANES)[1] == "unclassified path"]
        self.assertEqual(unclassified, ["LICENSE-APACHE", "LICENSE-MIT"])

    def test_bad_lane_map_is_rejected(self):
        for text in ('owner = "x"\n[lanes]\nC = []\n', 'owner = "@x"\n[lanes]\nD = []\n',
                     'owner = "@x"\n[lanes]\nC = ["a/**/b"]\n', 'owner = "@x"\n[lanes]\nC = ["/abs"]\n',
                     'owner = "@x"\n[lanes]\nC = ["a*/b*"]\n', 'owner = "@x"\n[lanes]\nC = ["./a"]\n'):
            with self.assertRaises(ValueError):
                pc.load_lanes(text)


class RatchetTests(unittest.TestCase):
    def test_no_change_and_pure_additions_pass(self):
        self.assertEqual(reasons(), [])
        added = {
            "formal/LAWS.bend": LAWS + "\nlaw extra:\n  1 == 1\n",
            "tools/kernel_mutants.py": MUTANTS.replace('("two", "c", "d"),', '("two", "c", "d"),\n    ("three", "e", "f"),'),
            "crates/containment-host/src/harness.rs": HARNESS.replace('"exfil_race"', '"exfil_race", "new_one"'),
            "claims.toml": CLAIMS.replace('"mutant:one"]', '"mutant:one", "mutant:two"]').replace('status = "tested"', 'status = "stale"')
            + '\n[[claim]]\nid = "K-2"\nstatement = "s"\nlayer = "host"\nstatus = "planned"\nfalsifier = "f"\n',
        }
        self.assertEqual(reasons(**added), [])

    def test_law_removed_or_reworded(self):
        self.assertIn("law fail_closed was removed", reasons(**{"formal/LAWS.bend": LAWS.split("law fail_closed")[0]}))
        self.assertIn("law fail_closed was reworded", reasons(**{"formal/LAWS.bend": LAWS.replace("x == y", "x == x")}))
        self.assertEqual(reasons(**{"formal/LAWS.bend": LAWS.replace("def helper():\n  1", "def helper():\n  2")}), [])

    def test_mutant_removed_or_changed(self):
        self.assertIn("mutant BEND_MUTANTS:two was removed", reasons(**{"tools/kernel_mutants.py": MUTANTS.replace('    ("two", "c", "d"),\n', "")}))
        self.assertIn("mutant RUST_MUTANTS:r1 was changed", reasons(**{"tools/kernel_mutants.py": MUTANTS.replace('("r1", "x")', '("r1", "y")')}))

    def test_scenario_or_sabotage_removed(self):
        out = reasons(**{"crates/containment-host/src/harness.rs": HARNESS.replace(', "exfil_race"', "")})
        self.assertTrue(any("SCENARIOS:exfil_race was removed" in r for r in out), out)
        out = reasons(**{"crates/containment-host/src/harness.rs": HARNESS.replace('("ignore_expiry", "monitor_crash")', "")})
        self.assertTrue(any("SABOTAGE:ignore_expiry was removed" in r for r in out), out)

    def test_reflowing_the_suite_tables_is_not_a_change(self):
        reflowed = ('const SCENARIOS: &[&str] = &[\n    "monitor_crash",\n    // the race\n    "exfil_race",\n];\n'
                    'const SABOTAGE: &[(&str, &str)] = &[\n    (\n        "ignore_expiry",\n        "monitor_crash",\n    ),\n];\n')
        self.assertEqual(reasons(**{"crates/containment-host/src/harness.rs": reflowed}), [])

    def test_a_control_aimed_at_another_scenario_is_a_change(self):
        # The old ratchet compared one flattened set of strings, so this passed.
        swapped = HARNESS.replace('("ignore_expiry", "monitor_crash")', '("ignore_expiry", "exfil_race")')
        out = reasons(**{"crates/containment-host/src/harness.rs": swapped})
        self.assertTrue(any("SABOTAGE:ignore_expiry was changed" in r for r in out), out)

    def test_removing_one_of_two_rows_with_the_same_name_escalates(self):
        two = HARNESS.replace('("ignore_expiry", "monitor_crash")', '("ignore_expiry", "monitor_crash"), ("ignore_expiry", "exfil_race")')
        base = dict(BASE, **{"crates/containment-host/src/harness.rs": two})
        for kept in ('("ignore_expiry", "monitor_crash")', '("ignore_expiry", "exfil_race")'):
            head = dict(BASE, **{"crates/containment-host/src/harness.rs": HARNESS.replace('("ignore_expiry", "monitor_crash")', kept)})
            with self.subTest(kept=kept):
                out = pc.ratchets(base.get, head.get)
                self.assertTrue(any("SABOTAGE:ignore_expiry was changed" in r for r in out), out)

    def test_a_suite_table_the_head_cannot_read_escalates(self):
        out = reasons(**{"crates/containment-host/src/harness.rs": HARNESS.replace("const SABOTAGE", "const SABOTAGES")})
        self.assertTrue(any("SABOTAGE could not be read" in r for r in out), out)

    def test_claim_weakened(self):
        cases = {
            "claim K-1 was removed": "",
            "claim K-1: statement was reworded": CLAIMS.replace("fails closed", "usually fails closed"),
            "claim K-1: falsifier was reworded": CLAIMS.replace("stays live", "stays live forever"),
            "claim K-1: files lost formal/LAWS.bend": CLAIMS.replace(', "formal/LAWS.bend"', ""),
            "claim K-1: evidence lost mutant:one": CLAIMS.replace(', "mutant:one"', ""),
            "claim K-1: depends_on lost K-0": CLAIMS.replace('depends_on = ["K-0"]', "depends_on = []"),
            "claim K-1: status raised from tested to proved": CLAIMS.replace('status = "tested"', 'status = "proved"'),
            "claim K-1: platforms was edited": CLAIMS.replace("abc1234", "def5678"),
        }
        for expected, text in cases.items():
            self.assertIn(expected, reasons(**{"claims.toml": text}), expected)

    def test_new_row_cannot_arrive_with_platforms(self):
        extra = CLAIMS + '\n[[claim]]\nid = "K-9"\nstatement = "s"\nlayer = "host"\nstatus = "tested"\nfalsifier = "f"\nplatforms = [{ name = "x", commit = "y", result = "pass" }]\n'
        self.assertIn("claim K-9: new row records platforms", reasons(**{"claims.toml": extra}))

    def test_unparseable_claims_escalates(self):
        self.assertTrue(any("does not parse" in r for r in reasons(**{"claims.toml": "[[claim"})))


class ClassifyTests(unittest.TestCase):
    def test_highest_lane_wins(self):
        self.assertEqual(pc.classify(["docs/reference.md"], BASE.get, BASE.get, LANES)["lane"], "A")
        self.assertEqual(pc.classify(["docs/reference.md", "crates/x.rs"], BASE.get, BASE.get, LANES)["lane"], "B")
        self.assertEqual(pc.classify(["docs/reference.md", ".github/workflows/check.yml"], BASE.get, BASE.get, LANES)["lane"], "C")
        self.assertEqual(pc.classify([], BASE.get, BASE.get, LANES)["lane"], "A")

    def test_ratchet_raises_a_lane_b_diff_to_c(self):
        head = tree(**{"claims.toml": CLAIMS.replace(', "formal/LAWS.bend"', "")})
        result = pc.classify(["claims.toml"], BASE.get, head, LANES)
        self.assertEqual(result["paths"]["claims.toml"]["lane"], "B")
        self.assertEqual(result["lane"], "C")
        self.assertEqual(result["escalations"], ["claim K-1: files lost formal/LAWS.bend"])


class ApprovalTests(unittest.TestCase):
    def review(self, login, state, sha="h1"):
        return {"user": {"login": login}, "state": state, "commit_id": sha}

    def test_only_the_owner_approving_this_head_counts(self):
        self.assertTrue(pc.approved([self.review("JDueaDev", "APPROVED")], "@jdueadev", "h1"))
        self.assertFalse(pc.approved([], "@jdueadev", "h1"))
        self.assertFalse(pc.approved([self.review("someone", "APPROVED")], "@jdueadev", "h1"))
        self.assertFalse(pc.approved([self.review("jdueadev", "APPROVED", "old")], "@jdueadev", "h1"))
        self.assertFalse(pc.approved([self.review("jdueadev", "APPROVED"), self.review("jdueadev", "CHANGES_REQUESTED")], "@jdueadev", "h1"))
        self.assertTrue(pc.approved([self.review("jdueadev", "APPROVED"), self.review("jdueadev", "COMMENTED")], "@jdueadev", "h1"))

    def test_paginated_reviews_are_read_in_order(self):
        pages = [[self.review("jdueadev", "APPROVED")], [self.review("jdueadev", "CHANGES_REQUESTED")]]
        self.assertFalse(pc.approved(pages, "@jdueadev", "h1"))
        self.assertTrue(pc.approved(list(reversed(pages)), "@jdueadev", "h1"))


class CodeownersAndInvariantTests(unittest.TestCase):
    def test_codeowners_is_exactly_lane_c(self):
        text = pc.codeowners_text(OWNER, LANES)
        self.assertEqual(pc.codeowners_errors(OWNER, LANES, text), [])
        self.assertIn("/.github/ " + OWNER, text)
        self.assertIn("/tools/test_*.py " + OWNER, text)
        self.assertTrue(pc.codeowners_errors(OWNER, LANES, text.replace("/scripts/ " + OWNER + "\n", "")))
        self.assertTrue(pc.codeowners_errors(OWNER, LANES, None))
        self.assertEqual(pc.codeowners_errors(OWNER, LANES, (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")), [])

    def test_sabotage_must_not_be_a_default_feature(self):
        self.assertEqual(pc.sabotage_default_errors('[features]\ndefault = []\nsabotage = []\n'), [])
        self.assertTrue(pc.sabotage_default_errors('[features]\ndefault = ["sabotage"]\nsabotage = []\n'))
        self.assertTrue(pc.sabotage_default_errors('[features]\ndefault = ["lab"]\nlab = ["sabotage"]\nsabotage = []\n'))
        self.assertEqual(pc.sabotage_default_errors((ROOT / "crates/containment-host/Cargo.toml").read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()

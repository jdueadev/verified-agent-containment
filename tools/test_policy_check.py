#!/usr/bin/env python3
"""Unit tests for tools/policy_check.py. Each rule has a case that makes it fire."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
                     "crates/containment-host/src/redteam.rs"):
            self.assertEqual(self.lane(path), "C", path)

    def test_rules_and_verifiers_are_lane_c(self):
        for path in (".github/workflows/check.yml", "ci/lanes.toml", "scripts/check.sh", "tools/claims_check.py",
                     "tools/policy_check.py", "AGENTS.md", ".github/CODEOWNERS",
                     "results/wsl2/lab-cd7172f/attack-suite.json", "results/attack-suite.json",
                     "results/formal-verdict.json", "docs/decisions/0001-agent-workflow.md",
                     "results/ci/lab-0123456/attack-suite.json", "tools/lab_record.py"):
            self.assertEqual(self.lane(path), "C", path)

    def test_host_code_and_build_inputs_are_lane_c(self):
        # #83: the lab can be fooled by the code it tests, so host code needs the maintainer.
        for path in ("crates/containment-host/src/controller.rs", "crates/containment-host/src/differential.rs",
                     "crates/containment-host/src/controller/gateway.rs", "crates/containment-host/src/hud.html",
                     "crates/containment-host/build.rs", "Cargo.toml", "Cargo.lock", ".cargo/config.toml",
                     ".cargo/config", "rust-toolchain.toml", "rust-toolchain",
                     "crates/containment-kernel/Cargo.toml", "crates/containment-kernel/build.rs",
                     "crates/containment-wasm/Cargo.toml", "crates/containment-wasm/build.rs"):
            self.assertEqual(self.lane(path), "C", path)

    def test_source_and_claims_are_lane_b(self):
        for path in ("crates/containment-kernel/src/lib.rs", "crates/containment-wasm/src/lib.rs",
                     "formal/LAWS.bend", "claims.toml",
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

    def test_a_dismissal_cancels_an_earlier_approval(self):
        reviews = [self.review("jdueadev", "APPROVED"), self.review("jdueadev", "DISMISSED")]
        self.assertFalse(pc.approved(reviews, "@jdueadev", "h1"))
        reviews.append(self.review("jdueadev", "APPROVED"))
        self.assertTrue(pc.approved(reviews, "@jdueadev", "h1"))

    def test_an_approval_dismissed_in_place_counts_for_nothing(self):
        approval = self.review("jdueadev", "APPROVED")
        approval["state"] = "DISMISSED"
        self.assertFalse(pc.approved([approval], "@jdueadev", "h1"))

    def test_a_deleted_reviewer_is_nobody(self):
        ghost = {"user": None, "state": "APPROVED", "commit_id": "h1"}
        self.assertFalse(pc.approved([ghost], "@jdueadev", "h1"))
        no_login = {"user": {"login": None}, "state": "APPROVED", "commit_id": "h1"}
        self.assertFalse(pc.approved([no_login], "@jdueadev", "h1"))
        self.assertTrue(pc.approved([ghost, self.review("jdueadev", "APPROVED")], "@jdueadev", "h1"))

    def test_an_unknown_commit_never_matches(self):
        self.assertFalse(pc.approved([self.review("jdueadev", "APPROVED", None)], "@jdueadev", None))
        self.assertFalse(pc.approved([self.review("jdueadev", "APPROVED", "")], "@jdueadev", ""))
        self.assertFalse(pc.approved([self.review("jdueadev", "APPROVED", None)], "@jdueadev", "h1"))

    def test_paginated_reviews_are_read_in_order(self):
        pages = [[self.review("jdueadev", "APPROVED")], [self.review("jdueadev", "CHANGES_REQUESTED")]]
        self.assertFalse(pc.approved(pages, "@jdueadev", "h1"))
        self.assertTrue(pc.approved(list(reversed(pages)), "@jdueadev", "h1"))


class EnforceExitTests(unittest.TestCase):
    """`classify --enforce` is the gate the `policy` workflow runs. These drive it end to
    end, with git replaced by fixed trees so the result depends on nothing local."""

    LANES_TEXT = (ROOT / "ci/lanes.toml").read_text(encoding="utf-8")

    def run_classify(self, paths, *extra, reviews=None, head_commit=None, trees=None):
        """Return (exit code, parsed result). Refs b, h and m are base, head and map-ref."""
        files = dict(BASE, **{"ci/lanes.toml": self.LANES_TEXT})
        trees = trees or {}
        argv = ["classify", "--base", "b", "--head", "h", *extra]
        if head_commit is None and "--head-sha" in extra:
            head_commit = extra[extra.index("--head-sha") + 1]

        def fake_git(*args):
            return (head_commit or "") + "\n" if args[0] == "rev-parse" else "\n".join(paths) + "\n"

        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            if reviews is not None:
                review_file = Path(tmp) / "reviews.json"
                review_file.write_text(json.dumps(reviews), encoding="utf-8")
                argv += ["--reviews", str(review_file)]
            with mock.patch.object(pc, "reader", lambda ref: trees.get(ref, files).get), \
                    mock.patch.object(pc, "git", fake_git), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = pc.main(argv)
        return code, json.loads(out.getvalue())

    def approval(self, sha="h1"):
        return [{"user": {"login": "jdueadev"}, "state": "APPROVED", "commit_id": sha}]

    def test_lane_c_without_approval_fails_only_when_enforced(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--enforce", reviews=[])
        self.assertEqual((code, result["lane"], result["needs_maintainer"], result["approved"]), (1, "C", True, False))
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", reviews=[])
        self.assertEqual((code, result["approved"]), (0, False))

    def test_lane_c_approved_at_this_head_passes(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--enforce", reviews=self.approval())
        self.assertEqual((code, result["lane"], result["approved"]), (0, "C", True))

    def test_lane_c_approved_at_an_older_head_fails(self):
        code, result = self.run_classify(["AGENTS.md"], "--head-sha", "h2", "--enforce", reviews=self.approval("h1"))
        self.assertEqual((code, result["approved"]), (1, False))

    def test_a_fork_needs_approval_whatever_its_lane(self):
        code, result = self.run_classify(["docs/reference.md"], "--head-sha", "h1", "--fork", "--enforce", reviews=[])
        self.assertEqual((code, result["lane"], result["needs_maintainer"]), (1, "A", True))
        code, result = self.run_classify(["docs/reference.md"], "--head-sha", "h1", "--enforce", reviews=[])
        self.assertEqual((code, result["lane"], result["needs_maintainer"]), (0, "A", False))

    def test_the_lane_map_comes_from_the_map_ref_not_the_head(self):
        def moved(lane):
            text = self.LANES_TEXT.replace('  "AGENTS.md",\n', "", 1)
            out = text.replace(f'{lane} = [\n', f'{lane} = [\n  "AGENTS.md",\n', 1)
            self.assertNotEqual(out, text)
            return dict(BASE, **{"ci/lanes.toml": out})

        # Three different maps put AGENTS.md in three different lanes, so the lane
        # reported shows which one was read. Only AGENTS.md is classified.
        maps = {"b": moved("B"), "h": moved("A"), "m": dict(BASE, **{"ci/lanes.toml": self.LANES_TEXT})}
        code, result = self.run_classify(["AGENTS.md"], "--map-ref", "m", "--head-sha", "h1",
                                         "--enforce", reviews=[], trees=maps)
        self.assertEqual((code, result["paths"]["AGENTS.md"]["lane"], result["lane"]), (1, "C", "C"))
        # and with the lanes rotated, the map-ref still decides.
        maps = {"b": dict(BASE, **{"ci/lanes.toml": self.LANES_TEXT}),
                "h": moved("B"), "m": moved("A")}
        code, result = self.run_classify(["AGENTS.md"], "--map-ref", "m", "--head-sha", "h1",
                                         "--enforce", reviews=[], trees=maps)
        self.assertEqual((code, result["paths"]["AGENTS.md"]["lane"]), (0, "A"))

    def test_a_missing_lane_map_is_refused(self):
        with self.assertRaises(SystemExit) as stop:
            self.run_classify(["AGENTS.md"], "--map-ref", "m", "--head-sha", "h1", "--enforce", reviews=[],
                              trees={"m": dict(BASE)})
        self.assertIn("has no ci/lanes.toml", str(stop.exception.code))

    def test_an_approval_of_another_commit_than_the_one_classified_is_refused(self):
        with self.assertRaises(SystemExit) as stop:
            self.run_classify(["AGENTS.md"], "--head-sha", "h1", "--enforce", reviews=self.approval(), head_commit="h9")
        self.assertIn("is not --head-sha", str(stop.exception.code))

    def test_reviews_or_enforce_without_a_head_commit_is_refused(self):
        ghost_commit = [{"user": {"login": "jdueadev"}, "state": "APPROVED", "commit_id": None}]
        for extra, reviews in ((("--enforce",), None), ((), self.approval()),
                               (("--head-sha", "", "--enforce"), ghost_commit)):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as stop:
                self.run_classify(["AGENTS.md"], *extra, reviews=reviews)
            self.assertEqual(stop.exception.code, 2)


class ReaderTests(unittest.TestCase):
    """reader() against this repository: only a path the commit lacks reads as absent."""

    def test_a_missing_path_is_none_and_a_present_one_is_read(self):
        get = pc.reader("HEAD")
        self.assertIsNone(get("no/such/file.txt"))
        self.assertIn("lanes", get("ci/lanes.toml"))

    def test_a_failed_read_of_a_present_path_is_an_error(self):
        def fake_git(*args):
            if args[0] == "show":
                raise subprocess.CalledProcessError(128, ["git", *args])
            return "c0ffee\n" if args[0] == "rev-parse" else "claims.toml\n"
        with mock.patch.object(pc, "git", fake_git), self.assertRaises(subprocess.CalledProcessError):
            pc.reader("HEAD")("claims.toml")

    def test_an_unknown_ref_is_an_error_not_an_empty_tree(self):
        with self.assertRaises(subprocess.CalledProcessError):
            pc.reader("refs/heads/no-such-branch-for-policy-tests")


class CodeownersAndInvariantTests(unittest.TestCase):
    def test_codeowners_is_exactly_lane_c(self):
        text = pc.codeowners_text(OWNER, LANES)
        self.assertEqual(pc.codeowners_errors(OWNER, LANES, text), [])
        self.assertIn("/.github/ " + OWNER, text)
        self.assertIn("/tools/spec_run.py " + OWNER, text)
        self.assertTrue(pc.codeowners_errors(OWNER, LANES, text.replace("/scripts/ " + OWNER + "\n", "")))
        self.assertTrue(pc.codeowners_errors(OWNER, LANES, None))
        self.assertEqual(pc.codeowners_errors(OWNER, LANES, (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")), [])

    def test_sabotage_must_not_be_a_default_feature(self):
        self.assertEqual(pc.sabotage_default_errors('[features]\ndefault = []\nsabotage = []\n'), [])
        self.assertTrue(pc.sabotage_default_errors('[features]\ndefault = ["sabotage"]\nsabotage = []\n'))
        self.assertTrue(pc.sabotage_default_errors('[features]\ndefault = ["lab"]\nlab = ["sabotage"]\nsabotage = []\n'))
        self.assertEqual(pc.sabotage_default_errors((ROOT / "crates/containment-host/Cargo.toml").read_text(encoding="utf-8")), [])


class KernelPurityTests(unittest.TestCase):
    ROOT_FILE = "crates/containment-kernel/src/lib.rs"
    PURE = "//! Kernel.\n#![no_std]\n#![forbid(unsafe_code)]\npub fn f(x: u8) -> u8 { core::cmp::min(x, 1) }\n"

    def errors(self, text, extra=None):
        return pc.kernel_purity_errors({self.ROOT_FILE: text, **(extra or {})})

    def test_the_real_kernel_is_pure(self):
        self.assertEqual(pc.kernel_purity_errors(pc.kernel_sources()), [])

    def test_a_pure_kernel_passes_and_comments_or_strings_do_not_count(self):
        self.assertEqual(self.errors(self.PURE), [])
        self.assertEqual(self.errors(self.PURE + '// uses std::fs\nconst S: &str = "std::env";\n'), [])

    def test_each_root_attribute_is_required(self):
        self.assertTrue(self.errors(self.PURE.replace("#![no_std]\n", "")))
        self.assertTrue(self.errors(self.PURE.replace("#![forbid(unsafe_code)]\n", "")))
        self.assertTrue(self.errors(self.PURE.replace("forbid(unsafe_code)", "deny(unsafe_code)")))
        self.assertTrue(self.errors(self.PURE.replace("#![no_std]", "#[no_std]")))

    def test_ways_out_of_core_are_refused(self):
        for snippet in ("extern crate std;", "extern crate libc;", "use std::fs;", "extern crate alloc;", "use alloc::vec::Vec;",
                        'const P: &str = include_str!("../../../examples/x");', 'include!("x.rs");',
                        'const K: &str = env!("HOME");', 'const K: Option<&str> = option_env!("HOME");',
                        '#[path = "../../../web/x.rs"]\nmod x;'):
            with self.subTest(snippet=snippet):
                self.assertTrue(self.errors(self.PURE + snippet + "\n"))

    def test_the_review_bypasses_are_refused(self):
        # Each of these got past the first version of the check (CodeRabbit on #84).
        bypasses = {
            "raw identifier": 'const P: &str = r#include_str!("../../../examples/x");',
            "raw include": 'r#include!("../../containment-wasm/src/payload.rs");',
            "renamed import": 'use core::include as load;\nload!("../../containment-wasm/src/payload.rs");',
            "path in cfg_attr": '#[cfg_attr(all(), path = "../../containment-wasm/src/payload.rs")]\npub mod payload;',
            "nested cfg_attr": '#[cfg_attr(all(), cfg_attr(all(), path = "x.rs"))]\nmod x;',
            "global_asm": 'core::arch::global_asm!("nop");',
            "feature gate": "#![feature(asm_experimental_arch)]",
            "export": "#[no_mangle]\npub fn exported() {}",
            "link section": '#[link_section = ".init_array"]\npub static S: u8 = 0;',
            "extern block": 'extern "C" { fn f(); }',
        }
        for name, snippet in bypasses.items():
            with self.subTest(name=name):
                self.assertTrue(self.errors(self.PURE + snippet + "\n"))

    def test_root_attributes_count_only_at_the_top_of_the_crate(self):
        moved = self.PURE.replace("#![forbid(unsafe_code)]\n", "") + "pub mod marker {\n    #![forbid(unsafe_code)]\n}\n"
        self.assertTrue(any("forbid(unsafe_code)" in e for e in self.errors(moved)))
        late = self.PURE.replace("#![no_std]\n", "") + "#![no_std]\n"
        self.assertTrue(any("no_std" in e for e in self.errors(late)))
        hidden = self.PURE.replace("#![no_std]", "#![cfg_attr(any(), no_std)]")
        self.assertTrue(any("no_std" in e for e in self.errors(hidden)))
        extra = self.PURE.replace("#![forbid(unsafe_code)]\n", "#![forbid(unsafe_code)]\n#![deny(clippy::panic)]\n")
        self.assertEqual(self.errors(extra), [])

    def test_every_kernel_file_is_checked_and_a_missing_root_fails(self):
        self.assertTrue(self.errors(self.PURE, {"crates/containment-kernel/src/m.rs": "use std::io;\n"}))
        self.assertTrue(pc.kernel_purity_errors({}))
        unreadable = self.errors(self.PURE + 'const S: &str = "unterminated;\n')
        self.assertTrue(unreadable)
        self.assertTrue(all("cannot be read" in e for e in unreadable), unreadable)


if __name__ == "__main__":
    unittest.main()

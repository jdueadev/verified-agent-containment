import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

ratchet = importlib.import_module("results_ratchet")
core = importlib.import_module("vac_core")
registry = importlib.import_module("vac_rules")
FLOOR = importlib.import_module("claims_check").MIN_DIFF_SEQUENCES


def changed(data, edit):
    out = copy.deepcopy(data)
    edit(out)
    return out


def config(name, expected, states, ok=True):
    return {"config": name, "expected": expected, "exit": 0 if expected == "pass" else 12, "violated": "",
            "distinct_states": states, "as_expected": ok}


TLA = {"spec": "formal/host/HostModel.tla", "sha256": "a" * 64, "passed": ["TypeOK"],
       "runs": [config("HostModel", "pass", 1000), config("HostModelPre1", "violates ClassifierCannotForceStop", 50)]}
MUTATION = {
    "bend": [{"mutant": "m1", "rejected": True, "first_failure": "x", "laws_violated": ["a", "b"], "witness": True},
             {"mutant": "m2", "rejected": True, "first_failure": "y", "laws_violated": ["b"], "witness": True}],
    "rust": [{"mutant": "r1", "rejected": True}],
    "bend_rejected": 2, "bend_witnessed": 2, "original_violations": {}, "rust_rejected": 1, "bend_total": 2,
    "rust_total": 1,
}
DIFF = {"sequences": FLOOR, "transitions": FLOOR * 15, "mismatches": 0}
WASM = {"transitions": FLOOR * 15, "mismatches": 0}
VERDICT = {"result": "ALL PROOFS CHECK", "sha256": {"formal/kernel.bend": "a" * 64}, "laws": 36}
SUITE = {
    "suite": "attack", "timed_repeat": 30, "cgroup_limits_waived": False, "controls_cgroup_limits_waived": False,
    "runs": [{"scenario": "s1", "weakness": "none", "passed": True}, {"scenario": "s1", "weakness": "none", "passed": True},
             {"scenario": "s2", "weakness": "none", "passed": True}, {"scenario": "s3", "weakness": "none", "passed": False}],
    "sabotage": [{"scenario": "s1", "weakness": "w1", "detected": True, "failed_checks": ["c"]},
                 {"scenario": "s2", "weakness": "w2", "detected": False, "failed_checks": []}],
}
LIVE = {"suite": "live", "runs": [{"scenario": "l1", "weakness": "none", "passed": True}],
        "sabotage": [{"scenario": "l1", "weakness": "lw", "detected": True, "target_check": "c"}]}


class Family:
    compare = None
    base = None

    def weak(self, edit):
        return type(self).compare(self.base, changed(self.base, edit))

    def assert_flags(self, edit, *expected):
        self.assertEqual(self.weak(edit), list(expected))

    def assert_holds(self, edit):
        self.assertEqual(self.weak(edit), [])


class TlaTests(Family, unittest.TestCase):
    compare = ratchet.tla
    base = TLA

    def test_a_config_that_stops_behaving_as_expected_is_flagged(self):
        self.assert_flags(lambda d: d["runs"][1].update(as_expected=False), "config HostModelPre1 as_expected: true -> false")

    def test_a_config_that_disappears_is_flagged_whatever_it_recorded(self):
        self.assert_flags(lambda d: d["runs"].pop(1), "config HostModelPre1: present -> absent")
        failing = changed(TLA, lambda d: d["runs"][1].update(as_expected=False))
        self.assertEqual(ratchet.tla(failing, changed(failing, lambda d: d["runs"].pop(1))),
                         ["config HostModelPre1: present -> absent"])

    def test_a_passing_config_that_explores_fewer_states_is_flagged(self):
        self.assert_flags(lambda d: d["runs"][0].update(distinct_states=999),
                          "config HostModel distinct_states: 1000 -> 999")
        self.assert_flags(lambda d: d["runs"][0].pop("distinct_states"),
                          "config HostModel distinct_states: 1000 -> absent")

    def test_a_passing_config_relabelled_as_expected_to_fail_is_flagged(self):
        self.assert_flags(lambda d: d["runs"][0].update(expected="violates TypeOK"),
                          'config HostModel expected: pass -> "violates TypeOK"')

    def test_a_violating_config_may_find_its_counterexample_sooner(self):
        self.assert_holds(lambda d: d["runs"][1].update(distinct_states=10))

    def test_a_config_that_failed_at_the_base_has_no_state_count_to_keep(self):
        failing = changed(TLA, lambda d: d["runs"][0].update(as_expected=False))
        self.assertEqual(ratchet.tla(failing, changed(failing, lambda d: d["runs"][0].update(distinct_states=1))), [])

    def test_equal_and_stronger_hold(self):
        self.assert_holds(lambda d: None)
        self.assert_holds(lambda d: d["runs"][0].update(distinct_states=1001))
        self.assert_holds(lambda d: d["runs"].append(config("HostModelNew", "pass", 5)))
        failing = changed(TLA, lambda d: d["runs"][1].update(as_expected=False))
        self.assertEqual(ratchet.tla(failing, TLA), [])

    def test_regeneration_with_identical_metrics_holds(self):
        self.assert_holds(lambda d: (d.update(sha256="b" * 64), d["runs"].reverse()))


class MutationTests(Family, unittest.TestCase):
    compare = ratchet.mutation
    base = MUTATION

    def test_a_drop_in_either_rejected_count_is_flagged(self):
        self.assert_flags(lambda d: d.update(bend_rejected=1), "bend_rejected: 2 -> 1")
        self.assert_flags(lambda d: d.update(rust_rejected=0), "rust_rejected: 1 -> 0")
        self.assert_flags(lambda d: d.pop("rust_rejected"), "rust_rejected: 1 -> absent")

    def test_a_mutant_that_stops_being_rejected_is_flagged(self):
        self.assert_flags(lambda d: d["bend"][1].update(rejected=False), "bend mutant m2 rejected: true -> false")
        self.assert_flags(lambda d: d["rust"][0].update(rejected=False), "rust mutant r1 rejected: true -> false")

    def test_a_rejected_mutant_that_disappears_is_flagged(self):
        self.assert_flags(lambda d: d["bend"].pop(1), "bend mutant m2 rejected: true -> absent",
                          "bend mutant m2 witness: true -> absent")
        self.assert_flags(lambda d: d["rust"].pop(), "rust mutant r1 rejected: true -> absent")

    def test_a_lost_witness_is_flagged(self):
        self.assert_flags(lambda d: d["bend"][1].update(witness=False), "bend mutant m2 witness: true -> false")

    def test_a_law_no_mutant_breaks_any_more_is_flagged(self):
        self.assert_flags(lambda d: d["bend"][0].update(laws_violated=["b"]), 'law a broken by mutants: ["m1"] -> []')
        self.assert_flags(lambda d: d["bend"][0].update(laws_violated=None, witness=False),
                          "bend mutant m1 witness: true -> false", 'law a broken by mutants: ["m1"] -> []')

    def test_a_law_another_mutant_still_breaks_holds(self):
        self.assert_holds(lambda d: d["bend"][1].update(laws_violated=["a"]))

    def test_an_added_mutant_is_a_strengthening(self):
        def add(d):
            d["bend"].append({"mutant": "m3", "rejected": True, "first_failure": "z", "laws_violated": ["c"], "witness": True})
            d.update(bend_rejected=3, bend_witnessed=3, bend_total=3)
        self.assert_holds(add)

    def test_equal_holds_and_regeneration_with_identical_metrics_holds(self):
        self.assert_holds(lambda d: None)
        self.assert_holds(lambda d: (d["bend"].reverse(), d["bend"][0].update(first_failure="elsewhere")))
        unrejected = changed(MUTATION, lambda d: (d["rust"][0].update(rejected=False), d.update(rust_rejected=0)))
        self.assertEqual(ratchet.mutation(unrejected, MUTATION), [])


class DifferentialTests(Family, unittest.TestCase):
    compare = ratchet.differential
    base = DIFF

    def test_the_all_zero_differential_of_182_is_flagged(self):
        self.assert_flags(lambda d: d.update(sequences=0, transitions=0),
                          f"sequences: {FLOOR} -> 0, below MIN_DIFF_SEQUENCES {FLOOR}",
                          f"transitions: {FLOOR * 15} -> 0, below MIN_DIFF_SEQUENCES {FLOOR}")

    def test_a_drop_names_the_floor_only_when_it_is_crossed(self):
        above = changed(DIFF, lambda d: d.update(sequences=FLOOR + 2))
        self.assertEqual(ratchet.differential(above, changed(above, lambda d: d.update(sequences=FLOOR + 1))),
                         [f"sequences: {FLOOR + 2} -> {FLOOR + 1}"])
        self.assertEqual(ratchet.differential(above, DIFF), [f"sequences: {FLOOR + 2} -> {FLOOR}"])
        self.assert_flags(lambda d: d.update(sequences=FLOOR - 1),
                          f"sequences: {FLOOR} -> {FLOOR - 1}, below MIN_DIFF_SEQUENCES {FLOOR}")

    def test_a_count_that_is_no_longer_an_integer_is_flagged(self):
        self.assert_flags(lambda d: d.update(sequences=False),
                          f"sequences: {FLOOR} -> false, below MIN_DIFF_SEQUENCES {FLOOR}")

    def test_a_mismatch_where_the_base_had_none_is_flagged(self):
        self.assert_flags(lambda d: d.update(mismatches=1), "mismatches: 0 -> 1")
        self.assert_flags(lambda d: d.pop("mismatches"), "mismatches: 0 -> absent")
        self.assertEqual(ratchet.differential(WASM, changed(WASM, lambda d: d.update(mismatches=2))), ["mismatches: 0 -> 2"])

    def test_a_mismatch_is_flagged_beside_a_count_drop(self):
        self.assert_flags(lambda d: d.update(transitions=FLOOR * 14, mismatches=1),
                          f"transitions: {FLOOR * 15} -> {FLOOR * 14}", "mismatches: 0 -> 1")

    def test_more_mismatches_than_a_failing_base_had_is_not_a_new_finding(self):
        failing = changed(WASM, lambda d: d.update(mismatches=2))
        self.assertEqual(ratchet.differential(failing, changed(WASM, lambda d: d.update(mismatches=3))), [])

    def test_the_wasm_case_count_is_ratcheted(self):
        self.assertEqual(ratchet.differential(WASM, changed(WASM, lambda d: d.update(transitions=FLOOR))),
                         [f"transitions: {FLOOR * 15} -> {FLOOR}"])

    def test_equal_and_stronger_hold(self):
        self.assert_holds(lambda d: None)
        self.assert_holds(lambda d: d.update(sequences=FLOOR * 2, transitions=FLOOR * 30))


class VerdictTests(Family, unittest.TestCase):
    compare = ratchet.verdict
    base = VERDICT

    def test_a_pass_that_becomes_anything_else_is_flagged(self):
        self.assert_flags(lambda d: d.update(result="SOME PROOFS FAIL"), 'result: "ALL PROOFS CHECK" -> "SOME PROOFS FAIL"')
        self.assert_flags(lambda d: d.pop("result"), 'result: "ALL PROOFS CHECK" -> absent')

    def test_equal_and_a_new_pass_hold(self):
        self.assert_holds(lambda d: d.update(sha256={"formal/kernel.bend": "b" * 64}, laws=40))
        failing = changed(VERDICT, lambda d: d.update(result="SOME PROOFS FAIL"))
        self.assertEqual(ratchet.verdict(failing, VERDICT), [])
        self.assertEqual(ratchet.verdict(failing, changed(failing, lambda d: d.update(result="worse"))), [])


class SuiteTests(Family, unittest.TestCase):
    compare = ratchet.suite
    base = SUITE

    def test_a_scenario_that_fails_in_any_run_is_flagged(self):
        self.assert_flags(lambda d: d["runs"][0].update(passed=False), "scenario s1 passed: true -> false")

    def test_a_scenario_that_disappears_is_flagged(self):
        self.assert_flags(lambda d: d["runs"].pop(2), "scenario s2 passed: true -> absent")

    def test_a_sabotage_control_that_goes_undetected_or_disappears_is_flagged(self):
        self.assert_flags(lambda d: d["sabotage"][0].update(detected=False), "sabotage w1 detected: true -> false")
        self.assert_flags(lambda d: d["sabotage"].pop(0), "sabotage w1 detected: true -> absent")

    def test_a_sabotage_build_run_is_not_an_honest_run(self):
        self.assert_holds(lambda d: d["runs"].append({"scenario": "s1", "weakness": "w1", "passed": False}))
        self.assert_flags(lambda d: d["runs"][2].update(weakness="w2"), "scenario s2 passed: true -> absent")

    def test_a_drop_in_timed_repeat_is_flagged(self):
        self.assert_flags(lambda d: d.update(timed_repeat=29), "timed_repeat: 30 -> 29")

    def test_a_cgroup_waiver_that_appears_is_flagged(self):
        self.assert_flags(lambda d: d.update(cgroup_limits_waived=True), "cgroup_limits_waived: false -> true")
        self.assert_flags(lambda d: d.pop("controls_cgroup_limits_waived"), "controls_cgroup_limits_waived: false -> absent")
        self.assert_flags(lambda d: d.update(cgroup_limits_waived=None), "cgroup_limits_waived: false -> null")

    def test_equal_and_stronger_hold(self):
        self.assert_holds(lambda d: None)
        self.assert_holds(lambda d: (d.update(timed_repeat=31), d["runs"][3].update(passed=True),
                                     d["sabotage"][1].update(detected=True), d["runs"].append(
                                         {"scenario": "s4", "weakness": "none", "passed": True})))
        self.assert_holds(lambda d: (d["runs"].pop(3), d["sabotage"].pop(1)))
        waived = changed(SUITE, lambda d: d.update(cgroup_limits_waived=True))
        self.assertEqual(ratchet.suite(waived, SUITE), [])

    def test_regeneration_with_identical_metrics_holds(self):
        self.assert_holds(lambda d: (d["runs"].reverse(), d.update(kernel="another")))
        self.assertEqual(ratchet.suite(LIVE, copy.deepcopy(LIVE)), [])


def texts(files):
    return lambda path: None if files.get(path) is None else json.dumps(files[path])


TREE = {"results/tla-check.json": TLA, "results/mutation-check.json": MUTATION, "results/differential.json": DIFF,
        "results/wasm-differential.json": WASM, "results/formal-verdict.json": VERDICT,
        "results/attack-suite.json": SUITE, "results/live-suite.json": LIVE}
OLD_LAB, NEW_LAB = "results/ci/lab-" + "a" * 40, "results/ci/lab-" + "b" * 40
LABS = {f"{OLD_LAB}/attack-suite.json": SUITE, f"{OLD_LAB}/live-suite.json": LIVE}


class WeakeningsTests(unittest.TestCase):
    def test_an_identical_tree_holds(self):
        self.assertEqual(ratchet.weakenings(texts(TREE), texts(copy.deepcopy(TREE))), [])

    def test_each_weakening_lands_on_its_file(self):
        head = copy.deepcopy(TREE)
        head["results/mutation-check.json"]["bend_rejected"] = 1
        head["results/live-suite.json"]["sabotage"][0]["detected"] = False
        self.assertEqual(ratchet.weakenings(texts(TREE), texts(head)),
                         [("results/mutation-check.json", "bend_rejected: 2 -> 1"),
                          ("results/live-suite.json", "sabotage lw detected: true -> false")])

    def test_a_file_new_at_the_head_holds_and_a_file_gone_from_it_is_flagged(self):
        base = {k: v for k, v in TREE.items() if k != "results/tla-check.json"}
        self.assertEqual(ratchet.weakenings(texts(base), texts(TREE)), [])
        self.assertEqual(ratchet.weakenings(texts(TREE), texts(base)),
                         [("results/tla-check.json", "present at the base, absent at the head")])

    def test_every_results_file_is_ratcheted(self):
        for path in TREE:
            with self.subTest(path=path):
                head = {k: v for k, v in TREE.items() if k != path}
                self.assertEqual(ratchet.weakenings(texts(TREE), texts(head)),
                                 [(path, "present at the base, absent at the head")])

    def test_a_head_file_that_is_not_a_json_object_is_flagged(self):
        head = texts(TREE)
        self.assertEqual(ratchet.weakenings(texts(TREE), lambda p: "[]" if p.endswith("verdict.json") else head(p)),
                         [("results/formal-verdict.json", "not a JSON object at the head")])
        self.assertEqual(ratchet.weakenings(texts(TREE), lambda p: "{" if p.endswith("verdict.json") else head(p)),
                         [("results/formal-verdict.json", "not a JSON object at the head")])

    def test_the_newest_lab_run_at_the_head_is_held_to_the_newest_at_the_base(self):
        new = {f"{NEW_LAB}/attack-suite.json": changed(SUITE, lambda d: d.update(timed_repeat=10)),
               f"{NEW_LAB}/live-suite.json": LIVE}
        self.assertEqual(ratchet.weakenings(texts({**TREE, **LABS}), texts({**TREE, **LABS, **new}), OLD_LAB, NEW_LAB),
                         [(f"{NEW_LAB}/attack-suite.json", f"timed_repeat: 30 -> 10 (base {OLD_LAB}/attack-suite.json)")])
        same = {f"{NEW_LAB}/attack-suite.json": SUITE, f"{NEW_LAB}/live-suite.json": LIVE}
        self.assertEqual(ratchet.weakenings(texts(LABS), texts(same), OLD_LAB, NEW_LAB), [])

    def test_a_lab_run_gone_from_the_head_is_flagged_and_a_first_one_holds(self):
        self.assertEqual(ratchet.weakenings(texts(LABS), texts({}), OLD_LAB, None),
                         [(f"{OLD_LAB}/attack-suite.json", "present at the base, absent at the head"),
                          (f"{OLD_LAB}/live-suite.json", "present at the base, absent at the head")])
        self.assertEqual(ratchet.weakenings(texts({}), texts(LABS), None, OLD_LAB), [])


class NewestLabTests(unittest.TestCase):
    def test_the_nearest_ancestor_wins(self):
        dirs = [OLD_LAB, NEW_LAB, "results/ci/lab-" + "c" * 40, "results/ci/notes"]
        distances = {"a" * 40: 5, "b" * 40: 2, "c" * 40: None}
        self.assertEqual(ratchet.newest_lab(dirs, distances.get), NEW_LAB)
        self.assertIsNone(ratchet.newest_lab(dirs[2:], distances.get))
        self.assertIsNone(ratchet.newest_lab([], distances.get))


class RuleTests(unittest.TestCase):
    def test_every_family_is_registered(self):
        rules = {r.id: r for r in registry.RULES}
        for rule_id in ("RES-TLA", "RES-MUT", "RES-DIFF", "RES-VERDICT", "RES-LAB"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual((rules[rule_id].stages, rules[rule_id].refs), (frozenset(core.STAGES), (213,)))

    def test_each_rule_reports_only_its_own_files(self):
        ctx = core.Ctx()
        ctx.memo["results-ratchet"] = [(path, "weaker") for path in [*TREE, f"{NEW_LAB}/live-suite.json"]]
        found = {r.id: sorted(f.path for f in r.check(ctx)) for r in registry.RULES if r.id.startswith("RES-")}
        self.assertEqual(found, {
            "RES-TLA": ["results/tla-check.json"],
            "RES-MUT": ["results/mutation-check.json"],
            "RES-DIFF": ["results/differential.json", "results/wasm-differential.json"],
            "RES-VERDICT": ["results/formal-verdict.json"],
            "RES-LAB": ["results/attack-suite.json", f"{NEW_LAB}/live-suite.json", "results/live-suite.json"],
        })

    def test_a_base_that_cannot_be_read_fails_closed(self):
        ctx = core.Ctx(base="no-such-ref-for-results-ratchet")
        for rule in (r for r in registry.RULES if r.id.startswith("RES-")):
            with self.subTest(rule=rule.id):
                found = rule.check(ctx)
                self.assertEqual([(f.rule, f.path) for f in found], [(rule.id, "results")])


if __name__ == "__main__":
    unittest.main()

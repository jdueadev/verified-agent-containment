#!/usr/bin/env python3
"""Unit tests for tools/lab_record.py. Each refusal has a case that makes it fire.

The fixture is the committed WSL2 lab run results/wsl2/lab-cd7172f: a real full run,
honest and controls, that every current lab claim was recorded against."""
import copy
import json
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_record as lr

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "results/wsl2/lab-cd7172f"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / "root"
        self.root.mkdir()
        shutil.copyfile(ROOT / "claims.toml", self.root / "claims.toml")
        self.results = {
            "attack-suite.json": json.loads((RUN / "attack-suite.json").read_text(encoding="utf-8")),
            "live-suite.json": json.loads((RUN / "live-suite.json").read_text(encoding="utf-8")),
        }
        self.cover_newer_evidence()

    def cover_newer_evidence(self):
        """The fixture run predates scenarios and controls that claims.toml cites today
        (wide_root, #88, say). Give each one a passing honest run or a detecting control,
        so these tests are about the recorder, not about how old the fixture is. Tests
        that need a missing or failing entry still remove or spoil one themselves."""
        claims = tomllib.loads((self.root / "claims.toml").read_text(encoding="utf-8"))["claim"]
        template_run = next(r for r in self.results["attack-suite.json"]["runs"] if r["weakness"] == "none")
        for claim in lr.lab_claims(claims):
            for ref in claim.get("evidence", []):
                kind, _, name = ref.partition(":")
                if kind not in lr.REF_KINDS:
                    continue
                suite, section = lr.REF_KINDS[kind]
                entries = self.results[suite][section]
                if section == "runs" and not any(r["scenario"] == name and r["weakness"] == "none" for r in entries):
                    entries.append(dict(template_run, scenario=name, passed=True))
                elif section == "sabotage" and not any(c["weakness"] == name for c in entries):
                    entries.append({"weakness": name, "scenario": "synthetic", "detected": True, "failed_checks": []})

    def environment(self, results=None, commit=COMMIT):
        build = (results or self.results)["attack-suite.json"]["build"]
        return (f"commit id: {commit}\nkernel: test\n"
                f"default binary sha256: {build['honest']['binary_sha256']}\n"
                f"sabotage binary sha256: {build['sabotage']['binary_sha256']}\n")

    def write_run(self, results=None, environment=True):
        run = self.tmp / "run"
        if run.exists():
            shutil.rmtree(run)
        run.mkdir()
        for name, data in (results or self.results).items():
            (run / lr.SUITES[name]).write_text(json.dumps(data), encoding="utf-8")
        if environment is True:
            environment = self.environment(results)
        if environment:
            (run / "environment.txt").write_text(environment, encoding="utf-8")
        return run

    def record(self, results=None, commit=COMMIT, platform="gha-ubuntu-24.04", environment=True):
        return lr.record(self.root, self.write_run(results, environment), commit, platform)

    def refused(self, needle, **kwargs):
        before = (self.root / "claims.toml").read_text(encoding="utf-8")
        with self.assertRaises(lr.RecordError) as raised:
            self.record(**kwargs)
        self.assertIn(needle, str(raised.exception))
        self.assertEqual((self.root / "claims.toml").read_text(encoding="utf-8"), before, "claims.toml changed on refusal")
        self.assertFalse((self.root / "results").exists(), "results were written on refusal")

    def test_a_full_run_records_every_lab_claim_and_nothing_else(self):
        before = {c["id"]: c for c in tomllib.loads((self.root / "claims.toml").read_text(encoding="utf-8"))["claim"]}
        ids, where = self.record()
        self.assertEqual(where, f"results/ci/lab-{COMMIT}")
        lab = {cid for cid, c in before.items() if any(p["result"].startswith("pass") for p in c.get("platforms", []))}
        self.assertEqual(set(ids), lab)
        self.assertTrue(lab)
        after = {c["id"]: c for c in tomllib.loads((self.root / "claims.toml").read_text(encoding="utf-8"))["claim"]}
        for cid, old in before.items():
            new = after[cid]
            if cid in lab:
                self.assertEqual(new["platforms"][:-1], old["platforms"])
                self.assertEqual(new["platforms"][-1]["name"], "gha-ubuntu-24.04")
                self.assertEqual(new["platforms"][-1]["commit"], COMMIT)
                self.assertTrue(new["platforms"][-1]["result"].startswith(f"pass (lab evidence: results/ci/lab-{COMMIT};"))
                new, old = {k: v for k, v in new.items() if k != "platforms"}, {k: v for k, v in old.items() if k != "platforms"}
            self.assertEqual(new, old, cid)
        for name in ("attack-suite.json", "live-suite.json", "environment.txt"):
            self.assertTrue((self.root / where / name).is_file(), name)

    def test_a_new_claim_with_lab_evidence_gets_its_first_entry(self):
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        text += ('\n[[claim]]\nid = "H-NEW-01"\nstatement = "s"\nlayer = "host"\nstatus = "tested"\n'
                 'evidence = ["scenario:monitor_crash", "sabotage:ignore_expiry"]\nfalsifier = "f"\n'
                 'platforms = []\nfiles = ["crates/containment-host/src/sandbox.rs"]\n')
        (self.root / "claims.toml").write_text(text, encoding="utf-8")
        ids, _ = self.record()
        self.assertIn("H-NEW-01", ids)
        self.assertFalse(any(cid.startswith("C-RST-03") for cid in ids), "a planned claim was recorded")
        row = next(c for c in tomllib.loads((self.root / "claims.toml").read_text(encoding="utf-8"))["claim"]
                   if c["id"] == "H-NEW-01")
        self.assertEqual([p["commit"] for p in row["platforms"]], [COMMIT])

    def test_the_same_platform_and_commit_is_not_recorded_twice(self):
        self.record()
        shutil.rmtree(self.root / "results")
        self.refused(f"already records gha-ubuntu-24.04 at {COMMIT}")

    def test_an_existing_results_directory_is_refused(self):
        (self.root / f"results/ci/lab-{COMMIT}").mkdir(parents=True)
        before = (self.root / "claims.toml").read_text(encoding="utf-8")
        with self.assertRaises(lr.RecordError) as raised:
            self.record()
        self.assertIn("already exists", str(raised.exception))
        self.assertEqual((self.root / "claims.toml").read_text(encoding="utf-8"), before)

    def test_the_environment_must_name_this_commit_and_these_binaries(self):
        self.refused("names commit", environment=self.environment(commit="f" * 40))
        wrong = self.environment().replace("default binary sha256: ", "default binary sha256: 00")
        self.refused("default binary sha256 does not match", environment=wrong)
        wrong = self.environment().replace("sabotage binary sha256: ", "sabotage binary sha256: 00")
        self.refused("sabotage binary sha256 does not match", environment=wrong)

    def test_only_a_real_true_counts(self):
        for value in ("true", 1, None):
            with self.subTest(value=value):
                results = copy.deepcopy(self.results)
                for run in results["attack-suite.json"]["runs"]:
                    if run["scenario"] == "monitor_crash" and run["weakness"] == "none":
                        run["passed"] = value
                self.refused("scenario:monitor_crash", results=results)

    def test_one_failed_run_among_passing_ones_is_refused(self):
        results = copy.deepcopy(self.results)
        runs = [r for r in results["attack-suite.json"]["runs"] if r["scenario"] == "monitor_crash" and r["weakness"] == "none"]
        results["attack-suite.json"]["runs"].append(dict(runs[0], passed=False))
        self.refused("scenario:monitor_crash: 1 honest run(s) failed", results=results)

    def test_an_attack_control_is_not_satisfied_by_a_live_control(self):
        results = copy.deepcopy(self.results)
        moved = [c for c in results["attack-suite.json"]["sabotage"] if c["weakness"] == "ignore_expiry"]
        results["attack-suite.json"]["sabotage"] = [c for c in results["attack-suite.json"]["sabotage"] if c not in moved]
        results["live-suite.json"]["sabotage"] += moved
        self.refused("sabotage:ignore_expiry: no control in attack-suite.json", results=results)

    def test_a_lab_claim_without_lab_evidence_is_refused(self):
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        claims = tomllib.loads(text)["claim"]
        target = next(c for c in claims if any(p["result"].startswith("pass") for p in c.get("platforms", [])))
        line = next(l for l in text.splitlines() if l.startswith("evidence = ") and all(r in l for r in target["evidence"]))
        (self.root / "claims.toml").write_text(text.replace(line, 'evidence = ["law:x"]', 1), encoding="utf-8")
        self.refused(f"{target['id']}: no scenario, sabotage, live or live-sabotage evidence")

    def corrupt_once(self, claim_id):
        """Make append_platform also rewrite one claim's statement, once."""
        real, done = lr.append_platform, []
        statement = next(c["statement"] for c in tomllib.loads((self.root / "claims.toml").read_text(encoding="utf-8"))["claim"]
                         if c["id"] == claim_id)

        def corrupting(text, cid, entry):
            out = real(text, cid, entry)
            if not done:
                done.append(True)
                out = out.replace(statement, statement + " (weakened)", 1)
            return out

        lr.append_platform = corrupting
        self.addCleanup(setattr, lr, "append_platform", real)

    def test_the_post_edit_guard_catches_a_stray_change_to_a_lab_claim(self):
        self.corrupt_once("H-LEASE-01")
        self.refused("claim H-LEASE-01: the edit changed more than its platforms")

    def test_the_post_edit_guard_catches_a_change_to_another_claim(self):
        self.corrupt_once("R-DIFF-01")
        self.refused("claim R-DIFF-01: changed although it is not a lab claim")

    def test_verify_accepts_a_recorded_run_and_catches_later_edits(self):
        self.record()
        self.assertEqual(lr.verify(self.root), [])
        where = self.root / f"results/ci/lab-{COMMIT}"
        data = json.loads((where / "attack-suite.json").read_text(encoding="utf-8"))
        for run in data["runs"]:
            if run["scenario"] == "monitor_crash":
                run["passed"] = False
        (where / "attack-suite.json").write_text(json.dumps(data), encoding="utf-8")
        self.assertTrue(any("scenario:monitor_crash" in p for p in lr.verify(self.root)))

    def test_verify_judges_claims_as_they_are_now(self):
        self.record()
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("evidence = [") and "scenario:monitor_crash" in l)
        (self.root / "claims.toml").write_text(
            text.replace(line, line.replace('"scenario:monitor_crash"', '"scenario:monitor_crash", "scenario:never_ran"'), 1),
            encoding="utf-8")
        self.assertTrue(any("scenario:never_ran: no honest run" in p for p in lr.verify(self.root)))

    def test_a_newer_entry_supersedes_one_that_no_longer_holds(self):
        self.record()
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("evidence = [") and "scenario:monitor_crash" in l)
        (self.root / "claims.toml").write_text(
            text.replace(line, line.replace('"scenario:monitor_crash"', '"scenario:monitor_crash", "scenario:benign"'), 1),
            encoding="utf-8")
        self.assertEqual(lr.verify(self.root), [], "benign ran in the fixture, so the entry still holds")
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("evidence = [") and "scenario:benign" in l)
        (self.root / "claims.toml").write_text(text.replace(line, line.replace('"scenario:benign"', '"scenario:never_ran"'), 1),
                                               encoding="utf-8")
        self.assertTrue(lr.verify(self.root))
        # A newer run that covers the claim as it is now supersedes the old entry.
        results = copy.deepcopy(self.results)
        extra = dict(next(r for r in results["attack-suite.json"]["runs"] if r["weakness"] == "none"), scenario="never_ran")
        results["attack-suite.json"]["runs"].append(extra)
        newer = "fedcba9876543210fedcba9876543210fedcba98"
        lr.record(self.root, self.write_run(results, self.environment(results, newer)), newer, "gha-ubuntu-24.04")
        self.assertEqual(lr.verify(self.root), [])

    def test_verify_catches_a_mismatched_or_missing_directory(self):
        self.record()
        shutil.rmtree(self.root / f"results/ci/lab-{COMMIT}")
        self.assertTrue(any("is missing" in p for p in lr.verify(self.root)))

    def test_a_failed_honest_run_is_refused(self):
        results = copy.deepcopy(self.results)
        run = next(r for r in results["attack-suite.json"]["runs"] if r["scenario"] == "monitor_crash" and r["weakness"] == "none")
        run["passed"] = False
        self.refused("scenario:monitor_crash: 1 honest run(s) failed", results=results)

    def test_an_undetected_control_is_refused(self):
        results = copy.deepcopy(self.results)
        next(c for c in results["attack-suite.json"]["sabotage"] if c["weakness"] == "ignore_expiry")["detected"] = False
        self.refused("sabotage:ignore_expiry: a control did not detect its defect", results=results)

    def test_a_scenario_missing_from_its_suite_is_refused(self):
        results = copy.deepcopy(self.results)
        results["attack-suite.json"]["runs"] = [r for r in results["attack-suite.json"]["runs"] if r["scenario"] != "monitor_crash"]
        self.refused("scenario:monitor_crash: no honest run in attack-suite.json", results=results)

    def test_a_run_on_a_sabotaged_build_is_not_an_honest_run(self):
        results = copy.deepcopy(self.results)
        runs = results["attack-suite.json"]["runs"]
        honest = [r for r in runs if r["scenario"] == "monitor_crash" and r["weakness"] == "none"]
        results["attack-suite.json"]["runs"] = [r for r in runs if r not in honest] + [
            dict(honest[0], weakness="ignore_expiry", passed=True)]
        self.refused("scenario:monitor_crash: no honest run in attack-suite.json", results=results)

    def test_a_live_reference_is_only_satisfied_by_the_live_suite(self):
        results = copy.deepcopy(self.results)
        moved = [r for r in results["live-suite.json"]["runs"] if r["scenario"] == "canary_exfil"]
        self.assertTrue(moved)
        results["live-suite.json"]["runs"] = [r for r in results["live-suite.json"]["runs"] if r["scenario"] != "canary_exfil"]
        results["attack-suite.json"]["runs"] += moved
        self.refused("live:canary_exfil: no honest run in live-suite.json", results=results)
        results = copy.deepcopy(self.results)
        results["live-suite.json"]["sabotage"] = [c for c in results["live-suite.json"]["sabotage"] if c["weakness"] != "live_canary_unchecked"]
        self.refused("live-sabotage:live_canary_unchecked: no control in live-suite.json", results=results)

    def test_ci_8_must_hold(self):
        cases = {
            "came from the same binary": lambda r: r["attack-suite.json"]["build"]["sabotage"].update(
                binary_sha256=r["attack-suite.json"]["build"]["honest"]["binary_sha256"]),
            "timed_repeat is 29": lambda r: r["attack-suite.json"].update(timed_repeat=29),
            "cgroup_limits_waived=false": lambda r: r["attack-suite.json"].update(cgroup_limits_waived=True),
            "controls_cgroup_limits_waived=false": lambda r: r["attack-suite.json"].update(controls_cgroup_limits_waived=True),
            "not stamped as coming from a default build": lambda r: r["live-suite.json"]["build"]["honest"].update(sabotage=True),
        }
        for needle, spoil in cases.items():
            with self.subTest(needle=needle):
                results = copy.deepcopy(self.results)
                spoil(results)
                self.refused(needle, results=results)

    def test_inputs_are_checked(self):
        self.refused("full 40-character SHA", commit="0123456")
        results = copy.deepcopy(self.results)
        results["attack-suite.json"]["kernel"] = "6.8\nevil"
        self.refused("unexpected kernel", results=results)
        self.refused("not a plain platform name", platform='gha"; evil = "x')
        self.refused("environment.txt is missing", environment=False)
        results = copy.deepcopy(self.results)
        results["attack-suite.json"]["kernel"] = 'x" ; y'
        self.refused("unexpected kernel", results=results)

    def test_a_platforms_value_not_on_one_line_is_refused(self):
        text = (self.root / "claims.toml").read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("platforms = ["))
        split = line.replace("[{", "[\n  {", 1)
        (self.root / "claims.toml").write_text(text.replace(line, split, 1), encoding="utf-8")
        self.refused("are not one `platforms = [...]` line")

    def test_append_platform_only_touches_its_claim(self):
        text = '[[claim]]\nid = "A"\nplatforms = [{ name = "x", commit = "1", result = "pass" }]\n\n[[claim]]\nid = "AB"\nplatforms = []\n'
        out = lr.append_platform(text, "A", '{ name = "y", commit = "2", result = "pass" }')
        rows = {c["id"]: c for c in tomllib.loads(out)["claim"]}
        self.assertEqual([p["name"] for p in rows["A"]["platforms"]], ["x", "y"])
        self.assertEqual(rows["AB"]["platforms"], [])
        with self.assertRaises(lr.RecordError):
            lr.append_platform(text, "C", "{}")


if __name__ == "__main__":
    unittest.main()

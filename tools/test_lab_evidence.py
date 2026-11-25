"""lab_evidence accepts a full, sealed pass and refuses each way of falling short."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lab_evidence  # noqa: E402

COMMIT = "c" * 40
IMAGE = "sha256:" + "1" * 64
REPO = "example/repo"
WORKFLOW = "example/repo/.github/workflows/lab.yml"
REF = "refs/heads/main"


def suite(sabotage):
    runs = [
        {"scenario": name, "passed": True, "checks": [{"name": "holds", "passed": True, "detail": 0}]}
        for name in ("benign", "monitor_crash")
    ]
    data = {
        "build": {"honest": {"binary_sha256": "a" * 64, "sabotage": False}, "sabotage": None},
        "runs": runs,
        "runs_total": len(runs),
        "runs_passed": len(runs),
        "cgroup_limits_waived": False,
        "controls_cgroup_limits_waived": False,
        "sabotage": [],
        "sabotage_total": 0,
        "sabotage_detected": 0,
    }
    if sabotage:
        data["build"]["sabotage"] = {"binary_sha256": "b" * 64, "sabotage": True}
        data["sabotage"] = [{"scenario": "monitor_crash", "weakness": "ignore_expiry", "detected": True}]
        data["sabotage_total"] = data["sabotage_detected"] = 1
    return data


def write_json(directory, name, data):
    (directory / name).write_text(json.dumps(data))


def sealed_pass(directory):
    for name in lab_evidence.HONEST.values():
        write_json(directory, name, suite(sabotage=False))
    for name in lab_evidence.CONTROLS.values():
        write_json(directory, name, suite(sabotage=True))
    (directory / lab_evidence.ENVIRONMENT).write_text(f"commit id: {COMMIT}\n")
    (directory / "attack-suite-honest.log").write_text("PASS benign\n")
    lab_evidence.write_manifest(directory, COMMIT, IMAGE, {"run_id": "1"})


def edit(name, change):
    def apply(directory):
        data = json.loads((directory / name).read_text())
        change(data)
        write_json(directory, name, data)
    return apply


def reseal(change):
    def apply(directory):
        change(directory)
        manifest = json.loads((directory / lab_evidence.MANIFEST).read_text())
        lab_evidence.write_manifest(directory, manifest["commit"], manifest["image"], manifest["run"])
    return apply


def set_key(key, value):
    return lambda data: data.__setitem__(key, value)


def fail_one_run(data):
    data["runs"][1]["passed"] = False
    data["runs"][1]["checks"][0]["passed"] = False
    data["runs_passed"] -= 1


def miss_one_control(data):
    data["sabotage"][0]["detected"] = False
    data["sabotage_detected"] -= 1


def waive_in_a_check(data):
    data["runs"][0]["checks"][0]["detail"] = {"waived": "--allow-missing-limits"}


def same_binary_twice(data):
    data["build"]["sabotage"]["binary_sha256"] = data["build"]["honest"]["binary_sha256"]


def other_honest_build(data):
    data["build"]["honest"]["binary_sha256"] = "d" * 64


def other_commit_in_manifest(directory):
    path = directory / lab_evidence.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["commit"] = "e" * 40
    path.write_text(json.dumps(manifest))


def no_image_in_manifest(directory):
    path = directory / lab_evidence.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["image"] = "vac-factory:check"
    path.write_text(json.dumps(manifest))


REFUSED = {
    "a byte changed after sealing": (
        lambda d: (d / "attack-suite-honest.log").write_text("PASS benign \n"),
        "attack-suite-honest.log differs from the manifest",
    ),
    "a result edited after sealing": (
        edit("live-suite.json", set_key("kernel", "edited")),
        "live-suite.json differs from the manifest",
    ),
    "a file added after sealing": (
        lambda d: (d / "extra.json").write_text("{}"),
        "extra.json is in the directory and not in the manifest",
    ),
    "a file removed after sealing": (
        lambda d: (d / "attack-suite-honest.log").unlink(),
        "attack-suite-honest.log is in the manifest and not in the directory",
    ),
    "no manifest": (
        lambda d: (d / lab_evidence.MANIFEST).unlink(),
        "manifest.json is missing",
    ),
    "a manifest for another commit": (other_commit_in_manifest, "manifest.json is for commit"),
    "a manifest that names a tag, not an image id": (no_image_in_manifest, "names no image id"),
    "a failed scenario, sealed": (
        reseal(edit("attack-suite-honest.json", fail_one_run)),
        "monitor_crash did not pass",
    ),
    "a scenario marked passed with a failed check, sealed": (
        reseal(edit("live-suite-honest.json", lambda data: data["runs"][0]["checks"][0].__setitem__("passed", False))),
        "benign did not pass",
    ),
    "no runs, sealed": (
        reseal(edit("attack-suite-honest.json", set_key("runs", []))),
        "attack-suite-honest.json records no runs",
    ),
    "a control that was not caught, sealed": (
        reseal(edit("attack-suite.json", miss_one_control)),
        "control ignore_expiry on monitor_crash was not caught",
    ),
    "no controls, sealed": (
        reseal(edit("live-suite.json", set_key("sabotage", []))),
        "live-suite.json records no sabotage controls",
    ),
    "the controls file missing, sealed": (
        reseal(lambda d: (d / "live-suite.json").unlink()),
        "live-suite.json is missing",
    ),
    "cgroup limits waived, sealed": (
        reseal(edit("attack-suite-honest.json", set_key("cgroup_limits_waived", True))),
        "ran with cgroup limits waived",
    ),
    "a waiver inside one check, sealed": (
        reseal(edit("attack-suite-honest.json", waive_in_a_check)),
        "benign waived holds",
    ),
    "honest runs from a sabotage build, sealed": (
        reseal(edit("live-suite-honest.json", lambda data: data["build"]["honest"].__setitem__("sabotage", True))),
        "was not made by a build without the sabotage feature",
    ),
    "controls from the honest binary, sealed": (
        reseal(edit("attack-suite.json", same_binary_twice)),
        "not two different binaries",
    ),
    "controls judged against another honest build, sealed": (
        reseal(edit("attack-suite.json", other_honest_build)),
        "judged against another honest build",
    ),
    "controls that carry other honest runs, sealed": (
        reseal(edit("attack-suite.json", lambda data: data["runs"].pop())),
        "not the ones in the honest file",
    ),
    "results of another commit, sealed": (
        reseal(lambda d: (d / lab_evidence.ENVIRONMENT).write_text("commit id: unknown\n")),
        "environment.txt is not for commit",
    ),
}


def fake_gh(directory, exit_code):
    path = directory / "gh"
    path.write_text(f"#!/bin/sh\necho \"$@\" > \"{directory}/gh-arguments\"\nexit {exit_code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


class LabEvidence(unittest.TestCase):
    def test_a_sealed_full_pass_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            sealed_pass(Path(tmp))
            self.assertEqual(lab_evidence.check(Path(tmp), COMMIT), [])

    def test_each_shortfall_is_refused(self):
        for name, (spoil, expected) in REFUSED.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                sealed_pass(directory)
                spoil(directory)
                errors = lab_evidence.check(directory, COMMIT)
                self.assertTrue(any(expected in line for line in errors), errors)

    def test_a_short_commit_id_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            sealed_pass(Path(tmp))
            self.assertTrue(lab_evidence.check(Path(tmp), COMMIT[:12]))

    def test_the_command_exits_1_on_a_refusal_and_0_on_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            sealed_pass(directory)
            self.assertEqual(lab_evidence.main(["check", str(directory), "--commit", COMMIT]), 0)
            (directory / "extra.json").write_text("{}")
            self.assertEqual(lab_evidence.main(["check", str(directory), "--commit", COMMIT]), 1)


class Attestation(unittest.TestCase):
    def ask(self, tools, gh):
        with tempfile.TemporaryDirectory() as tmp:
            sealed_pass(Path(tmp))
            return lab_evidence.attestation_errors(Path(tmp), COMMIT, REPO, WORKFLOW, REF, gh=gh)

    def test_gh_is_asked_about_the_commit_the_workflow_and_the_ref(self):
        with tempfile.TemporaryDirectory() as tools:
            gh = fake_gh(Path(tools), 0)
            self.assertEqual(self.ask(tools, gh), [])
            asked = (Path(tools) / "gh-arguments").read_text()
            for wanted in (
                "attestation verify",
                f"--repo {REPO}",
                f"--signer-workflow {WORKFLOW}",
                f"--source-digest {COMMIT}",
                f"--source-ref {REF}",
                "--deny-self-hosted-runners",
            ):
                self.assertIn(wanted, asked)

    def test_a_refusal_from_gh_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as tools:
            self.assertTrue(self.ask(tools, fake_gh(Path(tools), 1)))

    def test_no_gh_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as tools:
            self.assertTrue(self.ask(tools, os.path.join(tools, "absent-gh")))


if __name__ == "__main__":
    unittest.main()

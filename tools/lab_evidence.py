"""Seal and judge the output of one root lab run.

manifest DIR   write DIR/manifest.json: the commit, the image, the run, and the
               sha256 of every other file in DIR.
check DIR      refuse DIR unless every file matches the manifest, the manifest
               names the expected commit, and the results in it are a full pass.
verify DIR     check, then ask `gh attestation verify` whether GitHub signed the
               manifest for that commit from the lab workflow.

Each command prints one line per problem and exits 1 if there is any. Standard
library only, so it runs on a machine that has nothing but Python and gh.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

MANIFEST = "manifest.json"
HONEST = {"attack": "attack-suite-honest.json", "live": "live-suite-honest.json"}
CONTROLS = {"attack": "attack-suite.json", "live": "live-suite.json"}
ENVIRONMENT = "environment.txt"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_ID = re.compile(r"[0-9a-f]{40}")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files_in(directory):
    return {
        path.relative_to(directory).as_posix(): path
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name != MANIFEST
    }


def write_manifest(directory, commit, image, run):
    manifest = {
        "schema": 1,
        "commit": commit,
        "image": image,
        "run": run,
        "files": {name: sha256(path) for name, path in files_in(directory).items()},
    }
    (directory / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def manifest_errors(directory, commit):
    path = directory / MANIFEST
    if not path.is_file():
        return None, [f"{MANIFEST} is missing"]
    try:
        manifest = json.loads(path.read_text())
    except ValueError as error:
        return None, [f"{MANIFEST} is not JSON: {error}"]
    listed = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(listed, dict):
        return None, [f"{MANIFEST} has no file list"]
    errors = []
    if manifest.get("schema") != 1:
        errors.append(f"{MANIFEST} has schema {manifest.get('schema')!r}, not 1")
    if manifest.get("commit") != commit:
        errors.append(f"{MANIFEST} is for commit {manifest.get('commit')!r}, not {commit}")
    if not IMAGE_ID.fullmatch(str(manifest.get("image"))):
        errors.append(f"{MANIFEST} names no image id: {manifest.get('image')!r}")
    present = files_in(directory)
    for name in sorted(set(listed) - set(present)):
        errors.append(f"{name} is in the manifest and not in the directory")
    for name in sorted(set(present) - set(listed)):
        errors.append(f"{name} is in the directory and not in the manifest")
    for name in sorted(set(present) & set(listed)):
        if sha256(present[name]) != listed[name]:
            errors.append(f"{name} differs from the manifest")
    return manifest, errors


def load(directory, name, errors):
    path = directory / name
    if not path.is_file():
        errors.append(f"{name} is missing")
        return None
    try:
        data = json.loads(path.read_text())
    except ValueError as error:
        errors.append(f"{name} is not JSON: {error}")
        return None
    if not isinstance(data, dict):
        errors.append(f"{name} is not a JSON object")
        return None
    return data


def build_of(data, which):
    build = (data.get("build") or {}).get(which) or {}
    return build.get("binary_sha256"), build.get("sabotage")


def honest_errors(name, data):
    errors = []
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        return [f"{name} records no runs"]
    if data.get("runs_total") != len(runs):
        errors.append(f"{name} says {data.get('runs_total')} runs and lists {len(runs)}")
    if data.get("runs_passed") != len(runs):
        errors.append(f"{name} says {data.get('runs_passed')} of {len(runs)} runs passed")
    for run in runs:
        failed = [check.get("name") for check in run.get("checks") or [] if check.get("passed") is not True]
        if run.get("passed") is not True or failed or not run.get("checks"):
            errors.append(f"{name}: {run.get('scenario')} did not pass: {failed}")
    if build_of(data, "honest")[1] is not False:
        errors.append(f"{name} was not made by a build without the sabotage feature")
    for key in ("cgroup_limits_waived", "controls_cgroup_limits_waived"):
        if data.get(key):
            errors.append(f"{name} ran with cgroup limits waived ({key})")
    for run in runs:
        for check in run.get("checks") or []:
            detail = check.get("detail")
            if isinstance(detail, dict) and detail.get("waived"):
                errors.append(f"{name}: {run.get('scenario')} waived {check.get('name')}: {detail['waived']}")
    return errors


def controls_errors(name, data, honest):
    errors = []
    controls = data.get("sabotage")
    if not isinstance(controls, list) or not controls:
        return [f"{name} records no sabotage controls"]
    if data.get("sabotage_total") != len(controls):
        errors.append(f"{name} says {data.get('sabotage_total')} controls and lists {len(controls)}")
    if data.get("sabotage_detected") != len(controls):
        errors.append(f"{name} says {data.get('sabotage_detected')} of {len(controls)} controls were caught")
    for control in controls:
        if control.get("detected") is not True:
            errors.append(f"{name}: control {control.get('weakness')} on {control.get('scenario')} was not caught")
    honest_sha, _ = build_of(data, "honest")
    sabotage_sha, sabotaged = build_of(data, "sabotage")
    if sabotaged is not True:
        errors.append(f"{name}: the controls were not run by a build with the sabotage feature")
    if not honest_sha or honest_sha == sabotage_sha:
        errors.append(f"{name}: the honest and sabotage builds are not two different binaries")
    if honest is not None and honest_sha != build_of(honest, "honest")[0]:
        errors.append(f"{name}: the controls were judged against another honest build")
    if honest is not None and data.get("runs") != honest.get("runs"):
        errors.append(f"{name}: the honest runs it carries are not the ones in the honest file")
    return errors


def result_errors(directory, commit):
    errors = []
    environment = directory / ENVIRONMENT
    if not environment.is_file():
        errors.append(f"{ENVIRONMENT} is missing")
    elif f"commit id: {commit}\n" not in environment.read_text():
        errors.append(f"{ENVIRONMENT} is not for commit {commit}")
    for suite in HONEST:
        honest = load(directory, HONEST[suite], errors)
        if honest is not None:
            errors += honest_errors(HONEST[suite], honest)
        controls = load(directory, CONTROLS[suite], errors)
        if controls is not None:
            errors += controls_errors(CONTROLS[suite], controls, honest)
    return errors


def check(directory, commit):
    if not COMMIT_ID.fullmatch(commit):
        return [f"{commit!r} is not a full commit id"]
    _, errors = manifest_errors(directory, commit)
    return errors + result_errors(directory, commit)


def attestation_errors(directory, commit, repo, signer_workflow, source_ref, gh="gh"):
    if shutil.which(gh) is None:
        return [f"{gh} is not installed, so the attestation cannot be checked"]
    command = [
        gh, "attestation", "verify", str(directory / MANIFEST),
        "--repo", repo,
        "--signer-workflow", signer_workflow,
        "--source-digest", commit,
        "--source-ref", source_ref,
        "--deny-self-hosted-runners",
    ]
    done = subprocess.run(command, capture_output=True, text=True)
    sys.stderr.write(done.stdout + done.stderr)
    if done.returncode != 0:
        return [f"no attestation of {MANIFEST} by {signer_workflow} at {source_ref} for commit {commit}"]
    return []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("manifest")
    make.add_argument("directory", type=Path)
    make.add_argument("--commit", required=True)
    make.add_argument("--image", required=True)
    make.add_argument("--run", action="append", default=[], metavar="KEY=VALUE")
    for name in ("check", "verify"):
        judge = commands.add_parser(name)
        judge.add_argument("directory", type=Path)
        judge.add_argument("--commit", required=True)
        if name == "verify":
            judge.add_argument("--repo", required=True)
            judge.add_argument("--signer-workflow", required=True)
            judge.add_argument("--source-ref", required=True)
    args = parser.parse_args(argv)

    if args.command == "manifest":
        run = dict(pair.split("=", 1) for pair in args.run)
        manifest = write_manifest(args.directory, args.commit, args.image, run)
        print(f"lab-evidence: sealed {len(manifest['files'])} files for commit {args.commit}")
        return 0

    errors = check(args.directory, args.commit)
    if args.command == "verify" and not errors:
        errors = attestation_errors(args.directory, args.commit, args.repo, args.signer_workflow, args.source_ref)
    for line in errors:
        print(f"lab-evidence: {line}")
    if errors:
        print(f"lab-evidence: REFUSED, {len(errors)} problems")
        return 1
    print(f"lab-evidence: ACCEPTED for commit {args.commit}" + (" with a valid attestation" if args.command == "verify" else ", attestation not checked"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

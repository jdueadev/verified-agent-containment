#!/usr/bin/env python3
"""Attested lab evidence (CI-10, #209): a CI lab run's files carry a GitHub OIDC token
that binds their bytes to the run that made them.

Usage:
  lab_attest.py audience DIR       print the audience to request for a run directory
  lab_attest.py provenance --dir DIR --token FILE --run-id N --run-attempt N --out FILE
  lab_attest.py verify [--root DIR] check every tracked results/ci/lab-* (CI-10)
  lab_attest.py refresh-keys       re-pin GitHub's OIDC public keys

How it works. The `attest` job in .github/workflows/lab.yaml runs on a push, in the
`evidence` environment, on a runner that never builds or runs host code. It reads the
lab job's artifact, computes a manifest of SHA-256 digests (MANIFEST_NAMES maps each
file to the name it is committed under) and asks GitHub for an OIDC token whose
audience is AUDIENCE_PREFIX + sha256(manifest). GitHub signs that token and sets
event_name, ref, sha, workflow_ref, job_workflow_ref, environment and repository_id
itself, so a job in a pull request cannot obtain one that claims a push to an allowed
ref from lab.yaml in the evidence environment, and nobody can sign one without
GitHub's key. The record job commits the files byte for byte with provenance.json
(the manifest, the token, the run id and attempt).

CI-10 then holds for every tracked results/ci/lab-<sha>/ not listed as legacy in
ci/lab-attestation.toml: provenance.json is present; the committed files are exactly
the manifest's and hash to it; the token verifies under a key pinned in
ci/github-oidc-jwks.json; and its claims name this repository (by id, which survives
a transfer), lab.yaml at an allowed ref, a push, the evidence environment, the
directory's own commit, and the manifest's digest as audience.

What it proves: main's lab.yaml, at that commit, in that run, produced these bytes. It
does not prove the host code under test is honest; that code ran as root in the lab
job (decision 0004). Each error names the fix.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_check  # noqa: E402  (RS256 verification and the issuer, trusted base)

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = "ci/lab-attestation.toml"
KEYS_FILE = "ci/github-oidc-jwks.json"
PROVENANCE = "provenance.json"
LAB_DIR = re.compile(r"^results/ci/lab-([0-9a-f]{40})/")
# Committed name -> name in the lab job's artifact (scripts/lab/ci-lab.sh). The same
# mapping as tools/lab_record.py's SUITES, plus the environment file.
# The directories recorded before attestation existed. A legacy list in POLICY_FILE may
# name only these, so a new unattested directory cannot be waved through by listing it.
FROZEN_LEGACY = frozenset({
    "results/ci/lab-9263878b598c472f65aa58b3116ed959323b98fa",
    "results/ci/lab-a38ad0086aec46c6b33229f43da52065e8c76e11",
})
MANIFEST_NAMES = {
    "attack-suite.json": "attack-suite-local.json",
    "live-suite.json": "live-suite-local.json",
    "environment.txt": "environment.txt",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run_manifest(run_dir):
    """{committed name: sha256} over the lab job's artifact, or ValueError."""
    run_dir = Path(run_dir)
    out = {}
    for name, source in MANIFEST_NAMES.items():
        path = run_dir / source
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{path} is missing")
        out[name] = sha256(path.read_bytes())
    return out


def audience(policy, manifest):
    return policy["audience_prefix"] + sha256(canonical(manifest))


def load_policy(text):
    policy = tomllib.loads(text)
    need = {"repository_id": str, "workflow": str, "environment": str, "refs": list,
            "audience_prefix": str, "legacy": list}
    for key, kind in need.items():
        if not isinstance(policy.get(key), kind):
            raise ValueError(f"{POLICY_FILE}: {key} must be a {kind.__name__}")
    extra = set(policy["legacy"]) - FROZEN_LEGACY
    if extra:
        raise ValueError(f"{POLICY_FILE}: legacy may only name directories recorded before attestation "
                         f"(FROZEN_LEGACY in tools/lab_attest.py), not {sorted(extra)}; attest new evidence instead")
    return policy


def claim_problems(claims, policy, commit, aud):
    """Why these token claims do not prove the run, as a list (empty when they do)."""
    wrong = []
    expect = {"iss": gate_check.ISSUER, "event_name": "push", "sha": commit,
              "environment": policy["environment"], "repository_id": policy["repository_id"]}
    for key, value in expect.items():
        if claims.get(key) != value:
            wrong.append(f"{key} is {claims.get(key)!r}, not {value!r}")
    got_aud = claims.get("aud")
    if not (got_aud == aud or (isinstance(got_aud, list) and aud in got_aud)):
        wrong.append("aud does not match the manifest of the committed files")
    ref = claims.get("ref")
    if ref not in policy["refs"]:
        wrong.append(f"ref {ref!r} is not one of {policy['refs']}")
    suffix = f"/{policy['workflow']}@{ref}"
    for key in ("workflow_ref", "job_workflow_ref"):
        if not str(claims.get(key, "")).endswith(suffix):
            wrong.append(f"{key} {claims.get(key)!r} is not {policy['workflow']} at {ref}")
    return wrong


def verify_dir(where, files, commit, policy, keys):
    """CI-10 errors for one recorded directory. `files` maps each file name in it to its bytes."""
    tag = f"CI-10 {where}"
    if PROVENANCE not in files:
        return [f"{tag}: no {PROVENANCE}. CI lab evidence is written only by lab.yaml's record job, "
                f"from an attested run; to add evidence, run the lab on main (or list a pre-attestation "
                f"directory under legacy in {POLICY_FILE})"]
    try:
        prov = json.loads(files[PROVENANCE])
        manifest, token = prov["manifest"], prov["token"]
        if not isinstance(manifest, dict) or not isinstance(token, str):
            raise ValueError("manifest must be an object and token a string")
    except (ValueError, KeyError, TypeError) as error:
        return [f"{tag}: {PROVENANCE} is not a provenance record ({error})"]
    errors = []
    committed = {name for name in files if name != PROVENANCE}
    if committed != set(manifest):
        errors.append(f"{tag}: the files {sorted(committed)} are not the attested set {sorted(manifest)}")
    for name in sorted(committed & set(manifest)):
        if sha256(files[name]) != manifest[name]:
            errors.append(f"{tag}/{name}: differs from the attested manifest. Evidence is committed byte for "
                          f"byte by the record job; never edit it (INV-1)")
    try:
        claims = gate_check.verify_rs256(token, keys)
    except ValueError as error:
        if "no single key" in str(error):
            return errors + [f"{tag}: the token's signing key is not pinned ({error}). If GitHub rotated its "
                             f"keys, run `python3 tools/lab_attest.py refresh-keys` and commit {KEYS_FILE}"]
        return errors + [f"{tag}: the token does not verify ({error})"]
    if not isinstance(claims, dict):
        return errors + [f"{tag}: the token's claims are not an object"]
    errors += [f"{tag}: token {p}" for p in claim_problems(claims, policy, commit, audience(policy, manifest))]
    return errors


def tracked_lab_files(root, tracked=None):
    """{directory: {file name: bytes}} for every tracked file under results/ci/lab-<sha>/."""
    root = Path(root)
    if tracked is None:
        tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", "results/ci/"],
                                 capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    out = {}
    for path in tracked:
        match = LAB_DIR.match(path)
        if not match:
            continue
        where = path[:match.end() - 1]
        rest = path[match.end():]
        if "/" in rest:
            # A nested path is never part of an attested set.
            out.setdefault(where, {})[rest] = b"\0nested"
            continue
        out.setdefault(where, {})[rest] = (root / path).read_bytes()
    return out


def tree_errors(root=ROOT, tracked=None, policy=None, keys=None):
    """CI-10 over a checkout: every tracked results/ci/lab-<sha>/ not on the legacy list."""
    root = Path(root)
    try:
        policy = policy or load_policy((root / POLICY_FILE).read_text(encoding="utf-8"))
        keys = keys or json.loads((root / KEYS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"CI-10 cannot read {POLICY_FILE} or {KEYS_FILE}: {error}"]
    try:
        dirs = tracked_lab_files(root, tracked)
    except (OSError, subprocess.CalledProcessError) as error:
        return [f"CI-10 git could not list results/ci/, so lab provenance was not checked ({error})"]
    errors = []
    for where, files in sorted(dirs.items()):
        if where in policy["legacy"]:
            continue
        errors += verify_dir(where, files, LAB_DIR.match(where + "/").group(1), policy, keys)
    return errors


def provenance_record(run_dir, token, run_id, run_attempt):
    return {"manifest": run_manifest(run_dir), "token": token.strip(),
            "run_id": str(run_id), "run_attempt": str(run_attempt)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audience")
    a.add_argument("dir")
    p = sub.add_parser("provenance")
    for name in ("--dir", "--token", "--run-id", "--run-attempt", "--out"):
        p.add_argument(name, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--root", default=str(ROOT))
    sub.add_parser("refresh-keys")
    args = parser.parse_args(argv)

    if args.command == "audience":
        policy = load_policy((ROOT / POLICY_FILE).read_text(encoding="utf-8"))
        print(audience(policy, run_manifest(args.dir)))
        return 0
    if args.command == "provenance":
        record = provenance_record(args.dir, Path(args.token).read_text(encoding="utf-8"),
                                   args.run_id, args.run_attempt)
        Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    if args.command == "verify":
        errors = tree_errors(Path(args.root))
        print(json.dumps({"errors": errors}, indent=2))
        return 1 if errors else 0
    with urllib.request.urlopen(gate_check.JWKS_URL, timeout=20) as response:
        keys = json.loads(response.read())
    pinned = {"keys": sorted(({k: key[k] for k in ("kty", "kid", "alg", "use", "n", "e") if k in key}
                              for key in keys.get("keys", []) if key.get("kty") == "RSA"),
                             key=lambda key: key["kid"])}
    if not pinned["keys"]:
        sys.exit(f"refresh-keys: {gate_check.JWKS_URL} returned no RSA keys")
    (ROOT / KEYS_FILE).write_text(json.dumps(pinned, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"pinned {len(pinned['keys'])} keys in {KEYS_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

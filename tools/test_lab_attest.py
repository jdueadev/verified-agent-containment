#!/usr/bin/env python3
"""Tests for tools/lab_attest.py and CI-10 (#209): lab evidence counts only with a GitHub
OIDC token from main's lab.yaml whose audience binds every committed byte.

Tokens here are signed with a fixed test key (TEST_KEYS), never GitHub's. Each test
that rejects a token changes one claim or one byte, so each check is seen to bite.
"""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_check
import lab_attest as la
import lab_record

ROOT = Path(__file__).resolve().parent.parent
COMMIT = "1" * 40
WHERE = f"results/ci/lab-{COMMIT}"

# A 2048-bit RSA key made for these tests only.
N = int(
    "cca71ffc164ff46b0bd65363cc01ad29e9b77ad17a826e5872aa64b5a57c88b80bf9dcef2e974912bec78928"
    "b13a479042453239e2362adcc98888cba8aab1f8284344a86cdf58e8dff59fb7f6923aaa8c5d016a3d49cf0c"
    "a12865b8854121ea163449419e0d8c74e832efcb59989a680c36f2b9ecf64950c3f8cd73fa937b522ce08148"
    "f4c55da0176b1ecdfe44ba58f4cea2ef9f94ff3080ff64d0014249e968c474517f8edd83a172c4164e828243"
    "ddb7d71a171ba7c9e8099faa359087790ce4711342d679826ba86c9eca4e8b9d19e62895ea94198a7688a670"
    "acdf8850b5ea3a2e95575fae0f9e17d6c33ba0ccee2b44343991ccb4d1bc8c22cc98cd53", 16)
D = int(
    "8972f59869a3e994bbae86f34fe1105c460c6500ac374dc539be1745a88fab837107afcb348f87147feda3c1"
    "20c6f3a97fd8d992e6cb5a9e4efcd4637434b0b2ead7c3151b8a263cc1ae464757e37e636d4249e100a8c1d6"
    "c9a6482b55d418e30f66ae8cd38a65fb5eb857354c47a1ec9fc787de37b872253c79ae036718068a47032203"
    "2e110ac5d306365b4023f715529d42da77ce93138fcece0f8bd704a9629b70cb5a1574438741c2c4906dced4"
    "e3c6e496f5a8ed257553c597173877fbd2e3fb82c9dd2911000310627f36b319269e8b833d3ec15fe3f125a1"
    "e74b6871b2d7f9698501245e56299506b29203748100fd6fbd109cc5cb4718cc1a9ccc9", 16)
E = 65537
KID = "test-key"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def int_b64(value):
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


TEST_KEYS = {"keys": [{"kty": "RSA", "kid": KID, "alg": "RS256", "n": int_b64(N), "e": int_b64(E)}]}


def sign(claims, kid=KID, d=D):
    head = b64(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    digest = hashlib.sha256(f"{head}.{body}".encode("ascii")).digest()
    size = (N.bit_length() + 7) // 8
    padded = (b"\x00\x01" + b"\xff" * (size - len(gate_check.SHA256_INFO) - len(digest) - 3) + b"\x00"
              + gate_check.SHA256_INFO + digest)
    signature = pow(int.from_bytes(padded, "big"), d, N).to_bytes(size, "big")
    return f"{head}.{body}.{b64(signature)}"


POLICY = la.load_policy((ROOT / la.POLICY_FILE).read_text(encoding="utf-8"))
FILES = {"attack-suite.json": b'{"suite": "attack"}\n', "live-suite.json": b'{"suite": "live"}\n',
         "environment.txt": b"commit=" + COMMIT.encode() + b"\n"}


def manifest(files=FILES):
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def good_claims(files=FILES, **changes):
    ref = changes.pop("ref", "refs/heads/main")
    claims = {
        "iss": gate_check.ISSUER, "aud": la.audience(POLICY, manifest(files)), "event_name": "push",
        "ref": ref, "sha": COMMIT, "environment": "evidence", "repository_id": POLICY["repository_id"],
        "workflow_ref": f"owner/repo/.github/workflows/lab.yaml@{ref}",
        "job_workflow_ref": f"owner/repo/.github/workflows/lab.yaml@{ref}",
        "run_id": "42",
    }
    claims.update(changes)
    return claims


def recorded(claims=None, files=FILES, token=None, prov_manifest=None):
    """The files of one recorded directory, provenance.json included."""
    token = token if token is not None else sign(claims if claims is not None else good_claims(files))
    prov = {"manifest": prov_manifest if prov_manifest is not None else manifest(files),
            "token": token, "run_id": "42", "run_attempt": "1"}
    return dict(files, **{la.PROVENANCE: json.dumps(prov).encode()})


def errors(files):
    return la.verify_dir(WHERE, files, COMMIT, POLICY, TEST_KEYS)


class VerifyTests(unittest.TestCase):
    def test_an_attested_run_passes(self):
        self.assertEqual(errors(recorded()), [])

    def test_each_claim_must_name_main_lab_yaml_in_the_evidence_environment(self):
        bad = {
            "event_name": {"event_name": "pull_request"},
            "ref": {"ref": "refs/pull/1/merge"},
            "environment": {"environment": "gate"},
            "repository_id": {"repository_id": "1"},
            "workflow_ref": {"workflow_ref": "owner/repo/.github/workflows/check.yml@refs/heads/main"},
            "job_workflow_ref": {"job_workflow_ref": "owner/repo/.github/workflows/check.yml@refs/heads/main"},
            "sha": {"sha": "2" * 40},
            "iss": {"iss": "https://example.com"},
            "aud": {"aud": "lab-evidence:" + "0" * 64},
        }
        for name, change in bad.items():
            with self.subTest(claim=name):
                found = errors(recorded(good_claims(**change)))
                self.assertTrue(any(name in e for e in found), found)

    def test_a_byte_changed_after_the_run_fails(self):
        files = recorded()
        files["attack-suite.json"] = b'{"suite": "attack", "passed": true}\n'
        found = errors(files)
        self.assertTrue(any("attack-suite.json: differs from the attested manifest" in e for e in found), found)

    def test_a_manifest_rewritten_to_match_new_bytes_no_longer_matches_the_token(self):
        edited = dict(FILES, **{"attack-suite.json": b'{"forged": true}\n'})
        files = recorded(good_claims(FILES), files=edited, prov_manifest=manifest(edited))
        found = errors(files)
        self.assertTrue(any("aud does not match" in e for e in found), found)

    def test_an_added_or_missing_file_fails(self):
        files = recorded()
        files["extra.json"] = b"{}"
        self.assertTrue(any("not the attested set" in e for e in errors(files)))
        files = recorded()
        del files["live-suite.json"]
        self.assertTrue(any("not the attested set" in e for e in errors(files)))

    def test_a_token_from_an_unpinned_key_names_the_fix(self):
        found = errors(recorded(token=sign(good_claims(), kid="rotated")))
        self.assertTrue(any("refresh-keys" in e for e in found), found)

    def test_a_forged_signature_fails(self):
        found = errors(recorded(token=sign(good_claims(), d=D - 2)))
        self.assertTrue(any("does not verify" in e for e in found), found)

    def test_no_provenance_fails_and_says_how_evidence_is_made(self):
        found = errors(dict(FILES))
        self.assertEqual(len(found), 1)
        self.assertIn("written only by lab.yaml's record job", found[0])

    def test_unreadable_provenance_fails(self):
        self.assertTrue(errors(dict(FILES, **{la.PROVENANCE: b"not json"})))


class TreeTests(unittest.TestCase):
    def tree(self, extra):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        tracked = []
        for where, files in extra.items():
            for name, data in files.items():
                path = tmp / where / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                tracked.append(f"{where}/{name}")
        return tmp, tracked

    def test_a_new_unattested_directory_fails_and_legacy_ones_pass(self):
        legacy = sorted(la.FROZEN_LEGACY)[0]
        root, tracked = self.tree({legacy: FILES, WHERE: FILES})
        found = la.tree_errors(root, tracked, POLICY, TEST_KEYS)
        self.assertEqual([e.split(":")[0] for e in found], [f"CI-10 {WHERE}"])

    def test_an_attested_directory_passes(self):
        root, tracked = self.tree({WHERE: recorded()})
        self.assertEqual(la.tree_errors(root, tracked, POLICY, TEST_KEYS), [])

    def test_a_nested_file_is_never_part_of_the_attested_set(self):
        files = recorded()
        files["sub/attack-suite.json"] = b"{}"
        root, tracked = self.tree({WHERE: files})
        self.assertTrue(la.tree_errors(root, tracked, POLICY, TEST_KEYS))

    def test_the_legacy_list_cannot_grow(self):
        text = (ROOT / la.POLICY_FILE).read_text(encoding="utf-8").replace(
            "legacy = [", f'legacy = [\n  "{WHERE}",', 1)
        with self.assertRaises(ValueError) as caught:
            la.load_policy(text)
        self.assertIn("attest new evidence", str(caught.exception))

    def test_the_committed_tree_passes_ci_10(self):
        self.assertEqual(la.tree_errors(ROOT), [])

    def test_pinned_keys_are_rsa_and_named(self):
        keys = json.loads((ROOT / la.KEYS_FILE).read_text(encoding="utf-8"))["keys"]
        self.assertTrue(keys)
        for key in keys:
            self.assertEqual(key["kty"], "RSA")
            self.assertTrue(key["kid"])


class KeyRefreshTests(unittest.TestCase):
    def key(self, kid, n="AQAB"):
        return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": "AQAB"}

    def test_a_key_github_rotated_out_stays_pinned(self):
        merged = la.merge_keys({"keys": [self.key("old")]}, {"keys": [self.key("new"), {"kty": "EC", "kid": "x"}]})
        self.assertEqual([k["kid"] for k in merged["keys"]], ["new", "old"])

    def test_a_pinned_kid_with_new_material_is_refused(self):
        with self.assertRaises(ValueError):
            la.merge_keys({"keys": [self.key("k", n="AAAA")]}, {"keys": [self.key("k", n="BBBB")]})

    def test_refetching_the_same_keys_changes_nothing(self):
        pinned = {"keys": [self.key("a"), self.key("b")]}
        self.assertEqual(la.merge_keys(pinned, {"keys": [self.key("b"), self.key("a")]}), pinned)


class RecordTests(unittest.TestCase):
    def test_the_manifest_names_match_what_lab_record_commits(self):
        self.assertEqual({k: v for k, v in la.MANIFEST_NAMES.items() if k in lab_record.SUITES},
                         lab_record.SUITES)
        self.assertEqual(la.MANIFEST_NAMES[lab_record.ENVIRONMENT], lab_record.ENVIRONMENT)

    def test_run_manifest_hashes_the_raw_artifact_bytes(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        for name, source in la.MANIFEST_NAMES.items():
            (tmp / source).write_bytes(FILES[name])
        self.assertEqual(la.run_manifest(tmp), manifest())
        (tmp / "live-suite-local.json").unlink()
        with self.assertRaises(ValueError):
            la.run_manifest(tmp)


if __name__ == "__main__":
    unittest.main()

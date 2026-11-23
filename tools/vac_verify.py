import json
import subprocess
import tomllib
from pathlib import Path

SYNC_FILE = "results/formal-sync.json"
FORMAL_STATUSES = ("proved", "checked-bounded")
FORMAL_LAYERS = ("bend-kernel", "rust-kernel")
PROOF_INPUTS = ("formal/kernel.bend", "formal/LAWS.bend", "formal/PROOF.bend")


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


def formal_claims(root):
    claims = tomllib.loads((Path(root) / "claims.toml").read_text(encoding="utf-8")).get("claim", [])
    out = {}
    for c in claims:
        if c.get("platforms") or c.get("status") == "planned":
            continue
        if c.get("status") in FORMAL_STATUSES or c.get("layer") in FORMAL_LAYERS:
            out[c["id"]] = sorted(set(c.get("files", [])) | set(PROOF_INPUTS))
    return out


def load_sync(root):
    path = Path(root) / SYNC_FILE
    return json.loads(path.read_text(encoding="utf-8")).get("claims", {}) if path.exists() else {}


def changed_since(root, commit, files):
    known = git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    if known.returncode != 0:
        return None
    diff = git(root, "diff", "--name-only", commit, "--", *files)
    return [p for p in diff.stdout.splitlines() if p]


def stale(root):
    sync, out = load_sync(root), {}
    for cid, files in formal_claims(root).items():
        entry = sync.get(cid)
        if entry is None:
            out[cid] = ["never synced"]
            continue
        changed = changed_since(root, entry["synced_at"], files)
        if changed is None:
            out[cid] = [f"synced_at {entry['synced_at'][:12]} is not in this history"]
        elif changed:
            out[cid] = changed
    return out


def touched(root, base):
    diff = git(root, "diff", "--name-only", f"{base}...HEAD")
    paths = set(diff.stdout.split()) | set(git(root, "diff", "--name-only", "HEAD").stdout.split())
    return {cid: sorted(paths & set(files)) for cid, files in formal_claims(root).items() if paths & set(files)}


def record(root, head):
    claims = formal_claims(root)
    data = {"claims": {cid: {"synced_at": head, "files": files} for cid, files in sorted(claims.items())}}
    (Path(root) / SYNC_FILE).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sorted(claims)

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

policy_check = importlib.import_module("policy_check")

CORE_STATUSES = ("proved", "checked-bounded", "tested")
SUITE_KINDS = {"crates/containment-host/src/harness.rs": ("scenario", "sabotage"),
               "crates/containment-host/src/live_suite.rs": ("live", "live-sabotage")}
KERNEL_SPEC = "crates/containment-kernel/tests/"
WAIVERS_FILE = "ci/waivers.toml"


def core(get):
    claims = tomllib.loads(get("claims.toml") or "").get("claim", [])
    cited, ids = set(), {}
    for c in claims:
        if c.get("status") in CORE_STATUSES:
            ids[c["id"]] = c["status"]
            cited.update(c.get("evidence", []))
    return {"claims": ids, "refs": cited}


def core_reason(reason, c):
    refs = c["refs"]
    if m := re.match(r"^law (\S+) was ", reason):
        return f"law:{m.group(1)}" in refs
    if m := re.match(r"^mutant (\S+) was ", reason):
        return f"mutant:{m.group(1)}" in refs or f"rust-mutant:{m.group(1)}" in refs
    if m := re.match(r"^claim ([A-Z0-9-]+)", reason):
        return m.group(1) in c["claims"]
    for path, kinds in SUITE_KINDS.items():
        if reason.startswith(path + ": "):
            name = reason[len(path) + 2:].split(" ")[0]
            return any(f"{k}:{name}" in refs for k in kinds) or " was " not in reason
    if KERNEL_SPEC in reason:
        return True
    return False


def status_drops(base_core, head_get):
    head = {c["id"]: c.get("status") for c in tomllib.loads(head_get("claims.toml") or "").get("claim", [])}
    rank = policy_check.RANK
    return [f"claim {cid}: status lowered from {old} to {head.get(cid)}" for cid, old in sorted(base_core["claims"].items())
            if rank.get(head.get(cid), -1) < rank[old]]


def escalation_reasons(base, head_get, base_get, paths):
    return (policy_check.ratchets(base_get, head_get) + policy_check.spec_ratchets(paths, base_get, head_get)
            + policy_check.data_module_ratchets(paths, head_get))


def split(reasons, c):
    return [r for r in reasons if core_reason(r, c)], [r for r in reasons if not core_reason(r, c)]


def law_kill_gaps(c, mutation_report):
    killed = {law for m in mutation_report.get("bend", []) for law in m.get("laws_violated", [])}
    return sorted(r[4:] for r in c["refs"] if r.startswith("law:") and r[4:] not in killed)


def rejected_names(report):
    return {m["mutant"] for key in ("bend", "rust") for m in report.get(key, []) if m.get("rejected")}


def mutation_regressions(base_report, head_report):
    return sorted(rejected_names(base_report) - rejected_names(head_report))


def git(root, *args, check=True):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=check).stdout


def step(name, argv, cwd, timeout=7200):
    child = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    tail = (child.stdout + child.stderr).strip().splitlines()[-3:]
    return {"step": name, "ok": child.returncode == 0, "exit": child.returncode, "tail": tail}


def loop(root, base, head="HEAD", run_tools=True):
    root = Path(root)
    head_sha = git(root, "rev-parse", "--verify", f"{head}^{{commit}}").strip()
    base_sha = git(root, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
    base_get, head_get = policy_check.reader(base_sha), policy_check.reader(head_sha)
    paths = [p for p in git(root, "diff", "--name-only", "--no-renames", base_sha, head_sha).splitlines() if p]
    c = core(base_get)
    reasons = escalation_reasons(base_sha, head_get, base_get, paths)
    core_hits, waivable = split(reasons, c)
    core_hits += status_drops(c, head_get)
    steps = [{"step": "core-unchanged", "ok": not core_hits, "detail": core_hits}]
    if run_tools and not core_hits:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "head"
            git(root, "worktree", "add", "--detach", "-q", str(work), head_sha)
            try:
                steps += run_formal(work, base_get, c, paths)
            finally:
                git(root, "worktree", "remove", "--force", str(work), check=False)
    ok = all(s["ok"] for s in steps)
    receipt = {"base": base_sha, "head": head_sha, "ok": ok, "waivable": waivable, "steps": steps}
    receipt["digest"] = hashlib.sha256(json.dumps(receipt, sort_keys=True).encode()).hexdigest()
    return receipt


def run_formal(work, base_get, c, paths):
    out = []
    formal = any(p.startswith("formal/") for p in paths)
    kernel = any(p.startswith(("formal/", "crates/containment-kernel/", "tools/kernel_mutants.py", "tools/law_audit.mjs"))
                 for p in paths)
    host_model = any(p.startswith("formal/host/") for p in paths)
    out.append(step("bend-proof", ["bend", "PROOF.bend", "--check-only"], work / "formal"))
    if formal:
        out.append(step("lean-verdict", ["bash", "scripts/verdict.sh"], work))
    if host_model:
        out.append(step("tlc", ["bash", "tools/tla_check.sh"], work))
    out.append(step("kernel-tests", ["cargo", "test", "-q", "--locked", "-p", "containment-kernel"], work))
    if kernel:
        (work / "target/generated").mkdir(parents=True, exist_ok=True)
        out.append(step("bend-build", ["bend", "formal/kernel.bend", "-o", "target/generated/kernel.mjs"], work))
        mutation = step("mutation", [sys.executable, "tools/mutation_check.py", "target/generated/kernel.mjs",
                                     "target/safety-mutation.json"], work)
        out.append(mutation)
        if mutation["ok"]:
            head_report = json.loads((work / "target/safety-mutation.json").read_text(encoding="utf-8"))
            base_report = json.loads(base_get("results/mutation-check.json") or "{}")
            gaps = law_kill_gaps(c, head_report)
            lost = mutation_regressions(base_report, head_report)
            out.append({"step": "law-kill", "ok": not gaps, "detail": gaps})
            out.append({"step": "mutants-still-rejected", "ok": not lost, "detail": lost})
    claims = step("claims", [sys.executable, "tools/claims_check.py"], work)
    out.append(claims)
    return out


def load_waivers(text):
    data = tomllib.loads(text or "")
    rows = data.get("waiver", [])
    for row in rows:
        if not (isinstance(row.get("reason"), str) and isinstance(row.get("issue"), int)
                and re.fullmatch(r"[0-9a-f]{64}", str(row.get("receipt", ""))) and re.fullmatch(r"[0-9a-f]{40}", str(row.get("head", "")))):
            raise ValueError(f"{WAIVERS_FILE}: each waiver needs reason (text), issue (number), receipt (sha256), head (commit)")
    return rows


def waiver_toml(rows):
    out = []
    for row in rows:
        out.append("[[waiver]]\n" + "".join(f"{k} = {json.dumps(row[k])}\n" for k in ("reason", "issue", "receipt", "head")))
    return "\n".join(out)

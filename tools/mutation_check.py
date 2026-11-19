#!/usr/bin/env python3
"""Confirm that proof and differential checks reject deliberately unsafe kernels."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEND = os.environ.get("BEND", "bend")
BEND_MUTANTS = [
    ("classifier_can_kill", "    case ToKill{}:\n      ToFreeze{}", "    case ToKill{}:\n      ToKill{}"),
    ("expired_run_stays_live", "raise(cfg, now, ModeRun{}, d, ToFreeze{})", "StepResult{ControlState{ModeRun{}, d}, NoMore{}}"),
    ("renewal_ignores_maximum", "ControlState{ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))}\n    case ModeRestrict{}:", "ControlState{ModeRun{}, Nat.add(now, ttl)}\n    case ModeRestrict{}:"),
    ("freeze_before_revocation", "case ModeRun{} ToFreeze{}:\n      StepResult{ControlState{ModeFreeze{}, Nat.add(now, grace_of(cfg))}, Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, NoMore{}}}}}", "case ModeRun{} ToFreeze{}:\n      StepResult{ControlState{ModeFreeze{}, Nat.add(now, grace_of(cfg))}, Next{FreezeProcesses{}, Next{RevokeSecrets{}, Next{BlockEgress{}, NoMore{}}}}}"),
    ("unsigned_reset_runs", "    case False{}:\n      settle(cfg, now, m, d)", "    case False{}:\n      StepResult{ControlState{ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))}, reset_actions(m)}"),
    ("expired_access_allowed", "    case False{}:\n      False{}\n\ndef authorize", "    case False{}:\n      match r:\n        case AccessRequest{k, g, b}:\n          allow_mode(m, k, g, b)\n\ndef authorize"),
    ("freeze_allows_access", "    case ModeFreeze{}:\n      False{}\n    case ModeKill{}:\n      False{}\n\ndef allow_with", "    case ModeFreeze{}:\n      granted\n    case ModeKill{}:\n      False{}\n\ndef allow_with"),
    ("restrict_allows_secret", "        case SecretAccess{}:\n          False{}", "        case SecretAccess{}:\n          granted"),
    ("restrict_can_lower", "    case ModeRestrict{} ToRestrict{}:\n      StepResult{ControlState{ModeRestrict{}, d}, NoMore{}}", "    case ModeRestrict{} ToRestrict{}:\n      StepResult{ControlState{ModeRun{}, d}, NoMore{}}"),
]
RUST_MUTANTS = [
    ("classifier_can_kill", "let capped = if level == Level::Kill { Level::Freeze } else { level };", "let capped = level;"),
    ("lease_off_by_one", "if now_ms < control.deadline_ms {\n        return StepResult", "if now_ms <= control.deadline_ms {\n        return StepResult"),
    ("renewal_ignores_maximum", "now_ms.saturating_add(ttl_ms.min(config.max_lease_ms))", "now_ms.saturating_add(ttl_ms)"),
    ("freeze_before_revocation", "&[Action::RevokeSecrets, Action::BlockEgress, Action::FreezeProcesses];", "&[Action::FreezeProcesses, Action::RevokeSecrets, Action::BlockEgress];"),
    ("unsigned_reset_runs", "Event::Reset { now_ms, signed: true, ttl_ms } =>", "Event::Reset { now_ms, ttl_ms, .. } =>"),
    ("expired_access_allowed", "    if now_ms >= control.deadline_ms {\n        return false;\n    }\n    match control.mode {\n        Mode::Run => request.granted", "    let _ = now_ms;\n    match control.mode {\n        Mode::Run => request.granted"),
    ("freeze_allows_access", "Mode::Freeze | Mode::Kill => false,", "Mode::Freeze | Mode::Kill => request.granted,"),
    ("restrict_allows_secret", "request.kind == AccessKind::Egress && request.granted && request.baseline", "request.granted && request.baseline"),
]

def run(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)

def bend_mutants():
    out = []
    source = (ROOT / "formal/kernel.bend").read_text()
    for name, old, new in BEND_MUTANTS:
        assert source.count(old) >= 1, f"mutation target missing: {name}"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "formal"
            shutil.copytree(ROOT / "formal", target)
            (target / "kernel.bend").write_text(source.replace(old, new, 1))
            result = run([BEND, "PROOF.bend", "--check-only"], cwd=target)
            rejected = result.returncode != 0 or "SOME PROOFS FAIL" in result.stdout + result.stderr
            out.append({"mutant": name, "rejected": rejected})
    return out

def rust_mutants(kernel_mjs):
    out = []
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target/mutation")}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns("target", ".git", "results"))
        path = repo / "crates/containment-kernel/src/lib.rs"
        source = path.read_text()
        for name, old, new in RUST_MUTANTS:
            assert source.count(old) >= 1, f"mutation target missing: {name}"
            path.write_text(source.replace(old, new, 1))
            build = run(["cargo", "build", "-q", "-p", "containment-host"], cwd=repo, env=env)
            assert build.returncode == 0, build.stderr[-2000:]
            exe = ROOT / "target/mutation/debug/containment-lab"
            cases = Path(tmp) / f"{name}.jsonl"
            cases.write_text(run([str(exe), "differential-cases", "2000", "24301"], check=True).stdout)
            result = run(["bun", str(ROOT / "tools/differential.mjs"), kernel_mjs, str(cases)])
            out.append({"mutant": name, "rejected": result.returncode != 0})
    return out

def main():
    kernel_mjs = sys.argv[1]
    report = {"bend": bend_mutants(), "rust": rust_mutants(kernel_mjs)}
    report["bend_rejected"] = sum(x["rejected"] for x in report["bend"])
    report["rust_rejected"] = sum(x["rejected"] for x in report["rust"])
    report["bend_total"], report["rust_total"] = len(report["bend"]), len(report["rust"])
    Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("bend_rejected", "bend_total", "rust_rejected", "rust_total")}))
    return 0 if report["bend_rejected"] == report["bend_total"] and report["rust_rejected"] == report["rust_total"] else 1
sys.exit(main())

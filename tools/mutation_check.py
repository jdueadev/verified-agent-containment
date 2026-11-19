#!/usr/bin/env python3
"""Confirm that proof and differential checks reject deliberately unsafe kernels."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_mutants import BEND_MUTANTS, RUST_MUTANTS

ROOT = Path(__file__).resolve().parents[1]
BEND = os.environ.get("BEND", "bend")
def run(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)

def bend_mutants():
    out = []
    source = (ROOT / "formal/kernel.bend").read_text()
    for name, old, new in BEND_MUTANTS:
        assert source.count(old) == 1, f"mutation target missing: {name}"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "formal"
            shutil.copytree(ROOT / "formal", target)
            (target / "kernel.bend").write_text(source.replace(old, new, 1))
            # A mutant counts only if it is a valid kernel that the proofs then reject.
            valid = run([BEND, "kernel.bend", "--check-only"], cwd=target)
            assert "SOME PROOFS FAIL" not in valid.stdout + valid.stderr, f"mutant does not type-check: {name}"
            result = run([BEND, "PROOF.bend", "--check-only"], cwd=target)
            text = result.stdout + result.stderr
            rejected = result.returncode != 0 or "SOME PROOFS FAIL" in text
            where = next((line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("Location:")), None)
            # Independent evidence: a concrete input on which the mutant breaks a stated law.
            built = run([BEND, "kernel.bend", "-o", "mutant.mjs"], cwd=target)
            audit = run(["bun", str(ROOT / "tools/law_audit.mjs"), str(target / "mutant.mjs"), "40000"]) if built.returncode == 0 else None
            violated = sorted(json.loads(audit.stdout)["violated"]) if audit and audit.returncode == 0 else None
            out.append({"mutant": name, "rejected": rejected, "first_failure": where, "laws_violated": violated, "witness": bool(violated)})
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
            assert source.count(old) == 1, f"mutation target missing: {name}"
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
    report["bend_witnessed"] = sum(x["rejected"] and x["witness"] for x in report["bend"])
    report["original_violations"] = json.loads(run(["bun", str(ROOT / "tools/law_audit.mjs"), kernel_mjs, "200000"], check=True).stdout)["violated"]
    report["rust_rejected"] = sum(x["rejected"] for x in report["rust"])
    report["bend_total"], report["rust_total"] = len(report["bend"]), len(report["rust"])
    Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("bend_rejected", "bend_witnessed", "bend_total", "rust_rejected", "rust_total")}))
    return 0 if not report["original_violations"] and report["bend_witnessed"] == report["bend_total"] and report["bend_rejected"] == report["bend_total"] and report["rust_rejected"] == report["rust_total"] else 1
sys.exit(main())

#!/usr/bin/env python3
"""Confirm that proof and differential checks reject deliberately unsafe kernels."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_tokens import splice_once

ROOT = Path(__file__).resolve().parents[1]
MUTANT_LISTS = ("BEND_MUTANTS", "RUST_MUTANTS")


def load_mutants(text):
    """BEND_MUTANTS and RUST_MUTANTS from tools/kernel_mutants.py, read as data (#185).

    The file is lane B. Importing it ran it inside this judge, where it could patch
    subprocess or exit 0 before any mutant ran. Now it is parsed, never executed: only a
    module docstring and pure-literal assignments to plain names, each list exactly once,
    and each mutant a (name, old, new) triple of strings with a non-empty name and old
    text (new may be empty, to delete) and unique names.
    claims_check.py reads the same file the same way."""
    import ast
    out = {}
    for index, node in enumerate(ast.parse(text).body):
        where = f"tools/kernel_mutants.py line {node.lineno}"
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            continue
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            raise ValueError(f"{where}: only literal assignments to plain names are allowed")
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            raise ValueError(f"{where}: {node.targets[0].id} is not a pure literal") from None
        name = node.targets[0].id
        if name in MUTANT_LISTS:
            if name in out:
                raise ValueError(f"{where}: {name} is assigned more than once")
            if not isinstance(value, list) or not value:
                raise ValueError(f"{where}: {name} must be a non-empty list")
            for entry in value:
                # The replacement may be empty: a mutant can delete the matched code.
                if not (isinstance(entry, tuple) and len(entry) == 3 and all(isinstance(part, str) for part in entry)
                        and entry[0] and entry[1]):
                    raise ValueError(f"{where}: {name} has an entry that is not (name, old, new)")
            names = [entry[0] for entry in value]
            if len(names) != len(set(names)):
                raise ValueError(f"{where}: {name} repeats a mutant name")
            out[name] = value
    missing = [name for name in MUTANT_LISTS if name not in out]
    if missing:
        raise ValueError(f"tools/kernel_mutants.py: {', '.join(missing)} missing")
    return out["BEND_MUTANTS"], out["RUST_MUTANTS"]


BEND_MUTANTS, RUST_MUTANTS = load_mutants((ROOT / "tools/kernel_mutants.py").read_text(encoding="utf-8"))
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

def rust_mutant(source, name, old, new):
    """lib.rs with one Rust mutant applied, or an error naming the mutant."""
    try:
        return splice_once(source, old, new)
    except ValueError as err:
        raise SystemExit(f"mutation target {name}: {err}") from err

def rust_mutants(kernel_mjs):
    out = []
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target/mutation")}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns("target", ".git", "results"))
        path = repo / "crates/containment-kernel/src/lib.rs"
        source = path.read_text(encoding="utf-8")
        for name, old, new in RUST_MUTANTS:
            # Matched by tokens, not bytes, so reformatting lib.rs cannot lose a mutant
            # (#61). splice_once raises unless the pattern matches exactly once.
            path.write_text(rust_mutant(source, name, old, new), encoding="utf-8")
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

if __name__ == "__main__":
    sys.exit(main())

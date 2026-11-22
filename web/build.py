#!/usr/bin/env python3
"""Build the self-contained showcase page from the checked WebAssembly kernels."""
import base64, hashlib, json, re, subprocess, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from kernel_mutants import RUST_MUTANTS, SHOWCASE
import cookbook_check as cookbook

gen = root / "target/generated"
read = lambda p: json.loads((root / p).read_text())
b64 = lambda p: base64.b64encode(p.read_bytes()).decode()

def fallback(path):
    js = path.read_text()
    js = js[:js.index("var retasmFunc")] + "return asmFunc({});"
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)

suite, mutation, differential = read("results/attack-suite.json"), read("results/mutation-check.json"), read("results/differential.json")
verdict = read("results/formal-verdict.json")
current = verdict.get("result") == "ALL PROOFS CHECK" and all(
    hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in verdict["sha256"].items())
metric = lambda name: (suite["metrics"].get(name) or {}).get("p95")
evidence = {
    "laws": len(re.findall(r"^law ", (root / "formal/LAWS.bend").read_text(), re.M)), "proof_current": current,
    "bend_rejected": mutation["bend_rejected"], "bend_total": mutation["bend_total"],
    "rust_rejected": mutation["rust_rejected"], "rust_total": mutation["rust_total"], "transitions": differential["transitions"],
    "runs_passed": suite["runs_passed"], "runs_total": suite["runs_total"], "scenarios": suite["scenarios"],
    "timed": suite["timed_scenarios"], "repeat": suite["timed_repeat"], "sabotage_detected": suite["sabotage_detected"], "sabotage_total": suite["sabotage_total"],
    "admitted": suite["bytes_admitted_after_commit_total"], "written": suite["bytes_written_after_cut_total"], "measured": suite["contained_runs_measured"],
    "receipt_p95": metric("receipt_to_commit_ms"), "cut_p95": metric("commit_to_cut_ms"), "frozen_p95": metric("commit_to_frozen_ms"), "killed_p95": metric("commit_to_killed_ms"),
    "note": f"Scripted adversaries on Linux {suite['kernel']} with namespaces, seccomp and cgroup v2. The receiving sink, cgroup state and host process table supply the results, not the agent's own reports. "
        + ("cgroup pids, memory and CPU limits were not available on this hybrid cgroup host and were waived for the run. " if suite.get("cgroup_limits_waived") else "")
        + "This page runs only the decision kernel.",
}
edits = {name: (old, new) for name, old, new in RUST_MUTANTS}
variants, fallbacks = [], [f"safe(){{{fallback(gen / 'kernel.fallback.js')}}}"]
for name, title, effect, law in SHOWCASE:
    old, new = edits[name]
    variants.append({"id": name, "title": title, "effect": effect, "law": law, "old": old.strip(), "new": new.strip(), "wasm": b64(gen / f"variants/{name}.wasm")})
    fallbacks.append(f"{name}(){{{fallback(gen / f'variants/{name}.js')}}}")
kernels = {"safe": b64(gen / "kernel.opt.wasm"), "variants": variants}

# The cookbook panel (#106). The checker runs first: it builds the Bend kernel's mutants
# into target/generated/cookbook/, and the page is not built if any snippet fails. The
# interpreter and the snippets go in as the exact blocks the checker compares with the
# committed page, so the page cannot run a different interpreter than scripts/check.sh.
subprocess.run(["bend", "formal/kernel.bend", "-o", str(gen / "kernel.mjs")], cwd=root, check=True, stdout=subprocess.DEVNULL)
errors, notes = cookbook.check(root, ci=True)
# Recipe regions are scripts/check.sh's job, and one of them (the snippet's link to this
# page) can only be regenerated once this page exists. Every other error stops the build.
errors = [e for e in errors if "is out of date; run python3 tools/cookbook_check.py --write" not in e]
if errors:
    raise SystemExit("cookbook check failed; the page is not built:\n" + "\n".join(errors))
blocks = cookbook.page_blocks(root)

def bend_module(path):
    """A Bend kernel compiled to JS, as a function that returns its exports."""
    js = path.read_text()
    if js.count("export default ") != 1 or "</" in js or "<!--" in js:
        raise SystemExit(f"{path}: cannot inline this module")
    return "function(){" + js.replace("export default ", "return ", 1) + "}"

snippets = {sid: json.loads(text) for sid, (_, text, _) in cookbook.load_snippets(root)[0].items()}
bend = {"safe": bend_module(gen / "kernel.mjs")}
for data in snippets.values():
    name = data["breaks"]
    bend[name] = bend_module(root / cookbook.MUTANT_JS / f"{name.split(':', 1)[1]}.mjs")
built = subprocess.run(["git", "describe", "--always", "--dirty", "--abbrev=7"], cwd=root, capture_output=True, text=True).stdout.strip() or "unknown"
evidence["built"] = built

values = {
    "KERNELS_JSON": cookbook.script_json(kernels),
    "EVIDENCE_JSON": cookbook.script_json(evidence),
    "FALLBACKS_JS": ",\n".join(fallbacks),
    "COOKBOOK_INTERPRETER": blocks[cookbook.PAGE_INTERPRETER[0]],
    "COOKBOOK_SNIPPETS": blocks[cookbook.PAGE_SNIPPETS[0]],
    "COOKBOOK_BEND_JS": "{" + ",\n".join(f"{json.dumps(name)}:{js}" for name, js in bend.items()) + "}",
}
page = (root / "web/template.html").read_text()
# One pass, so text inserted for one placeholder is never scanned for another.
page = re.sub(r"__([A-Z_]+)__", lambda m: values[m.group(1)], page)
out = Path(sys.argv[1] if len(sys.argv) > 1 else root / "web/dist/agent-containment-simulator.html")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(page)
print(json.dumps({"out": str(out), "bytes": out.stat().st_size, "variants": len(variants), "recipes": len(snippets), "proof_current": current, "built": built}))

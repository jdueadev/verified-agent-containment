#!/usr/bin/env python3
"""Build the self-contained showcase page from the checked WebAssembly kernel."""
import base64, json, re, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
wasm = root / "target/generated/kernel.opt.wasm"
fallback = root / "target/generated/kernel.fallback.js"
suite = json.loads((root / "results/attack-suite.json").read_text())
laws = len(re.findall(r"^law ", (root / "formal/LAWS.bend").read_text(), re.M))
js = fallback.read_text()
js = js[:js.index("var retasmFunc")] + "return asmFunc({});"
js = re.sub(r"^\s*//.*$", "", js, flags=re.M)
frozen = suite["metrics"]["trigger_to_frozen_ms"]
evidence = {
    "laws": laws,
    "runs_passed": suite["runs_passed"],
    "runs_total": suite["runs_total"],
    "bytes_after_trigger": suite["bytes_after_trigger_total"],
    "sabotage_detected": suite["sabotage_detected"],
    "sabotage_total": suite["sabotage_total"],
    "note": (
        f"Measured with scripted adversaries on Linux {suite['kernel']}, using namespaces and cgroup v2. "
        f"Trigger to frozen: p50 {frozen['p50']:.2f} ms, p95 {frozen['p95']:.2f} ms. "
        "This page runs only the decision kernel. It does not run an agent, isolate your browser, or test WSL2."
    ),
}
page = (root / "web/template.html").read_text()
page = page.replace("__WASM_BASE64__", base64.b64encode(wasm.read_bytes()).decode())
page = page.replace("__EVIDENCE_JSON__", json.dumps(evidence))
page = page.replace("__FALLBACK_JS__", js)
out = Path(sys.argv[1] if len(sys.argv) > 1 else root / "web/dist/agent-containment-simulator.html")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(page)
print(json.dumps({"out": str(out), "bytes": out.stat().st_size, **{k: evidence[k] for k in ("laws", "runs_passed", "runs_total")}}))

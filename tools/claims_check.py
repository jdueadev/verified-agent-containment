#!/usr/bin/env python3
"""Check claims.toml against the repository's evidence and generate docs/claims.md.

Usage: claims_check.py [--write] [--strict]
(without --write, fails if docs/claims.md is out of date; --strict also fails on stale rows
and on suite results whose build stamps are missing or wrong)

CI-1  every law: in a non-planned row exists in formal/LAWS.bend, and results/formal-verdict.json
      hashes match the formal/ files at HEAD
CI-2  every law, Bend mutant, Rust mutant and sabotage in the repository is cited by some row
CI-3  proved needs a law:; checked-bounded needs a tla: that passed in results/tla-check.json for the current spec; tested needs a falsifier that was caught
      (cited mutants/sabotages detected, cited scenarios passed in every recorded run, doc: text present)
CI-4  a row is stale when a path in its files changed after the commit of every passing platform
      (reported as a warning and shown as stale; an error with --strict). A module root such as
      controller.rs also covers controller/. A platform whose commit predates a change is marked.
CI-5  no row is stronger than its weakest depends_on
CI-6  every claim id cited in docs/design-spec.md exists
CI-7  every tracked file under crates/containment-host/src is in the files of some row
CI-8  (--strict) results/attack-suite.json and results/live-suite.json record that the honest runs
      came from a default build and the sabotage controls from a different, sabotage build
"""
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RANK = {"proved": 5, "checked-bounded": 4, "tested": 3, "assumed": 2, "planned": 1, "stale": 0}
LAYERS = {"bend-kernel", "rust-kernel", "host", "os", "env"}
KINDS = {"law", "mutant", "rust-mutant", "scenario", "sabotage", "diff", "tla", "doc", "live", "live-sabotage"}


def load_inventory():
    laws = re.findall(r"^law ([a-z_0-9]+):", (ROOT / "formal/LAWS.bend").read_text(), re.M)
    spec = importlib.util.spec_from_file_location("kernel_mutants", ROOT / "tools/kernel_mutants.py")
    mutants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mutants)
    bend = [m[0] for m in mutants.BEND_MUTANTS]
    rust = [m[0] for m in mutants.RUST_MUTANTS]
    harness = (ROOT / "crates/containment-host/src/harness.rs").read_text()
    sabotage_block = harness.split("const SABOTAGE")[1].split("];")[0]
    sabotage = re.findall(r'\("([a-z_]+)",\s*"[a-z_]+"\)', sabotage_block)
    scenario_block = harness.split("const SCENARIOS")[1].split("];")[0]
    scenarios = re.findall(r'"([a-z_]+)"', scenario_block)
    live_src = (ROOT / "crates/containment-host/src/live_suite.rs").read_text()
    live_sabotage = re.findall(r'\("([a-z_]+)",\s*"[a-z_]+",', live_src.split("const SABOTAGE")[1].split("];")[0])
    live_scenarios = re.findall(r'"([a-z_]+)"', live_src.split("const SCENARIOS")[1].split("];")[0])
    return laws, bend, rust, sabotage, scenarios, live_scenarios, live_sabotage


def load_results():
    mutation = json.loads((ROOT / "results/mutation-check.json").read_text())
    suites = [json.loads(p.read_text()) for p in [ROOT / "results/attack-suite.json", ROOT / "results/attack-suite-under-cpu-load.json"] if p.exists()]
    scenario_ok = {}
    sabotage_ok = {}
    for suite in suites:
        for run in suite["runs"]:
            if run.get("weakness", "none") == "none":
                scenario_ok[run["scenario"]] = scenario_ok.get(run["scenario"], True) and bool(run["passed"])
        for item in suite["sabotage"]:
            sabotage_ok[item["weakness"]] = sabotage_ok.get(item["weakness"], True) and bool(item["detected"])
    bend_ok = {m["mutant"]: m["rejected"] and m.get("witness", False) for m in mutation["bend"]}
    rust_ok = {m["mutant"]: m["rejected"] for m in mutation["rust"]}
    diffs = {}
    for name, file in [("rust-bend", "differential.json"), ("rust-wasm", "wasm-differential.json")]:
        path = ROOT / "results" / file
        if path.exists():
            data = json.loads(path.read_text())
            diffs[name] = data.get("mismatches", 1) == 0
    live_ok, live_sab_ok = {}, {}
    live_path = ROOT / "results/live-suite.json"
    if live_path.exists():
        live = json.loads(live_path.read_text())
        for run in live["runs"]:
            live_ok[run["scenario"]] = live_ok.get(run["scenario"], True) and bool(run["passed"])
        for item in live["sabotage"]:
            live_sab_ok[item["weakness"]] = bool(item["detected"])
    return bend_ok, rust_ok, scenario_ok, sabotage_ok, diffs, live_ok, live_sab_ok


def verdict_matches_head():
    verdict = json.loads((ROOT / "results/formal-verdict.json").read_text())
    for path, digest in verdict["sha256"].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest:
            return False, f"{path} differs from the hash in results/formal-verdict.json"
    return verdict["result"] == "ALL PROOFS CHECK", verdict["result"]


def tla_passed(spec, prop):
    """A tla:<spec>#<prop> reference holds if results/tla-check.json records the
    property as passed for the spec file as it is now."""
    path = ROOT / "results/tla-check.json"
    if not path.exists() or spec != "host":
        return False
    data = json.loads(path.read_text())
    # The recorded digest covers the spec and every configuration TLC ran.
    inputs = data.get("inputs") or [data["spec"]]
    if data["spec"] not in inputs:
        return False
    current = hashlib.sha256(b"".join((ROOT / p).read_bytes() for p in inputs)).hexdigest()
    return data["sha256"] == current and prop in data["passed"] and all(r["as_expected"] for r in data["runs"])


def expand(paths):
    """A Rust module root covers its submodules: `x.rs` also means `x/`."""
    out = list(paths)
    for path in paths:
        if path.endswith(".rs") and (ROOT / path[:-3]).is_dir():
            out.append(path[:-3])
    return out


def uncovered_sources(claims, root="crates/containment-host/src"):
    """Tracked host sources that no claim lists in `files` (CI-7). An inventory
    that cannot be taken, or is empty, is reported: it is not full coverage."""
    try:
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", root],
                                 capture_output=True, text=True, check=True).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        tracked = []
    if not tracked:
        return [f"{root} (git could not list its tracked files, so coverage was not checked)"]
    listed = {path.rstrip("/") for claim in claims for path in expand(claim.get("files", []))}
    return [f for f in tracked if not any(f == path or f.startswith(path + "/") for path in listed)]


def build_errors():
    """The honest runs must come from a default build and the controls from a
    sabotage build, and the two must be different binaries (CI-8)."""
    out = []
    for name in ["attack-suite.json", "live-suite.json"]:
        path = ROOT / "results" / name
        if not path.exists():
            continue
        build = json.loads(path.read_text()).get("build") or {}
        honest, controls = build.get("honest") or {}, build.get("sabotage") or {}
        if honest.get("sabotage") is not False:
            out.append(f"CI-8 results/{name}: the honest runs are not stamped as coming from a default build")
        elif controls.get("sabotage") is not True:
            out.append(f"CI-8 results/{name}: the sabotage controls are not stamped as coming from a sabotage build")
        elif not all(re.fullmatch(r"[0-9a-f]{64}", str(part.get("binary_sha256"))) for part in (honest, controls)):
            out.append(f"CI-8 results/{name}: a build stamp has no SHA-256 of its binary")
        elif honest.get("binary_sha256") == controls.get("binary_sha256"):
            out.append(f"CI-8 results/{name}: the honest runs and the controls came from the same binary")
    return out


def changed_since(commit, paths):
    paths = expand(paths)
    if not paths:
        return []
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", commit, "--", *paths],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [f"(cannot diff against {commit})"]
    return [line for line in out.splitlines() if line]


def main():
    strict = "--strict" in sys.argv[1:]
    write = "--write" in sys.argv[1:]
    claims = tomllib.loads((ROOT / "claims.toml").read_text())["claim"]
    laws, bend, rust, sabotage, scenarios, live_scenarios, live_sabotage = load_inventory()
    bend_ok, rust_ok, scenario_ok, sabotage_ok, diffs, live_ok, live_sab_ok = load_results()
    errors = []
    by_id = {}
    cited = {k: set() for k in KINDS}

    for claim in claims:
        cid = claim["id"]
        if cid in by_id:
            errors.append(f"{cid}: duplicate id")
        by_id[cid] = claim
        if claim["layer"] not in LAYERS:
            errors.append(f"{cid}: unknown layer {claim['layer']}")
        if claim["status"] not in RANK:
            errors.append(f"{cid}: unknown status {claim['status']}")
        for ref in claim.get("evidence", []):
            kind, _, name = ref.partition(":")
            if kind not in KINDS:
                errors.append(f"{cid}: unknown evidence kind in {ref}")
                continue
            cited[kind].add(name)

    verdict_ok, verdict_note = verdict_matches_head()
    effective = {}

    def caught(cid, ref):
        kind, _, name = ref.partition(":")
        if kind == "mutant":
            return bend_ok.get(name, False)
        if kind == "rust-mutant":
            return rust_ok.get(name, False)
        if kind == "sabotage":
            return sabotage_ok.get(name, False)
        if kind == "scenario":
            return scenario_ok.get(name, False)
        if kind == "diff":
            return diffs.get(name, False)
        if kind == "live":
            return live_ok.get(name, False)
        if kind == "live-sabotage":
            return live_sab_ok.get(name, False)
        if kind == "doc":
            file, _, text = name.partition("#")
            path = ROOT / file
            return path.exists() and text in path.read_text()
        if kind == "law":
            return name in laws and verdict_ok
        if kind == "tla":
            spec, _, prop = name.partition("#")
            return tla_passed(spec, prop)
        return False

    for claim in claims:
        cid, status, evidence = claim["id"], claim["status"], claim.get("evidence", [])
        kinds = {ref.partition(":")[0] for ref in evidence}
        if status != "planned":
            for ref in evidence:
                kind, _, name = ref.partition(":")
                if kind == "law" and name not in laws:
                    errors.append(f"CI-1 {cid}: {ref} is not in formal/LAWS.bend")
                if kind == "law" and not verdict_ok:
                    errors.append(f"CI-1 {cid}: proof verdict does not match HEAD ({verdict_note})")
                if kind in {"scenario", "sabotage"} and name not in (scenarios if kind == "scenario" else sabotage):
                    errors.append(f"CI-3 {cid}: {ref} does not exist in harness.rs")
                if kind in {"live", "live-sabotage"} and name not in (live_scenarios if kind == "live" else live_sabotage):
                    errors.append(f"CI-3 {cid}: {ref} does not exist in live_suite.rs")
        if status == "proved" and "law" not in kinds:
            errors.append(f"CI-3 {cid}: proved needs a law:")
        if status == "checked-bounded" and "tla" not in kinds:
            errors.append(f"CI-3 {cid}: checked-bounded needs a tla:")
        if status in {"proved", "tested"}:
            falsifiers = [r for r in evidence if r.partition(":")[0] in {"mutant", "rust-mutant", "sabotage", "diff", "doc", "live-sabotage"}]
            if not falsifiers:
                errors.append(f"CI-3 {cid}: {status} needs a mutant, sabotage, diff or doc check that is caught")
            for ref in evidence:
                if ref.partition(":")[0] != "tla" and not caught(cid, ref):
                    errors.append(f"CI-3 {cid}: {ref} was not caught or did not pass in results/")
        if status == "checked-bounded":
            for ref in evidence:
                if ref.partition(":")[0] == "tla" and not caught(cid, ref):
                    errors.append(f"CI-3 {cid}: {ref} has no passing TLC result for the current spec (run tools/tla_check.sh)")
        # Each passing platform is evidence for the code as it was at that
        # platform's commit. The claim is stale only when every one of them
        # predates a change to its files; a platform that does is marked in
        # docs/claims.md either way.
        stale_files = []
        passing = [p for p in claim.get("platforms", []) if p["result"].startswith("pass")]
        for platform in passing:
            platform["_changed"] = changed_since(platform["commit"], claim.get("files", []))
        if passing and all(p["_changed"] for p in passing):
            stale_files = min((p["_changed"] for p in passing), key=len)
        effective[cid] = "stale" if stale_files else status
        claim["_stale"] = stale_files

    for claim in claims:
        cid = claim["id"]
        for dep in claim.get("depends_on", []):
            if dep not in by_id:
                errors.append(f"CI-5 {cid}: depends on unknown {dep}")
            else:
                # Without --strict, staleness is a warning (CI-4): compare declared
                # strength, so a stale dependency alone does not fail the check.
                mine, theirs = (effective[cid], effective[dep]) if strict else (by_id[cid]["status"], by_id[dep]["status"])
                if RANK[mine] > RANK[theirs]:
                    errors.append(f"CI-5 {cid}: {mine} is stronger than dependency {dep} ({theirs})")

    for kind, names in [("law", laws), ("mutant", bend), ("rust-mutant", rust), ("sabotage", sabotage), ("live-sabotage", live_sabotage)]:
        for name in names:
            if name not in cited[kind]:
                errors.append(f"CI-2 {kind}:{name} is not cited by any claim")

    spec_ids = set(re.findall(r"\b([CLAKRH]-[A-Z0-9]+-[A-Z0-9]+|C-SYS-1|C-DOC-1)\b", (ROOT / "docs/design-spec.md").read_text()))
    for sid in sorted(spec_ids - set(by_id)):
        errors.append(f"CI-6 docs/design-spec.md cites {sid}, which is not in claims.toml")

    for path in uncovered_sources(claims):
        errors.append(f"CI-7 {path} is not covered by the files of any claim")

    markdown = render(claims, effective, verdict_ok, len(laws), len(bend), len(rust), len(sabotage))
    target = ROOT / "docs/claims.md"
    if write:
        target.write_text(markdown)
    elif not target.exists() or target.read_text() != markdown:
        errors.append("docs/claims.md is out of date; run tools/claims_check.py --write")

    counts = {}
    for status in effective.values():
        counts[status] = counts.get(status, 0) + 1
    stale = {c["id"]: c["_stale"] for c in claims if c["_stale"]}
    warnings = [f"CI-4 {cid}: stale, {', '.join(files)} changed after its platform commit; rerun and update platforms"
                for cid, files in stale.items()]
    if strict:
        errors.extend(warnings)
        errors.extend(build_errors())
    print(json.dumps({"claims": len(claims), "status": counts, "errors": errors, "stale": warnings}, indent=2))
    return 1 if errors else 0


def esc(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(claims, effective, verdict_ok, n_laws, n_bend, n_rust, n_sab):
    lines = [
        "# Claims",
        "",
        "Generated from `claims.toml` by `tools/claims_check.py --write`. Do not edit by hand.",
        "",
        f"Inventory cited: {n_laws} laws, {n_bend} Bend mutants, {n_rust} Rust mutants, {n_sab} sabotaged controllers. "
        f"Proof verdict matches HEAD: {'yes' if verdict_ok else 'no'}.",
        "",
        "Status, strongest first: proved (Bend law, Lean-rechecked), checked-bounded (TLA+ model), tested (attack suite or "
        "differential, with a falsifier that was caught), assumed (stated, not checked), planned (v3 design, not built), "
        "stale (evidence predates a change).",
        "",
        "| id | statement | layer | status | evidence | falsifier | platforms |",
        "|---|---|---|---|---|---|---|",
    ]
    for claim in claims:
        evidence = claim.get("evidence", [])
        shown = ", ".join(f"`{e}`" for e in evidence[:6]) + (f", +{len(evidence) - 6} more" if len(evidence) > 6 else "")
        platforms = "; ".join(f"{p['name']} @{p['commit']}: {p['result']}" + (" (predates later changes)" if p.get("_changed") else "")
                              for p in claim.get("platforms", []))
        status = effective[claim["id"]]
        if claim.get("depends_on"):
            status += " (needs " + ", ".join(claim["depends_on"]) + ")"
        statement = claim["statement"] + (f" *Limits: {claim['limits']}*" if claim.get("limits") else "")
        lines.append(f"| {claim['id']} | {esc(statement)} | {claim['layer']} | {esc(status)} | {esc(shown) or '—'} | "
                     f"{esc(claim['falsifier'])} | {esc(platforms) or '—'} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())

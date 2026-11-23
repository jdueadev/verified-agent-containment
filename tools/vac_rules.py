import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

vac_core = importlib.import_module("vac_core")
policy_check = importlib.import_module("policy_check")
workflow_lint = importlib.import_module("workflow_lint")
pins_check = importlib.import_module("pins_check")

Finding = vac_core.Finding
Rule = vac_core.Rule
T0 = frozenset({"t0", "t1", "pr", "rc", "release"})
T1 = frozenset({"t1", "rc", "release"})
RC = frozenset({"rc", "release"})
EVERYWHERE = ("**",)
CLAIM_WATCHES = ("claims.toml", "results/**", "formal/**", "crates/**", "docs/claims.md", "docs/design-spec.md",
                 "tools/kernel_mutants.py", "ci/lab-attestation.toml", "ci/github-oidc-jwks.json")


def findings(rule_id, messages, path="."):
    return [Finding(rule_id, path, 0, m) for m in messages]


def sabotage_off(ctx):
    text = policy_check.read(policy_check.HOST_MANIFEST)
    if text is None:
        return findings("POL-SAB", ["missing"], policy_check.HOST_MANIFEST)
    return findings("POL-SAB", policy_check.sabotage_default_errors(text), policy_check.HOST_MANIFEST)


def kernel_pure(ctx):
    return findings("POL-KER", policy_check.kernel_purity_errors(policy_check.kernel_sources()), policy_check.KERNEL_SRC)


def lanes_and_owners(ctx):
    text = policy_check.read(policy_check.LANES_FILE)
    try:
        owner, lanes = policy_check.load_lanes(text)
        policy_check.load_trusted(text)
    except (ValueError, TypeError) as error:
        return findings("POL-LANES", [str(error)], policy_check.LANES_FILE)
    return findings("POL-LANES", policy_check.codeowners_errors(owner, lanes, policy_check.read(policy_check.CODEOWNERS_FILE)),
                    policy_check.CODEOWNERS_FILE)


def claude_paths(ctx):
    return findings("POL-CLAUDE", policy_check.claude_path_errors(policy_check.index_entries(), policy_check.read), ".claude")


def workflows(ctx):
    allowed = workflow_lint.load_allowed((ctx.root / workflow_lint.ALLOW_FILE).read_text(encoding="utf-8"))
    files = workflow_lint.workflow_files(ctx.root)
    out = [Finding("WF-LINT", name, 0, e) for name, text in files.items() for e in workflow_lint.lint(name, text, allowed)]
    if not any(n.startswith(workflow_lint.WORKFLOWS + "/") for n in files):
        out.append(Finding("WF-LINT", workflow_lint.WORKFLOWS, 0, "no workflow files"))
    return out


def pins(ctx):
    pinned = pins_check.parse_pins((ctx.root / "ci/pins.env").read_text(encoding="utf-8"))
    channel = pins_check.toolchain_channel((ctx.root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    return findings("PIN-DRIFT", pins_check.drift_errors(pinned, channel, pins_check.load_workflows()), "ci/pins.env")


def claims_report(ctx):
    def compute():
        strict = ["--strict"] if ctx.stage in ("rc", "release") else []
        code, out, err = vac_core.run_tool(ctx, "claims", [sys.executable, "tools/claims_check.py", *strict])
        try:
            return json.loads(out[out.index("{"):])
        except ValueError:
            return {"errors": [f"claims_check printed no report (exit {code}): {err.strip()[-300:]}"]}
    return ctx.once("claims-report", compute)


CLAIM_PREFIX = re.compile(r"^(CI-\d+)\b")


def claim_rule(number):
    rule_id = f"CL-{number}"

    def check(ctx):
        return [Finding(rule_id, "claims.toml", 0, e) for e in claims_report(ctx).get("errors", [])
                if (m := CLAIM_PREFIX.match(e)) and m.group(1) == f"CI-{number}"]
    return check


def claims_other(ctx):
    known = {f"CI-{n}" for n in CLAIM_NUMBERS}
    out = []
    for e in claims_report(ctx).get("errors", []):
        m = CLAIM_PREFIX.match(e)
        if m is None or m.group(1) not in known:
            out.append(Finding("CL-OTHER", "claims.toml", 0, e))
    return out


def law_names(text):
    return re.findall(r"^law ([a-z_][a-z0-9_]*):", text, re.M)


def laws_without_killer(ctx):
    laws = law_names((ctx.root / "formal/LAWS.bend").read_text(encoding="utf-8"))
    report = json.loads((ctx.root / "results/mutation-check.json").read_text(encoding="utf-8"))
    killed = {law for m in report.get("bend", []) for law in m.get("laws_violated", [])}
    return [Finding("LAW-KILL", "formal/LAWS.bend", 0, f"law {law} is broken by no mutant in results/mutation-check.json")
            for law in laws if law not in killed]


def tool_run(rule_id, argv, path, timeout=3600):
    def check(ctx):
        code, out, err = vac_core.run_tool(ctx, rule_id, argv, timeout)
        if code == 0:
            return []
        tail = (err or out).strip().splitlines()[-5:]
        return [Finding(rule_id, path, 0, f"exit {code}: " + " / ".join(tail))]
    return check


def registry_errors(ctx):
    out, seen = [], set()
    for rule in RULES:
        where = "tools/vac_rules.py"
        if rule.id in seen:
            out.append(Finding("REG-1", where, 0, f"{rule.id}: id is not unique"))
        seen.add(rule.id)
        if not re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", rule.id):
            out.append(Finding("REG-1", where, 0, f"{rule.id}: id must be UPPER-CASE words joined by '-'"))
        if not rule.title or len(rule.title) > 100:
            out.append(Finding("REG-1", where, 0, f"{rule.id}: title must be 1-100 characters"))
        if not rule.fix.strip():
            out.append(Finding("REG-1", where, 0, f"{rule.id}: fix must name what to run"))
        if not rule.refs:
            out.append(Finding("REG-1", where, 0, f"{rule.id}: refs must name at least one issue"))
        if not rule.stages or not rule.stages <= set(vac_core.STAGES):
            out.append(Finding("REG-1", where, 0, f"{rule.id}: stages must be a non-empty subset of {vac_core.STAGES}"))
        if not rule.watches:
            out.append(Finding("REG-1", where, 0, f"{rule.id}: watches must name at least one path"))
    return out


CLAIM_TITLES = {
    1: "Every cited law exists and the formal verdict matches the Bend sources",
    2: "Every law, mutant and sabotage control is cited by a claim",
    3: "Each status has the evidence it needs",
    4: "No claim is stale against its platforms",
    5: "No claim is stronger than what it depends on",
    6: "Every claim id cited in the design spec exists",
    7: "Every host source file is covered by a claim",
    8: "Honest runs and controls come from different, full builds",
    9: "Every passing platform has committed artifacts",
    10: "CI lab evidence carries a GitHub OIDC attestation of every byte",
}
CLAIM_NUMBERS = tuple(CLAIM_TITLES)
CLAIM_STAGES = {4: RC, 8: RC}

RULES = (
    Rule("REG-1", "Every rule has a unique id, a title, stages, watches, a fix and refs", T0, ("tools/vac_rules.py",),
         registry_errors, "edit the Rule in tools/vac_rules.py", (209,)),
    Rule("POL-SAB", "The sabotage feature is never a default feature", T0, ("crates/containment-host/Cargo.toml",),
         sabotage_off, "remove sabotage from [features] default in crates/containment-host/Cargo.toml", (44,)),
    Rule("POL-KER", "The kernel stays pure: no_std, no unsafe, core only, no build-time reads", T0,
         ("crates/containment-kernel/**",), kernel_pure, "remove the impure construct from crates/containment-kernel/src",
         (84, 86)),
    Rule("POL-LANES", "The lane map and trusted list parse, and CODEOWNERS equals lane C", T0,
         ("ci/lanes.toml", ".github/CODEOWNERS"), lanes_and_owners, "python3 tools/policy_check.py codeowners --write",
         (169, 206)),
    Rule("POL-CLAUDE", "Tracked .claude/ holds only allow-listed files", T0, (".claude/**",), claude_paths,
         "remove the file or add it to the allow-list in tools/policy_check.py", (169,)),
    Rule("WF-LINT", "Workflows keep secrets in main-only environments and event text out of scripts", T0,
         (".github/**", "ci/workflow_lint.toml"), workflows, "move the expression into env:, or the secret into a main-only environment",
         (137,)),
    Rule("PIN-DRIFT", "Tool versions are pinned in ci/pins.env and rust-toolchain.toml only", T0,
         ("ci/pins.env", "rust-toolchain.toml", ".github/**"), pins, "read the version from ci/pins.env instead of stating it",
         (55,)),
    *(Rule(f"CL-{n}", t, CLAIM_STAGES.get(n, T0), CLAIM_WATCHES, claim_rule(n),
           "python3 tools/claims_check.py, then fix claims.toml or the evidence it names", (44,))
      for n, t in CLAIM_TITLES.items()),
    Rule("CL-OTHER", "claims_check reports nothing outside the registered CL rules", T0, CLAIM_WATCHES, claims_other,
         "python3 tools/claims_check.py --write if docs/claims.md drifted; otherwise register the new rule", (175, 179)),
    Rule("LAW-KILL", "Every law is broken by at least one mutant", T0,
         ("formal/**", "tools/kernel_mutants.py", "results/mutation-check.json"), laws_without_killer,
         "add a mutant to tools/kernel_mutants.py that breaks the law, then python3 tools/mutation_check.py", (209,)),
    Rule("TOOL-TESTS", "The tool unit tests pass", T0, ("tools/**", "ci/**", "claims.toml", "results/**", "formal/**"),
         tool_run("TOOL-TESTS", [sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"], "tools"),
         "python3 -m unittest discover -s tools -p 'test_*.py'", (65,)),
    Rule("KERNEL-TEST", "The kernel crate's tests pass", T0, ("crates/containment-kernel/**", "Cargo.toml", "Cargo.lock"),
         tool_run("KERNEL-TEST", ["cargo", "test", "-q", "--locked", "-p", "containment-kernel"], "crates/containment-kernel"),
         "cargo test -p containment-kernel", (44,), needs=("cargo",)),
    Rule("T1-GATE", "The full local gate, scripts/check.sh, passes with every tool present", T1, EVERYWHERE,
         tool_run("T1-GATE", ["bash", "scripts/check.sh"], "scripts/check.sh", 7200),
         "run vac check --t1 in the pinned container and fix the first failing step", (176,),
         needs=("cargo", "node", "bend", "java")),
)

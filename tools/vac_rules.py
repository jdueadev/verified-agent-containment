import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

vac_core = importlib.import_module("vac_core")
policy_check = importlib.import_module("policy_check")
workflow_lint = importlib.import_module("workflow_lint")
pins_check = importlib.import_module("pins_check")
vac_verify = importlib.import_module("vac_verify")
vac_safety = importlib.import_module("vac_safety")
vac_gen = importlib.import_module("vac_gen")
results_ratchet = importlib.import_module("results_ratchet")
vac_comments = importlib.import_module("vac_comments")

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


def proof_matches_generator(ctx):
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "tools").mkdir()
        (Path(tmp) / "formal").mkdir()
        shutil.copy(ctx.root / "tools/generate_proof.py", Path(tmp) / "tools/generate_proof.py")
        child = __import__("subprocess").run([sys.executable, "tools/generate_proof.py"], cwd=tmp, capture_output=True, text=True)
        if child.returncode != 0:
            return [Finding("FV-PROOF-GEN", "tools/generate_proof.py", 0, f"generator failed: {child.stderr.strip()[-300:]}")]
        if (Path(tmp) / "formal/PROOF.bend").read_bytes() != (ctx.root / "formal/PROOF.bend").read_bytes():
            return [Finding("FV-PROOF-GEN", "formal/PROOF.bend", 0, "differs from what tools/generate_proof.py writes")]
    return []


def lean_pinned(ctx):
    pinned = pins_check.parse_pins((ctx.root / "ci/pins.env").read_text(encoding="utf-8"))
    if not re.fullmatch(r"\d+\.\d+\.\d+", pinned.get("LEAN_VERSION", "")):
        return [Finding("FV-PIN", "ci/pins.env", 0, "LEAN_VERSION is missing or not X.Y.Z")]
    return []


def formal_in_sync(ctx):
    return [Finding("FV-SYNC", cid, 0, "covered files changed since the formal checks last confirmed it: " + ", ".join(files))
            for cid, files in sorted(vac_verify.stale(ctx.root).items())]


def base_ref(ctx):
    if ctx.base:
        return ctx.base
    return ctx.once("base", lambda: vac_core.git(ctx, "merge-base", "HEAD", "origin/main").strip())


def escalations(ctx):
    def compute():
        base = base_ref(ctx)
        base_get, head_get = policy_check.reader(base), policy_check.reader("HEAD")
        paths = [p for p in vac_core.git(ctx, "diff", "--name-only", "--no-renames", base, "HEAD").splitlines() if p]
        c = vac_safety.core(base_get)
        core_hits, waivable = vac_safety.split(vac_safety.escalation_reasons(base, head_get, base_get, paths), c)
        return core_hits + vac_safety.status_drops(c, head_get), waivable, base_get, head_get
    return ctx.once("escalations", compute)


def core_intact(ctx):
    core_hits = escalations(ctx)[0]
    return [Finding("SAFE-CORE", "claims.toml", 0, f"{r}: evidence a claim cites is never waivable; restore it, or add new evidence in a new name")
            for r in core_hits]


def waivers_cover(ctx):
    _, waivable, base_get, head_get = escalations(ctx)
    out = []
    try:
        base_rows = vac_safety.load_waivers(base_get(vac_safety.WAIVERS_FILE))
        head_rows = vac_safety.load_waivers(head_get(vac_safety.WAIVERS_FILE))
    except ValueError as error:
        return [Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, str(error))]
    if head_rows[:len(base_rows)] != base_rows:
        out.append(Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, "waivers are append-only: an existing row was changed or removed"))
    covered = {row["reason"] for row in head_rows}
    out += [Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, f"{r}: no waiver; run vac waive") for r in waivable if r not in covered]
    latest = {row["reason"]: row for row in head_rows[len(base_rows):]}
    for row in latest.values():
        receipt_path = ctx.root / "ci/waiver-receipts" / f"{row['receipt']}.json"
        if not receipt_path.exists():
            out.append(Finding("WAIVE-1", str(receipt_path.relative_to(ctx.root)), 0, f"{row['reason']}: receipt missing"))
            continue
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        body = {k: v for k, v in receipt.items() if k != "digest"}
        digest = __import__("hashlib").sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if digest != row["receipt"] or receipt.get("digest") != digest:
            out.append(Finding("WAIVE-1", str(receipt_path.relative_to(ctx.root)), 0, f"{row['reason']}: receipt digest does not match"))
        elif not receipt.get("ok") or row["reason"] not in receipt.get("waivable", []):
            out.append(Finding("WAIVE-1", str(receipt_path.relative_to(ctx.root)), 0, f"{row['reason']}: the safety loop did not pass for it"))
        elif receipt.get("base") != base_ref(ctx):
            out.append(Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, f"{row['reason']}: its receipt judged from base {str(receipt.get('base'))[:12]}, the gate judges from {base_ref(ctx)[:12]}; run vac waive again"))
        elif row["head"] != receipt.get("head"):
            out.append(Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, f"{row['reason']}: the waiver names head {row['head'][:12]}, its receipt ran at {str(receipt.get('head'))[:12]}"))
        else:
            try:
                diff = vac_core.git(ctx, "diff", "--name-only", row["head"], "HEAD")
            except subprocess.CalledProcessError:
                out.append(Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0, f"{row['reason']}: head {row['head'][:12]} is not in this history; run vac waive again"))
                continue
            moved = [p for p in diff.splitlines()
                     if p and p != vac_safety.WAIVERS_FILE and not p.startswith("ci/waiver-receipts/")]
            if moved:
                out.append(Finding("WAIVE-1", vac_safety.WAIVERS_FILE, 0,
                                   f"{row['reason']}: the tree changed after the safety loop ran ({', '.join(moved[:5])}); run vac waive again"))
    return out
def results_rule(rule_id, watches):
    def check(ctx):
        try:
            found = ctx.once("results-ratchet", lambda: results_ratchet.ratchet(ctx.base))
        except (subprocess.CalledProcessError, OSError, UnicodeDecodeError, LookupError) as error:
            return [Finding(rule_id, "results", 0, f"cannot compare results/ with the base: {error}")]
        return [Finding(rule_id, path, 0, message) for path, message in found
                if any(vac_core.matches(path, w) for w in watches)]
    return check


def generated_files_match(ctx):
    out = []
    for path, text in vac_gen.generated(RULES, UNENFORCED).items():
        target = ctx.root / path
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            out.append(Finding("GEN-1", path, 0, "differs from what vac gen writes; generated files are never edited by hand"))
    return out


def no_decision_records(ctx):
    found = sorted(p.relative_to(ctx.root).as_posix() for p in (ctx.root / "docs/decisions").glob("*")) \
        if (ctx.root / "docs/decisions").exists() else []
    return [Finding("DEC-1", p, 0, "decision records are gone; put the reason in the rule's refs issue") for p in found]


def panic_aborts(ctx):
    import tomllib
    profile = tomllib.loads((ctx.root / "Cargo.toml").read_text(encoding="utf-8")).get("profile", {}).get("release", {})
    if profile.get("panic") != "abort":
        return [Finding("RS-PANIC", "Cargo.toml", 0, f"[profile.release] panic is {profile.get('panic')!r}, not \"abort\"")]
    return []


ALLOW_ATTR = re.compile(r"#\s*!?\s*\[\s*allow\s*\(([^)]*)\)")
CRLF_EOL = ("i/crlf", "i/mixed")


def allow_lints(text):
    found = []
    for attribute in ALLOW_ATTR.finditer(text or ""):
        found += [name.strip() for name in attribute.group(1).split(",") if name.strip()] or [""]
    return found


def allow_count(get, paths):
    return sum(len(allow_lints(get(p))) for p in paths)


def allow_places(get, paths):
    places = {}
    for path in paths:
        for lint in allow_lints(get(path)):
            places[(path, lint)] = places.get((path, lint), 0) + 1
    return places


def allow_added(before, after):
    return sorted(place for place, count in after.items() if count > before.get(place, 0))


def allow_not_added(ctx):
    base = base_ref(ctx)
    head_paths = [p for p in vac_core.git(ctx, "ls-files", "--", "crates").splitlines() if p.endswith(".rs")]
    base_paths = [p for p in vac_core.git(ctx, "ls-tree", "-r", "--name-only", base, "--", "crates").splitlines()
                  if p.endswith(".rs")]
    before = allow_places(policy_check.reader(base), base_paths)
    after = allow_places(lambda p: (ctx.root / p).read_text(encoding="utf-8") if (ctx.root / p).exists() else None,
                         head_paths)
    return [Finding("RS-ALLOW", path, 0, f"#[allow({lint})] is new here; it was not at {base[:12]}")
            for path, lint in allow_added(before, after)]


def line_endings(ctx):
    out = []
    for line in vac_core.git(ctx, "ls-files", "--eol").splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[0] in CRLF_EOL and not fields[3].endswith(".cmd"):
            out.append(Finding("EOL-1", fields[3], 0, f"committed with {fields[0][2:]} line endings; only *.cmd may hold CRLF"))
    return out
def comment_tree(ctx):
    return ctx.once("comment-tree", lambda: vac_comments.Tree(ctx.root, ctx.base or vac_comments.MAIN))


def no_new_comments(ctx):
    try:
        spans = vac_comments.new_comments(comment_tree(ctx), ctx.changed)
    except ValueError as error:
        return [Finding("NC-1", vac_comments.DEBT_FILE, 0, str(error))]
    return [Finding("NC-1", s.path, s.line, vac_comments.describe(s)) for s in spans]


def comment_debt_shrinks(ctx):
    try:
        errors = vac_comments.debt_errors(comment_tree(ctx))
    except ValueError as error:
        errors = [str(error)]
    return findings("NC-2", errors, vac_comments.DEBT_FILE)


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
RESULT_RULES = {
    "RES-TLA": ("No TLC configuration stops behaving as expected, disappears or explores fewer states",
                ("results/tla-check.json",), "bash tools/tla_check.sh"),
    "RES-MUT": ("No mutant stops being rejected or witnessed, and no law loses its last killing mutant",
                ("results/mutation-check.json",), "bash scripts/check.sh"),
    "RES-DIFF": ("No differential runs fewer cases, drops below the floor or finds a mismatch",
                 ("results/differential.json", "results/wasm-differential.json"), "bash scripts/check.sh"),
    "RES-VERDICT": ("The formal verdict never stops being ALL PROOFS CHECK", ("results/formal-verdict.json",),
                    "bash scripts/verdict.sh"),
    "RES-LAB": ("No lab scenario or sabotage control is lost, timed_repeat never drops, no cgroup waiver appears",
                ("results/attack-suite.json", "results/live-suite.json", "results/ci/**"),
                "the lab, .github/workflows/lab.yaml on main,"),
}

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
    Rule("FV-PROOF-GEN", "formal/PROOF.bend is exactly what tools/generate_proof.py writes", T0,
         ("formal/PROOF.bend", "tools/generate_proof.py"), proof_matches_generator,
         "python3 tools/generate_proof.py, then commit formal/PROOF.bend", (209,)),
    Rule("FV-PIN", "The Lean version that rechecks the proofs is pinned in ci/pins.env", T0, ("ci/pins.env",),
         lean_pinned, "add LEAN_VERSION=X.Y.Z to ci/pins.env", (209,)),
    Rule("FV-SYNC", "Every formal claim was confirmed against the code it covers at its current files", RC,
         ("claims.toml", "formal/**", "crates/**", "results/formal-sync.json"), formal_in_sync,
         "vac verify record (it runs vac check --t1 in full first)", (209,)),
    Rule("SAFE-CORE", "No change removes, rewords or lowers evidence that a claim cites", T0,
         ("claims.toml", "formal/**", "tools/kernel_mutants.py", "crates/**"), core_intact,
         "restore the cited law, mutant, scenario or claim; strengthen by adding a new one under a new name", (209,)),
    Rule("WAIVE-1", "Every other weakening carries a waiver backed by a passing safety loop", T0,
         ("**",), waivers_cover, "vac waive --reason '<the reason>' --issue N", (209,)),
    *(Rule(rule_id, title, T0, watches, results_rule(rule_id, watches),
           f"rerun {producer} and fix the code until results/ is no weaker; a deliberate weakening needs its own "
           "issue (#213)", (213,))
      for rule_id, (title, watches, producer) in RESULT_RULES.items()),
    Rule("GEN-1", "AGENTS.md and CLAUDE.md are exactly what vac gen writes from this registry", T0,
         ("AGENTS.md", "CLAUDE.md", "tools/vac_rules.py", "tools/vac_gen.py"), generated_files_match,
         "python3 tools/vac.py gen --write", (209,)),
    Rule("DEC-1", "No decision record exists; a rule's reason lives in its refs issue", T0, ("docs/decisions/**",),
         no_decision_records, "delete the file and put the reason in the issue the rule's refs name", (209,)),
    Rule("RS-PANIC", "Release builds abort on panic, so a controller panic is a fail-stop", T0, ("Cargo.toml",),
         panic_aborts, "set panic = \"abort\" under [profile.release] in Cargo.toml", (209,)),
    Rule("RS-ALLOW", "No #[allow] is added to get past a lint", T0, ("crates/**",), allow_not_added,
         "remove the #[allow] and fix what the lint reports", (209,)),
    Rule("EOL-1", "Text files are committed LF; only *.cmd keeps CRLF", T0, EVERYWHERE, line_endings,
         "convert the file to LF (git add --renormalize)", (209,)),
    Rule("RS-CLIPPY", "Kernel and host pass clippy with -D warnings, sabotage build included; every unsafe says why",
         T0, ("crates/**", "Cargo.toml", "Cargo.lock", "clippy.toml"),
         tool_run("RS-CLIPPY", ["bash", "-c", "cargo clippy -q --locked -p containment-kernel -p containment-host --all-targets -- -D warnings"
                             " && cargo clippy -q --locked -p containment-host --all-targets --features sabotage -- -D warnings"],
                  "crates"),
         "cargo clippy -p containment-host --all-targets -- -D warnings; add // SAFETY: above each unsafe block", (209,),
         needs=("cargo",)),
    Rule("NC-1", "No tracked file outside ci/comment_debt.toml has a comment", T0, EVERYWHERE, no_new_comments,
         "turn the comment into a rule in tools/vac_rules.py, a message the code prints, or a name; else delete it",
         (209,)),
    Rule("NC-2", "ci/comment_debt.toml only shrinks, and lists only files that still have comments", T0, EVERYWHERE,
         comment_debt_shrinks, "python3 tools/vac.py comments --debt-write; a file can leave the list, never join it",
         (209,)),
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

UNENFORCED = (
    ("PR-ISSUE", "A pull request links an open issue with Closes #n or Part of #n, in any lane, from any author", 211),
    ("PR-ONE", "No other open pull request closes the same issue", 211),
    ("PR-BODY", "The pull request body is written by vac pr and carries a receipt for its head", 212),
    ("WF-THIN", "Every workflow run: is one line, python3 tools/vac.py ci <job>", 206),
    ("WF-TRIG", "No schedule except the weekly digest, no workflow_run, no push to main", 206),
    ("RS-UNWRAP", "No new unwrap or expect on input an agent can influence in the host", 209),
    ("LAB-THROWAWAY", "The root lab runs only in a disposable Linux or WSL2 machine; vac refuses its commands", 209),
    ("CLAUDE-REVIEW", "Review a branch that touches agent configuration by its diff, or with claude --bare --setting-sources user", 169),
    ("EV-REPRO", "At a release candidate, check outputs are regenerated and compared byte for byte with results/", 209),
    ("SAFE-ATTEST", "At a release candidate, the safety loop runs in CI and is attested; a waiver without it blocks the tag", 209),
)

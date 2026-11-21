#!/usr/bin/env python3
"""Check claims.toml against the repository's evidence and generate docs/claims.md.

Usage:
  claims_check.py [--write] [--strict]
  claims_check.py --affected [GIT_REF]

Without --write, fails if docs/claims.md is out of date (in non-strict mode,
staleness-only doc drift is reported as a warning so Draft PRs can iterate
without committing throwaway stale tables). --strict also fails on stale rows
and on suite results whose build stamps or run settings are missing or wrong.

--affected [GIT_REF] prints a local summary of which claims are invalidated by
uncommitted edits (default: vs HEAD) or branch edits (e.g. --affected origin/main).

CI-1  every law: in a non-planned row exists in formal/LAWS.bend, and results/formal-verdict.json
      hashes match the formal/ files at HEAD
CI-2  every law, Bend mutant, Rust mutant and sabotage in the repository is cited by some row
CI-3  proved needs a law:; checked-bounded needs a tla: that passed in results/tla-check.json for the current spec; tested needs a falsifier that was caught
      (cited mutants/sabotages detected, cited scenarios passed in every recorded run, doc: text present)
CI-4  a row is stale when a path in its files changed after the commit of every passing platform
      (reported as a warning and shown as stale; an error with --strict). A platform whose commit
      predates a change is marked in docs/claims.md.
CI-5  no row is stronger than its weakest depends_on
CI-6  every claim id cited in docs/design-spec.md exists
CI-7  every tracked file under crates/containment-host/src is matched by the files (path, directory
      prefix, or glob pathspec) of some row
CI-8  (--strict) results/attack-suite.json and results/live-suite.json record that the honest runs
      came from a default build and the sabotage controls from a different, sabotage build, and
      results/attack-suite.json is a full unwaived run (timed_repeat >= 30, no limits waiver)
CI-9  every passing platform names a commit that has tracked artifacts under results/ (a path
      containing the commit id). This shows the evidence is linked, not that it is authentic.
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
GLOB_META = set("*?[")
MIN_ATTACK_TIMED_REPEAT = 30


def is_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in GLOB_META)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a git-style glob pattern (*, **, ?, [...]) to a full-match regex."""
    out = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                j = i + 2
                while j < n and pattern[j] == "*":
                    j += 1
                if j < n and pattern[j] == "/":
                    out.append("(?:.*/)?")
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            j = i + 1
            if j < n and pattern[j] in ("!", "^"):
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))
                i += 1
            else:
                body = pattern[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                body = body.replace("\\", "\\\\")
                if body.startswith("^"):
                    out.append(f"[{body}/]")
                else:
                    out.append(f"[{body}]")
                i = j + 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def path_matches(path: str, pattern: str) -> bool:
    """Match a repo-relative POSIX path against an exact file, directory prefix, or glob."""
    norm_path = path.replace("\\", "/").lstrip("./")
    norm_pat = pattern.replace("\\", "/").lstrip("./").rstrip("/")
    if not norm_pat:
        return False
    if is_glob(norm_pat):
        return bool(glob_to_regex(norm_pat).match(norm_path))
    return norm_path == norm_pat or norm_path.startswith(norm_pat + "/")


def git_pathspec(pattern: str) -> str:
    norm = pattern.replace("\\", "/")
    return f":(glob){norm}" if is_glob(norm) else norm


class InventoryError(Exception):
    """An inventory could not be taken completely. Never treated as an empty one."""


_RAW_STRING = re.compile(r'b?r(#*)"')


def _skip_literal_or_comment(src, i):
    """If a comment, string or char literal starts at i, return (index after it, kind),
    else None. Covers line and nested block comments, plain, byte and raw strings,
    and char literals as distinct from lifetimes. Enough to find the suite tables
    reliably; a full Rust lexer is #61 step 2."""
    if src.startswith("//", i):
        end = src.find("\n", i)
        return (len(src) if end < 0 else end), "comment"
    if src.startswith("/*", i):
        depth, j = 1, i + 2
        while depth:
            if j >= len(src):
                raise InventoryError("unterminated block comment")
            if src.startswith("/*", j):
                depth, j = depth + 1, j + 2
            elif src.startswith("*/", j):
                depth, j = depth - 1, j + 2
            else:
                j += 1
        return j, "comment"
    raw = _RAW_STRING.match(src, i)
    if raw and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
        close = '"' + raw.group(1)
        end = src.find(close, raw.end())
        if end < 0:
            raise InventoryError("unterminated raw string")
        return end + len(close), "string"
    if src[i] == '"':
        j = i + 1
        while j < len(src) and src[j] != '"':
            j += 2 if src[j] == "\\" else 1
        if j >= len(src):
            raise InventoryError("unterminated string")
        return j + 1, "string"
    if src[i] == "'":
        # A char literal is one char or one escape between quotes; anything else
        # starting with an apostrophe (`'a`, `'static`) is a lifetime or label.
        if src.startswith("\\", i + 1):
            # Follow the escape's own shape: \u{hex and _}, \xNN, or one char.
            escape = re.compile(r"\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|[^\n])'").match(src, i + 1)
            if not escape:
                raise InventoryError("malformed char literal")
            return escape.end(), "char"
        if i + 2 < len(src) and src[i + 2] == "'" and src[i + 1] not in "'\n":
            return i + 3, "char"
    return None


def _blank(src, comments=True, strings=False):
    """src with comments (and optionally string and char contents) replaced by spaces.
    Offsets and newlines are kept, so positions and line starts still line up with src."""
    out, i = [], 0
    while i < len(src):
        found = _skip_literal_or_comment(src, i)
        if found is None:
            out.append(src[i])
            i += 1
            continue
        after, kind = found
        piece = src[i:after]
        if kind == "comment" and comments:
            piece = re.sub(r"[^\n]", " ", piece)
        elif kind != "comment" and strings:
            piece = piece[0] + re.sub(r"[^\n]", " ", piece[1:-1]) + piece[-1]
        out.append(piece)
        i = after
    return "".join(out)


def const_array_names(src, const, where):
    """Names in `const <const>: ... = &[ ... ];`, one per top-level entry, whatever the
    line layout. An entry is a string literal or a tuple whose first field is one.
    Comments are ignored, including a commented-out declaration. Raises InventoryError
    when the block is missing, repeated, unclosed or empty, or when any entry yields
    no name: an inventory is either complete or an error."""
    src = _blank(src)
    code_only = _blank(src, comments=False, strings=True)
    decls = [m for m in re.finditer(rf"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?const[ \t]+{const}[ \t]*:", code_only)]
    if len(decls) != 1:
        raise InventoryError(f"{where}: expected one `const {const}:` declaration, found {len(decls)}")
    eq = src.find("=", decls[0].end())
    open_at = src.find("[", eq) if eq >= 0 else -1
    if open_at < 0 or src[eq + 1:open_at].strip() != "&":
        raise InventoryError(f"{where}: `const {const}` is not `= &[ ... ]`")
    entries, start, depth, i = [], open_at + 1, 0, open_at + 1
    while True:
        if i >= len(src):
            raise InventoryError(f"{where}: `const {const}` is not closed")
        found = _skip_literal_or_comment(src, i)
        if found is not None:
            i = found[0]
            continue
        ch = src[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        elif (ch == "," and depth == 0) or (ch == "]" and depth == 0):
            entries.append(src[start:i])
            start = i + 1
            if ch == "]":
                break
        i += 1
    names = []
    for raw in entries:
        entry = raw.strip()  # comments were already blanked by the scanner
        if not entry:
            continue  # trailing comma, or a comment between entries
        match = re.fullmatch(r'\(\s*"([a-z_]+)"\s*(?:,.*)?\)|"([a-z_]+)"', entry, re.S)
        if not match:
            raise InventoryError(f"{where}: an entry of `const {const}` has no literal name: {entry[:60]!r}")
        names.append(match.group(1) or match.group(2))
    if not names:
        raise InventoryError(f"{where}: `const {const}` has no entries")
    return names


def load_inventory():
    laws = re.findall(r"^law ([a-z_0-9]+):", (ROOT / "formal/LAWS.bend").read_text(encoding="utf-8"), re.M)
    spec = importlib.util.spec_from_file_location("kernel_mutants", ROOT / "tools/kernel_mutants.py")
    mutants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mutants)
    bend = [m[0] for m in mutants.BEND_MUTANTS]
    rust = [m[0] for m in mutants.RUST_MUTANTS]
    harness_path = "crates/containment-host/src/harness.rs"
    live_path = "crates/containment-host/src/live_suite.rs"
    harness = (ROOT / harness_path).read_text(encoding="utf-8")
    live_src = (ROOT / live_path).read_text(encoding="utf-8")
    sabotage = const_array_names(harness, "SABOTAGE", harness_path)
    scenarios = const_array_names(harness, "SCENARIOS", harness_path)
    live_sabotage = const_array_names(live_src, "SABOTAGE", live_path)
    live_scenarios = const_array_names(live_src, "SCENARIOS", live_path)
    return laws, bend, rust, sabotage, scenarios, live_scenarios, live_sabotage


def load_results():
    mutation = json.loads((ROOT / "results/mutation-check.json").read_text(encoding="utf-8"))
    suites = [json.loads(p.read_text(encoding="utf-8")) for p in [ROOT / "results/attack-suite.json", ROOT / "results/attack-suite-under-cpu-load.json"] if p.exists()]
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
            data = json.loads(path.read_text(encoding="utf-8"))
            diffs[name] = data.get("mismatches", 1) == 0
    live_ok, live_sab_ok = {}, {}
    live_path = ROOT / "results/live-suite.json"
    if live_path.exists():
        live = json.loads(live_path.read_text(encoding="utf-8"))
        for run in live["runs"]:
            live_ok[run["scenario"]] = live_ok.get(run["scenario"], True) and bool(run["passed"])
        for item in live["sabotage"]:
            live_sab_ok[item["weakness"]] = bool(item["detected"])
    return bend_ok, rust_ok, scenario_ok, sabotage_ok, diffs, live_ok, live_sab_ok


def canonical_bytes(path: Path) -> bytes:
    """Read spec bytes with LF line endings so Windows autocrlf checkouts match Linux digests."""
    return path.read_bytes().replace(b"\r\n", b"\n")


def verdict_matches_head():
    verdict = json.loads((ROOT / "results/formal-verdict.json").read_text(encoding="utf-8"))
    for path, digest in verdict["sha256"].items():
        if hashlib.sha256(canonical_bytes(ROOT / path)).hexdigest() != digest:
            return False, f"{path} differs from the hash in results/formal-verdict.json"
    return verdict["result"] == "ALL PROOFS CHECK", verdict["result"]


def tla_passed(spec, prop):
    """A tla:<spec>#<prop> reference holds if results/tla-check.json records the
    property as passed for the spec file as it is now."""
    path = ROOT / "results/tla-check.json"
    if not path.exists() or spec != "host":
        return False
    data = json.loads(path.read_text(encoding="utf-8"))
    # The recorded digest covers the spec and every configuration TLC ran.
    inputs = data.get("inputs") or [data["spec"]]
    if data["spec"] not in inputs:
        return False
    current = hashlib.sha256(b"".join(canonical_bytes(ROOT / p) for p in inputs)).hexdigest()
    return data["sha256"] == current and prop in data["passed"] and all(r["as_expected"] for r in data["runs"])


def uncovered_sources(claims, root="crates/containment-host/src", tracked=None):
    """Tracked host sources that no claim matches in `files` (CI-7). An inventory
    that cannot be taken, or is empty, is reported: it is not full coverage."""
    if tracked is None:
        try:
            tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", root],
                                     capture_output=True, text=True, check=True).stdout.splitlines()
        except (subprocess.CalledProcessError, FileNotFoundError):
            tracked = []
    if not tracked:
        return [f"{root} (git could not list its tracked files, so coverage was not checked)"]
    patterns = [pattern for claim in claims for pattern in claim.get("files", [])]
    return [f for f in tracked if not any(path_matches(f, pattern) for pattern in patterns)]


def provenance_errors(claims, tracked=None):
    """A passing platform entry must point at lab artifacts that are in the
    repository (CI-9): some tracked path under results/ contains its commit id.
    A listing that cannot be taken is reported, not treated as a pass."""
    if tracked is None:
        try:
            tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "results"],
                                     capture_output=True, text=True, check=True).stdout.splitlines()
        except (subprocess.CalledProcessError, FileNotFoundError):
            tracked = []
    if not tracked:
        return ["CI-9 git could not list results/, so platform provenance was not checked"]
    out = []
    for claim in claims:
        for platform in claim.get("platforms", []):
            commit = str(platform.get("commit", ""))
            if not str(platform.get("result", "")).startswith("pass"):
                continue
            if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
                out.append(f"CI-9 {claim['id']}: platform {platform.get('name')} has no commit id")
            elif not any(commit in path for path in tracked):
                out.append(f"CI-9 {claim['id']}: no tracked file under results/ records the run at {commit}")
    return out


def build_errors(results_dir=None):
    """The honest runs must come from a default build and the controls from a
    sabotage build, the two must be different binaries, and attack-suite.json
    must be a full unwaived run (CI-8)."""
    results_dir = ROOT / "results" if results_dir is None else Path(results_dir)
    out = []
    for name in ["attack-suite.json", "live-suite.json"]:
        path = results_dir / name
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        build = data.get("build") or {}
        honest, controls = build.get("honest") or {}, build.get("sabotage") or {}
        if honest.get("sabotage") is not False:
            out.append(f"CI-8 results/{name}: the honest runs are not stamped as coming from a default build")
        elif controls.get("sabotage") is not True:
            out.append(f"CI-8 results/{name}: the sabotage controls are not stamped as coming from a sabotage build")
        elif not all(isinstance(part.get("binary_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", part["binary_sha256"])
                     for part in (honest, controls)):
            out.append(f"CI-8 results/{name}: a build stamp has no SHA-256 of its binary")
        elif honest.get("binary_sha256") == controls.get("binary_sha256"):
            out.append(f"CI-8 results/{name}: the honest runs and the controls came from the same binary")
        if name == "attack-suite.json":
            repeat = data.get("timed_repeat")
            if isinstance(repeat, bool) or not isinstance(repeat, int) or repeat < MIN_ATTACK_TIMED_REPEAT:
                out.append(f"CI-8 results/{name}: timed_repeat is {repeat!r}, need at least {MIN_ATTACK_TIMED_REPEAT} for merged evidence")
            if data.get("cgroup_limits_waived") is not False:
                out.append(f"CI-8 results/{name}: honest runs must have cgroup_limits_waived=false (got {data.get('cgroup_limits_waived')!r})")
            if data.get("controls_cgroup_limits_waived") is not False:
                out.append(f"CI-8 results/{name}: sabotage controls must have controls_cgroup_limits_waived=false (got {data.get('controls_cgroup_limits_waived')!r})")
    return out


def changed_since(commit, paths):
    if not paths:
        return []
    specs = [git_pathspec(p) for p in paths]
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", commit, "--", *specs],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [f"(cannot diff against {commit})"]
    return [line for line in out.splitlines() if line]


def affected_claims(claims, changed_files):
    """Map each affected claim id to the changed files that matched its `files`."""
    out = []
    for claim in claims:
        patterns = claim.get("files", [])
        hits = [f for f in changed_files if any(path_matches(f, pat) for pat in patterns)]
        if hits:
            has_lab = any(p["result"].startswith("pass") for p in claim.get("platforms", []))
            out.append({
                "id": claim["id"],
                "layer": claim["layer"],
                "status": claim["status"],
                "needs_lab": has_lab,
                "files": hits,
            })
    return out


def run_affected(claims, base_ref):
    try:
        diff_out = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", base_ref],
                                  capture_output=True, text=True, check=True).stdout.splitlines()
        untracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--others", "--exclude-standard"],
                                   capture_output=True, text=True, check=True).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"error: could not compute changed files against {base_ref}: {exc}", file=sys.stderr)
        return 1
    changed = sorted({p.replace("\\", "/") for p in diff_out + untracked if p})
    if not changed:
        print(f"No changed files relative to {base_ref}. No claims affected.")
        return 0
    hits = affected_claims(claims, changed)
    lab_hits = [h for h in hits if h["needs_lab"]]
    fast_hits = [h for h in hits if not h["needs_lab"]]
    print(f"Changed files vs {base_ref} ({len(changed)}):")
    for f in changed:
        print(f"  - {f}")
    if not hits:
        print("\nAffected claims: none (no root lab run needed).")
        return 0
    if lab_hits:
        print(f"\nHost claims requiring root lab refresh before merge ({len(lab_hits)}):")
        for h in lab_hits:
            print(f"  - {h['id']} ({h['layer']}/{h['status']}): {', '.join(h['files'])}")
    else:
        print("\nNo host lab claims affected (fast CI only; no root lab run needed).")
    if fast_hits:
        print(f"\nNon-lab claims checked by fast CI ({len(fast_hits)}):")
        for h in fast_hits:
            print(f"  - {h['id']} ({h['layer']}/{h['status']}): {', '.join(h['files'])}")
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    claims = tomllib.loads((ROOT / "claims.toml").read_text(encoding="utf-8"))["claim"]
    if "--affected" in args:
        idx = args.index("--affected")
        base_ref = args[idx + 1] if idx + 1 < len(args) and not args[idx + 1].startswith("-") else "HEAD"
        return run_affected(claims, base_ref)

    strict = "--strict" in args
    write = "--write" in args
    try:
        laws, bend, rust, sabotage, scenarios, live_scenarios, live_sabotage = load_inventory()
    except InventoryError as error:
        print(json.dumps({"claims": len(claims), "errors": [f"CI-2 inventory: {error}"]}, indent=2))
        return 1
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
            return path.exists() and text in path.read_text(encoding="utf-8")
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

    spec_ids = set(re.findall(r"\b([CLAKRH]-[A-Z0-9]+-[A-Z0-9]+|C-SYS-1|C-DOC-1)\b", (ROOT / "docs/design-spec.md").read_text(encoding="utf-8")))
    for sid in sorted(spec_ids - set(by_id)):
        errors.append(f"CI-6 docs/design-spec.md cites {sid}, which is not in claims.toml")

    for path in uncovered_sources(claims):
        errors.append(f"CI-7 {path} is not covered by the files of any claim")

    errors.extend(provenance_errors(claims))

    stale = {c["id"]: c["_stale"] for c in claims if c["_stale"]}
    warnings = [f"CI-4 {cid}: stale, {', '.join(files)} changed after its platform commit; rerun and update platforms"
                for cid, files in stale.items()]

    markdown = render(claims, effective, verdict_ok, len(laws), len(bend), len(rust), len(sabotage))
    target = ROOT / "docs/claims.md"
    if write:
        target.write_text(markdown, encoding="utf-8", newline="\n")
    elif not target.exists() or target.read_text(encoding="utf-8") != markdown:
        if strict or not stale:
            errors.append("docs/claims.md is out of date; run tools/claims_check.py --write")
        else:
            warnings.append("docs/claims.md will need regeneration after refreshing stale lab evidence")

    counts = {}
    for status in effective.values():
        counts[status] = counts.get(status, 0) + 1
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

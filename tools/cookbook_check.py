#!/usr/bin/env python3
"""Keep the proof cookbook (docs/cookbook/) tied to its sources, and run its snippets.

Usage:
  cookbook_check.py           check; writes nothing
  cookbook_check.py --write   regenerate every generated region in docs/cookbook/*.md

A recipe holds generated regions between marker lines:

  <!-- cookbook:begin KIND ARGS -->
  ...
  <!-- cookbook:end KIND ARGS -->

  claim ID        the claim's id, layer, statement, limits and falsifier, copied verbatim
                  from claims.toml (no status: the effective status depends on git
                  history and is in docs/claims.md)
  law NAME...     the laws, quoted from formal/LAWS.bend with their line numbers
  mutant NAME     the Bend mutant's edit as a diff against formal/kernel.bend
  snippet ID      docs/cookbook/snippets/ID.json and the output of running it

Static stage (python only, always runs): every region equals what --write would
produce, every law and mutant a recipe shows is cited by the recipe's claim, every
snippet is shown by exactly one recipe, no claim cites the cookbook as doc: evidence,
and if web/dist embeds the cookbook, its inlined interpreter and snippets are
byte-identical to the sources.

Toolchain stage (node, bend and the artifacts scripts/check.sh builds): every snippet
must pass on the Bend kernel (target/generated/kernel.mjs) and on a fresh instance of
the release wasm, the two must observe the same values on every step, and the
snippet's `breaks` mutant must fail the run with the snippet's `teeth` expectation
among the failures. A mutant run that throws is an error, never teeth. The snippet
transcripts are checked here too. Missing tools print SKIPPED locally (tier T0) and
fail when CI is set.

Snippets are documentation tests, not evidence: no claim may cite them, and this tool
never writes results/. scripts/check.sh never passes --write.
"""
import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from claims_check import mutant_names  # noqa: E402  (trusted base, lane C)

ROOT = Path(__file__).resolve().parent.parent
COOKBOOK = "docs/cookbook"
SNIPPETS = f"{COOKBOOK}/snippets"
LAWS = "formal/LAWS.bend"
KERNEL = "formal/kernel.bend"
PAGE = "web/dist/agent-containment-simulator.html"
INTERPRETER = "tools/snippet_run.mjs"
DRIVER = "tools/snippet_node.mjs"
BEND_JS = "target/generated/kernel.mjs"
WASM = "target/wasm32-unknown-unknown/release/containment_wasm.wasm"
MUTANT_JS = "target/generated/cookbook"
KINDS = {"claim", "law", "mutant", "snippet"}
MARKER = re.compile(r"^<!-- cookbook:(begin|end) ([a-z]+)((?: [A-Za-z0-9_.-]+)+) -->$")
TRANSCRIPT = "<!-- cookbook:transcript -->"
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# Delimiters of the blocks web/build.py inlines into the page (see page_blocks).
PAGE_INTERPRETER = ("/*cookbook:interpreter*/", "/*cookbook:end-interpreter*/")
PAGE_SNIPPETS = ("/*cookbook:snippets*/", "/*cookbook:end-snippets*/")
EXPORT_LINE = "export { validate, runSnippet, bendAdapter, wasmAdapter };"
NODE_TIMEOUT_S = 120
# The interpreter runs inside the page as well as under node: no imports, I/O or eval.
FORBIDDEN_JS = (r"^\s*import\b", r"\bimport\s*\(", r"\brequire\s*\(", r"\beval\s*\(", r"\bFunction\s*\(",
                r"\bfetch\s*\(", r"\bXMLHttpRequest\b", r"\bprocess\.", r"\bdocument\.", r"\bwindow\.")
# A page that mentions these is running the interpreter, so it must embed both blocks.
PAGE_FINGERPRINTS = ("runSnippet", "bendAdapter", "wasmAdapter", "cookbook:")


class CookbookError(Exception):
    pass


def rel(root, path):
    return path.relative_to(root).as_posix()


def read(root, path):
    return (root / path).read_text(encoding="utf-8")


# ---------- sources ----------

def law_blocks(text):
    """{name: (first line, last line, text)} for every law in LAWS.bend. A block is the
    run of `#` lines directly above `law NAME:` (no blank line between), the law line, and
    the lines after it up to the first blank line or the end of the file."""
    lines = text.split("\n")
    out = {}
    for i, line in enumerate(lines):
        m = re.match(r"^law ([a-z_0-9]+):$", line)
        if not m:
            continue
        name = m.group(1)
        if name in out:
            raise CookbookError(f"{LAWS}: law {name} is defined more than once")
        start = i
        while start > 0 and lines[start - 1].startswith("#"):
            start -= 1
        end = i
        while end + 1 < len(lines) and lines[end + 1].strip():
            end += 1
        out[name] = (start + 1, end + 1, "\n".join(lines[start:end + 1]))
    return out


def bend_mutants(text):
    """{name: (old, new)} from BEND_MUTANTS in tools/kernel_mutants.py, read as data. The
    file's shape is first checked by claims_check.mutant_names."""
    bend, _ = mutant_names(text)
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "BEND_MUTANTS":
            table = {name: (old, new) for name, old, new in ast.literal_eval(node.value)}
            assert sorted(table) == sorted(bend)
            return table
    raise CookbookError("tools/kernel_mutants.py: BEND_MUTANTS not found")


def apply_mutant(source, name, old, new):
    if source.count(old) != 1:
        raise CookbookError(f"mutant {name}: its target occurs {source.count(old)} times in {KERNEL}, not once")
    return source.replace(old, new, 1)


def mutant_diff(source, name, old, new):
    """(first line, last line, diff lines) for the original lines the mutant touches."""
    apply_mutant(source, name, old, new)
    at = source.index(old)
    first = source.count("\n", 0, at)
    last = source.count("\n", 0, at + len(old))
    before = source.split("\n")[first:last + 1]
    region = "\n".join(before)
    if region.count(old) != 1:
        raise CookbookError(f"mutant {name}: cannot place its edit")
    after = region.replace(old, new, 1)
    diff = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=before, b=after.split("\n"), autojunk=False).get_opcodes():
        if tag == "equal":
            diff += [" " + x for x in before[i1:i2]]
        else:
            diff += ["-" + x for x in before[i1:i2]]
            diff += ["+" + x for x in after.split("\n")[j1:j2]]
    return first + 1, last + 1, diff


def load_claims(root):
    return {c["id"]: c for c in tomllib.loads(read(root, "claims.toml"))["claim"]}


def doc_ref_errors(root, claims):
    """A generated recipe copies claim text, so a doc: check pointed at it would pass by
    construction. No claim may use the cookbook as evidence. The path is resolved the way
    the filesystem would open it, so `./`, `//`, `..` and symlinks cannot hide it."""
    out = []
    cookbook = (root / COOKBOOK).resolve()
    recipes = {recipe.resolve() for recipe in (root / COOKBOOK).glob("*.md")}
    for cid, claim in claims.items():
        for ref in claim.get("evidence", []):
            kind, _, target = ref.partition(":")
            if kind != "doc":
                continue
            path = (root / target.split("#", 1)[0]).resolve()
            if path == cookbook or path.is_relative_to(cookbook) or path in recipes:
                out.append(f"claims.toml {cid}: {ref} points into {COOKBOOK}/; the cookbook is not evidence")
    return out


def load_snippets(root):
    """{id: (path, text, parsed)}. Python checks only what it needs to cross-reference;
    the schema belongs to tools/snippet_run.mjs (validate), run in the toolchain stage."""
    folder = root / SNIPPETS
    out, errors = {}, []
    paths = sorted(folder.glob("*.json")) if folder.is_dir() else []
    others = sorted(p.name for p in folder.iterdir() if p.suffix != ".json") if folder.is_dir() else []
    for name in others:
        errors.append(f"{SNIPPETS}/{name}: only .json snippets belong here")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        where = rel(root, path)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as err:
            errors.append(f"{where}: not JSON: {err}")
            continue
        if not isinstance(data, dict) or data.get("id") != path.stem:
            errors.append(f"{where}: its \"id\" must equal the file name, {path.stem}")
            continue
        out[path.stem] = (where, text, data)
    if not out and not errors:
        errors.append(f"{SNIPPETS}: no snippets found; the cookbook must have at least one")
    return out, errors


# ---------- regions ----------

def parse_regions(text, where):
    """[(kind, args, begin line index, end line index)] in file order."""
    lines = text.split("\n")
    regions, open_ = [], None
    seen = set()
    for i, line in enumerate(lines):
        # Any line that starts like a marker must be an exact one, so a near miss (an
        # indent, a typo) is an error instead of silently not being a region.
        if not line.lstrip().startswith("<!-- cookbook:"):
            continue
        if line == TRANSCRIPT:
            if open_ is None or open_[0] != "snippet":
                raise CookbookError(f"{where}:{i + 1}: {TRANSCRIPT} outside a snippet region")
            continue
        m = MARKER.match(line)
        if not m:
            raise CookbookError(f"{where}:{i + 1}: malformed cookbook marker: {line.strip()}")
        what, kind, args = m.group(1), m.group(2), tuple(m.group(3).split())
        if kind not in KINDS:
            raise CookbookError(f"{where}:{i + 1}: unknown region kind {kind!r}")
        if what == "begin":
            if open_ is not None:
                raise CookbookError(f"{where}:{i + 1}: region {kind} begins inside region {open_[0]}")
            if (kind, args) in seen:
                raise CookbookError(f"{where}:{i + 1}: region {kind} {' '.join(args)} appears twice")
            seen.add((kind, args))
            open_ = (kind, args, i)
        else:
            if open_ is None or open_[:2] != (kind, args):
                raise CookbookError(f"{where}:{i + 1}: end {kind} {' '.join(args)} does not close an open region")
            regions.append((kind, args, open_[2], i))
            open_ = None
    if open_ is not None:
        raise CookbookError(f"{where}:{open_[2] + 1}: region {open_[0]} is never closed")
    return regions


def link(path, first, last):
    span = f"line {first}" if first == last else f"lines {first}–{last}"
    anchor = f"#L{first}" if first == last else f"#L{first}-L{last}"
    return f"[`{path}`, {span}](../../{path}{anchor})"


def render_claim(claim):
    out = [f"> **{claim['id']}** · layer `{claim['layer']}` · Generated from "
           "[`claims.toml`](../../claims.toml); claims.toml wins. "
           "Status and evidence: [`docs/claims.md`](../claims.md).",
           ">", *quoted("Statement", claim["statement"])]
    if claim.get("limits"):
        out += [">", *quoted("Limits", claim["limits"])]
    out += [">", *quoted("Falsifier", claim["falsifier"])]
    return out


def quoted(label, text):
    """A claim field as block-quote lines, one output line per line of the value, so a
    multi-line value is written and re-read as the same lines."""
    lines = str(text).split("\n")
    return [f"> **{label}:** {lines[0]}"] + [f"> {line}" if line else ">" for line in lines[1:]]


def render_laws(names, laws):
    groups = []
    for name in names:
        first, last, text = laws[name]
        if groups and first == groups[-1][1] + 2:
            groups[-1] = (groups[-1][0], last, groups[-1][2] + "\n\n" + text)
        else:
            groups.append((first, last, text))
    out = []
    for first, last, text in groups:
        if out:
            out.append("")
        out += [f"Quoted from {link(LAWS, first, last)}:", "", "```", *text.split("\n"), "```"]
    return out


def render_mutant(name, diff):
    first, last, lines = diff
    return [f"Mutant `{name}` from [`tools/kernel_mutants.py`](../../tools/kernel_mutants.py), "
            f"applied to {link(KERNEL, first, last)}:", "", "```diff", *lines, "```"]


def render_snippet_source(sid, text, page_has_cookbook):
    run = (f" Run it in the [simulator page](../../{PAGE}#recipe={sid}) (open the downloaded file in a browser)."
           if page_has_cookbook else "")
    return [f"Snippet [`snippets/{sid}.json`](snippets/{sid}.json), checked by "
            f"[`tools/cookbook_check.py`](../../tools/cookbook_check.py) on every `scripts/check.sh` run.{run}",
            "", "```json", *text.rstrip("\n").split("\n"), "```"]


def describe_event(e):
    extra = {"renew": f" ttl {e.get('ttl')}", "classifier": f" {e.get('level')}", "hard": f" {e.get('level')}",
             "reset": f" signed={str(e.get('signed')).lower()} counter {e.get('counter')} from {e.get('from')}"
                      f" not_after {e.get('not_after')} ttl {e.get('ttl')}"}.get(e.get("type"), "")
    return f"{e.get('type')}{extra} at {e.get('now')}"


def render_transcript(snippet, bend, mutant_name, mutant):
    out = ["Output of the Bend kernel (`target/generated/kernel.mjs`), recorded by `cookbook_check.py --write`. "
           "`scripts/check.sh` reruns the snippet and fails if this output, the Rust kernel's, or the "
           "mutant's result changes.", "", "```text"]
    for n, (step, got) in enumerate(zip(snippet["steps"], bend["steps"]), 1):
        o = got["observed"]
        actions = ", ".join(o["actions"]) or "none"
        access = "".join(f"; {a['kind']} {'allowed' if ok else 'denied'}" for a, ok in zip(step.get("access", []), o["access"]))
        out.append(f"step {n}: {describe_event(step['event'])} -> {o['mode']}, deadline {o['deadline']}, "
                   f"clock {o['clock']}, counter {o['counter']}, actions: {actions}{access}")
    out.append(f"on mutant {mutant_name}:")
    for n, got in enumerate(mutant["steps"], 1):
        for f in got["failures"]:
            out.append(f"  step {n}: {f['field']} expected {json.dumps(f['expected'])}, observed {json.dumps(f['observed'])}")
    out.append("```")
    return out


def region_body(lines, begin, end):
    return lines[begin + 1:end]


def static_part(body):
    return body[:body.index(TRANSCRIPT)] if TRANSCRIPT in body else body


# ---------- the page ----------

def inline_interpreter(source):
    """The interpreter as the page inlines it: the module body without its export line,
    as an expression that evaluates to the exported functions."""
    if source.count(EXPORT_LINE) != 1 or not source.rstrip("\n").endswith(EXPORT_LINE):
        raise CookbookError(f"{INTERPRETER}: must end with exactly one line `{EXPORT_LINE}`")
    if "</" in source or "<!--" in source or "*/" in source:
        raise CookbookError(f"{INTERPRETER}: must not contain `</`, `<!--` or `*/`, so it can be inlined in a script")
    for pattern in FORBIDDEN_JS:
        if re.search(pattern, source, re.M):
            raise CookbookError(f"{INTERPRETER}: must have no imports, I/O or eval; found {pattern}")
    body = source.rstrip("\n")[:-len(EXPORT_LINE)]
    return "(function(){\n" + body + "return { validate, runSnippet, bendAdapter, wasmAdapter };\n})()"


def script_json(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(ch, esc)
    return text


def page_blocks(root=ROOT):
    """{start delimiter: exact text} that web/build.py must inline into the page. The
    snippets go in as their source text, so the page shows and runs the committed file."""
    snippets, errors = load_snippets(root)
    if errors:
        raise CookbookError("; ".join(errors))
    return {
        PAGE_INTERPRETER[0]: PAGE_INTERPRETER[0] + inline_interpreter(read(root, INTERPRETER)) + PAGE_INTERPRETER[1],
        PAGE_SNIPPETS[0]: PAGE_SNIPPETS[0] + script_json({sid: text for sid, (_, text, _) in snippets.items()}) + PAGE_SNIPPETS[1],
    }


def page_errors(root, page_text):
    """If the committed page embeds the cookbook, it must embed exactly the current sources."""
    if not any(mark in page_text for mark in PAGE_FINGERPRINTS):
        return [], False
    errors = []
    try:
        blocks = page_blocks(root)
    except CookbookError as err:
        return [f"{PAGE}: {err}"], True
    for start, end in (PAGE_INTERPRETER, PAGE_SNIPPETS):
        if page_text.count(start) != 1 or page_text.count(end) != 1:
            errors.append(f"{PAGE}: needs exactly one {start} ... {end} block")
            continue
        found = page_text[page_text.index(start):page_text.index(end) + len(end)]
        if found != blocks[start]:
            errors.append(f"{PAGE}: the {start} block differs from the sources; rebuild the page (scripts/build-page.sh)")
    return errors, True


# ---------- the toolchain ----------

def node_runner(request):
    """Run tools/snippet_node.mjs on a request and return its parsed output."""
    result = subprocess.run(["node", str(ROOT / DRIVER)], input=json.dumps(request), text=True,
                            capture_output=True, timeout=NODE_TIMEOUT_S, cwd=ROOT)
    if result.returncode != 0:
        raise CookbookError(f"{DRIVER} failed: {result.stderr.strip()[-2000:]}")
    return json.loads(result.stdout)["results"]


def missing_tools(root):
    out = [tool for tool in ("node", "bend") if shutil.which(tool) is None]
    out += [path for path in (BEND_JS, WASM) if not (root / path).is_file()]
    return out


def build_mutants(root, names, mutants, out_dir):
    """Compile each named Bend mutant once, from a scratch copy of formal/, into
    out_dir/<name>.mjs: a temporary directory when checking, target/generated/cookbook/
    when building the page (page_inputs)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    source = read(root, KERNEL)
    paths = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(names):
            work = Path(tmp) / name / "formal"
            shutil.copytree(root / "formal", work)
            old, new = mutants[name]
            (work / "kernel.bend").write_text(apply_mutant(source, name, old, new), encoding="utf-8")
            built = subprocess.run(["bend", "kernel.bend", "-o", "mutant.mjs"], cwd=work, text=True,
                                   capture_output=True, timeout=NODE_TIMEOUT_S)
            if built.returncode != 0 or not (work / "mutant.mjs").is_file():
                raise CookbookError(f"mutant {name} did not compile: {(built.stdout + built.stderr).strip()[-1000:]}")
            target = out_dir / f"{name}.mjs"
            shutil.copyfile(work / "mutant.mjs", target)
            paths[name] = target
    return paths


def judge(sid, snippet, results, mutant_name):
    """Errors for one snippet's runs on bend, wasm and its mutant."""
    errors = []
    where = f"{SNIPPETS}/{sid}.json"

    def failures_text(result):
        if result["status"] == "error":
            return result.get("error", "error")
        return "; ".join(f"step {n}: {f['field']} expected {json.dumps(f['expected'])}, observed {json.dumps(f['observed'])}"
                         for n, s in enumerate(result["steps"], 1) for f in s["failures"])

    for kernel in ("bend", "wasm"):
        result = results[kernel]
        if result["status"] != "pass":
            errors.append(f"{where}: {result['status']} on the {kernel} kernel: {failures_text(result)}")
    if not errors:
        for n, (a, b) in enumerate(zip(results["bend"]["steps"], results["wasm"]["steps"]), 1):
            if a["observed"] != b["observed"]:
                errors.append(f"{where}: step {n}: the Bend and wasm kernels disagree: "
                              f"bend {json.dumps(a['observed'])}, wasm {json.dumps(b['observed'])}")
    mutant = results["mutant"]
    teeth = snippet.get("teeth")
    if not (isinstance(teeth, dict) and type(teeth.get("step")) is int and teeth["step"] >= 1
            and isinstance(teeth.get("field"), str)):
        errors.append(f"{where}: teeth must be {{\"step\": N, \"field\": NAME}} with an integer step")
    elif mutant["status"] == "pass":
        errors.append(f"{where}: passes on mutant {mutant_name}; add an expectation the mutant breaks")
    elif mutant["status"] == "error":
        errors.append(f"{where}: the run on mutant {mutant_name} raised an error, which shows nothing: {mutant.get('error')}")
    else:
        step = mutant["steps"][teeth["step"] - 1] if len(mutant["steps"]) >= teeth["step"] else None
        if step is None or teeth["field"] not in [f["field"] for f in step["failures"]]:
            errors.append(f"{where}: mutant {mutant_name} does not break the teeth expectation "
                          f"(step {teeth['step']}, {teeth['field']}); it fails only: {failures_text(mutant)}")
    return errors


# ---------- main ----------

def check(root=ROOT, write=False, runner=None, toolchain=None, ci=None, snippets_only=False, keep_mutants=False):
    """(errors, notes). runner and toolchain are injectable so the unit tests need no
    node, bend or wasm: toolchain(root, snippets, mutant names) returns
    {id: {"bend": result, "wasm": result, "mutant": result}}, or None to skip.
    snippets_only runs the snippets and skips the recipe regions and the committed
    page, for the page build (see page_inputs). Only keep_mutants writes the mutant
    builds to target/generated/cookbook/; otherwise they live in a temporary directory."""
    assert not (write and snippets_only)
    ci = bool(os.environ.get("CI")) if ci is None else ci
    errors, notes = [], []
    claims = load_claims(root)
    errors += doc_ref_errors(root, claims)
    laws = law_blocks(read(root, LAWS))
    kernel_source = read(root, KERNEL)
    mutants = bend_mutants(read(root, "tools/kernel_mutants.py"))
    snippets, snippet_errors = load_snippets(root)
    errors += snippet_errors
    page_path = root / PAGE
    page_err, page_has_cookbook = page_errors(root, page_path.read_text(encoding="utf-8")) \
        if page_path.is_file() and not snippets_only else ([], False)
    errors += page_err

    # Cross-references a snippet needs before it can run.
    runnable = {}
    for sid, (where, text, data) in snippets.items():
        claim = claims.get(data.get("claim"))
        breaks = data.get("breaks")
        if claim is None:
            errors.append(f"{where}: unknown claim {data.get('claim')!r}")
        elif not isinstance(breaks, str) or not breaks.startswith("mutant:") or breaks[len("mutant:"):] not in mutants:
            errors.append(f"{where}: breaks must name a Bend mutant as mutant:NAME, got {breaks!r}")
        elif breaks not in claim.get("evidence", []):
            errors.append(f"{where}: {breaks} is not in the evidence of {claim['id']}")
        else:
            runnable[sid] = breaks[len("mutant:"):]

    # The toolchain stage, run once for all snippets.
    results = None
    if snippets:
        if toolchain is None:
            missing = missing_tools(root)
            if missing:
                message = f"cookbook snippets ({', '.join(missing)} missing)"
                if ci or write:
                    errors.append(f"cannot run {message}" + ("; --write needs them" if write else ""))
                else:
                    notes.append(f"SKIPPED: {message}")
            else:
                def toolchain(root_, snippets_, names):
                    with tempfile.TemporaryDirectory() as scratch:
                        out_dir = root_ / MUTANT_JS if keep_mutants else Path(scratch)
                        built = build_mutants(root_, set(names.values()), mutants, out_dir)
                        kernels = [{"name": "bend", "kind": "bend", "path": str(root_ / BEND_JS)},
                                   {"name": "wasm", "kind": "wasm", "path": str(root_ / WASM)}]
                        kernels += [{"name": f"mutant:{n}", "kind": "bend", "path": str(p)} for n, p in built.items()]
                        run = (runner or node_runner)({"kernels": kernels, "snippets": [
                            {"id": sid, "text": snippets_[sid][1]} for sid in names]})
                    return {sid: {"bend": run[sid]["bend"], "wasm": run[sid]["wasm"], "mutant": run[sid][f"mutant:{n}"]}
                            for sid, n in names.items()}
        if toolchain is not None and runnable:
            try:
                results = toolchain(root, snippets, runnable)
            except (CookbookError, OSError, subprocess.SubprocessError, ValueError, KeyError) as err:
                errors.append(f"cookbook snippets could not run: {err}")
        if results is not None:
            for sid, name in runnable.items():
                errors += judge(sid, snippets[sid][2], results[sid], name)

    if snippets_only:
        return errors, notes

    # Regions.
    shown = {}
    changed, rewrites = [], []
    for path in sorted((root / COOKBOOK).glob("*.md")):
        where = rel(root, path)
        if path.is_symlink():
            errors.append(f"{where}: a recipe must be a regular file, not a symlink")
            continue
        text = path.read_text(encoding="utf-8")
        try:
            regions = parse_regions(text, where)
        except CookbookError as err:
            errors.append(str(err))
            continue
        claim_ids = [args for kind, args, _, _ in regions if kind == "claim"]
        if path.name == "README.md" and not regions:
            continue
        if len(claim_ids) != 1:
            errors.append(f"{where}: a recipe needs exactly one claim region, found {len(claim_ids)}")
            continue
        claim = claims.get(claim_ids[0][0])
        if claim is None or len(claim_ids[0]) != 1:
            errors.append(f"{where}: unknown claim {' '.join(claim_ids[0])}")
            continue
        # Without this, deleting a region's markers would turn its checked block back into
        # unchecked prose. A recipe for a Bend kernel claim shows a law, a mutant and a snippet.
        kinds = {kind for kind, _, _, _ in regions}
        if claim["layer"] == "bend-kernel":
            missing = [k for k in ("law", "mutant", "snippet") if k not in kinds]
            if missing:
                errors.append(f"{where}: a recipe for a bend-kernel claim needs a {', a '.join(missing)} region")
        lines = text.split("\n")
        new_lines, cursor = [], 0
        for kind, args, begin, end in regions:
            body = region_body(lines, begin, end)
            expected, compare_all = None, True
            if kind == "claim":
                expected = render_claim(claim)
            elif kind == "law":
                bad = [n for n in args if n not in laws]
                uncited = [n for n in args if n in laws and f"law:{n}" not in claim.get("evidence", [])]
                if bad:
                    errors.append(f"{where}: no law {', '.join(bad)} in {LAWS}")
                elif uncited:
                    errors.append(f"{where}: {claim['id']} does not cite law {', '.join(uncited)}")
                else:
                    expected = render_laws(args, laws)
            elif kind == "mutant":
                name = args[0]
                if len(args) != 1 or name not in mutants:
                    errors.append(f"{where}: no Bend mutant {' '.join(args)}")
                elif f"mutant:{name}" not in claim.get("evidence", []):
                    errors.append(f"{where}: {claim['id']} does not cite mutant:{name}")
                else:
                    try:
                        expected = render_mutant(name, mutant_diff(kernel_source, name, *mutants[name]))
                    except CookbookError as err:
                        errors.append(f"{where}: {err}")
            elif kind == "snippet":
                sid = args[0]
                if len(args) != 1 or sid not in snippets:
                    errors.append(f"{where}: no snippet {' '.join(args)} in {SNIPPETS}/")
                else:
                    shown.setdefault(sid, []).append(where)
                    _, stext, data = snippets[sid]
                    if data.get("claim") != claim["id"] or data.get("recipe") != path.stem:
                        errors.append(f"{where}: snippet {sid} belongs to claim {data.get('claim')!r} and recipe "
                                      f"{data.get('recipe')!r}, not {claim['id']} and {path.stem}")
                    expected = render_snippet_source(sid, stext, page_has_cookbook)
                    if results is not None and sid in runnable and results[sid]["bend"]["status"] == "pass" \
                            and results[sid]["mutant"]["status"] == "fail":
                        expected = expected + [TRANSCRIPT, *render_transcript(data, results[sid]["bend"], runnable[sid], results[sid]["mutant"])]
                    else:
                        compare_all = False
            if expected is None:
                new_lines += lines[cursor:end + 1]
                cursor = end + 1
                continue
            same = body == expected if compare_all else static_part(body) == expected
            if not compare_all:
                notes.append(f"{where}: transcript of snippet {args[0]} not checked (snippets did not run)")
            if not same:
                if write:
                    # Applied only if the whole check passes; with no errors every snippet
                    # ran, so compare_all holds and `expected` is the complete region.
                    changed.append(f"{where}: {kind} {' '.join(args)}")
                else:
                    diff = "\n".join(difflib.unified_diff(body, expected, "committed", "generated", lineterm="", n=1))
                    errors.append(f"{where}:{begin + 1}: region {kind} {' '.join(args)} is out of date; "
                                  f"run python3 tools/cookbook_check.py --write\n{diff}")
                new_lines += lines[cursor:begin + 1] + expected + [lines[end]]
            else:
                new_lines += lines[cursor:end + 1]
            cursor = end + 1
        new_lines += lines[cursor:]
        if new_lines != lines:
            rewrites.append((path, "\n".join(new_lines)))

    for sid, (where, _, _) in snippets.items():
        places = shown.get(sid, [])
        if len(places) != 1:
            errors.append(f"{where}: must be shown by exactly one recipe snippet region, found {len(places)}")
    if write:
        if errors:
            notes.append("--write changed nothing: fix the errors and run it again")
        else:
            for path, text in rewrites:
                path.write_text(text, encoding="utf-8", newline="\n")
            notes += [f"rewrote {c}" for c in changed]
    return errors, notes


def page_inputs(root=ROOT):
    """What web/build.py may embed: {snippet id: Bend mutant name}, only after every
    snippet has run and passed (toolchain required), and only names from BEND_MUTANTS,
    whose builds are in target/generated/cookbook/<name>.mjs. Recipe regions and the
    committed page are not checked here: the page is what is being rebuilt."""
    errors, _ = check(root, ci=True, snippets_only=True, keep_mutants=True)
    if errors:
        raise CookbookError("cookbook snippets failed; the page is not built:\n" + "\n".join(errors))
    mutants = bend_mutants(read(root, "tools/kernel_mutants.py"))
    snippets, _ = load_snippets(root)
    out = {}
    for sid, (_, _, data) in snippets.items():
        name = data["breaks"][len("mutant:"):]
        if name not in mutants or not re.fullmatch(r"[a-z0-9_]+", name):
            raise CookbookError(f"snippet {sid}: {data['breaks']!r} is not a Bend mutant")
        out[sid] = name
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["--write"]):
        print("usage: cookbook_check.py [--write]", file=sys.stderr)
        return 2
    try:
        errors, notes = check(write=argv == ["--write"])
    except CookbookError as err:
        errors, notes = [str(err)], []
    for note in notes:
        print(note, file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    snippets = len(list((ROOT / SNIPPETS).glob("*.json"))) if (ROOT / SNIPPETS).is_dir() else 0
    print(json.dumps({"snippets": snippets, "errors": len(errors),
                      "toolchain": "skipped" if any(n.startswith("SKIPPED") for n in notes) else "ran"}))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

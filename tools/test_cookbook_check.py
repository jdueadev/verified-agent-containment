#!/usr/bin/env python3
"""Unit tests for tools/cookbook_check.py and tools/snippet_run.mjs.

The checker tests build a small fixture repository and inject the toolchain stage,
so they need no node, bend or wasm. The interpreter tests run tools/snippet_run.mjs
under node on a toy kernel; they skip when node is missing locally and fail in CI."""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cookbook_check as cb

TOOLS = Path(__file__).resolve().parent

CLAIMS = '''
[[claim]]
id = "K-T-01"
statement = "Nothing lowers the mode."
layer = "bend-kernel"
status = "proved"
evidence = ["law:tighten", "law:stays", "mutant:can_lower"]
falsifier = "A lower mode"
files = ["formal/kernel.bend"]

[[claim]]
id = "K-T-02"
statement = "Another claim."
layer = "bend-kernel"
status = "proved"
evidence = ["law:other", "mutant:other_mutant"]
falsifier = "Something else"
files = ["formal/kernel.bend"]
'''

LAWS = '''# Header for the section.

# Tighten only.
law tighten:
  for +m: Mode
  {ok(m)}

# Stays put.
law stays:
  for +m: Mode
  {ok(m)}

law other:
  {ok}
'''

KERNEL = '''def step(m):
  match m:
    case Restrict{}:
      Restrict{}
'''

MUTANTS = '''"""Fixture mutants."""
BEND_MUTANTS = [
    ("can_lower", "    case Restrict{}:\\n      Restrict{}", "    case Restrict{}:\\n      Run{}"),
    ("other_mutant", "def step(m):", "def step(n):"),
]
RUST_MUTANTS = [
    ("rust_one", "a", "b"),
]
'''

SNIPPET = {
    "id": "t-one", "claim": "K-T-01", "recipe": "t", "title": "Restrict stays",
    "breaks": "mutant:can_lower", "teeth": {"step": 2, "field": "mode"},
    "config": {"max_lease": 2500, "freeze_grace": 4000},
    "start": {"mode": "run", "deadline": 2000, "clock": 0, "counter": 0},
    "steps": [
        {"event": {"type": "classifier", "now": 100, "level": "restrict"}, "expect": {"mode": "restrict"}},
        {"event": {"type": "classifier", "now": 200, "level": "restrict"}, "expect": {"mode": "restrict"}},
    ],
}

RECIPE = '''# Test recipe

<!-- cookbook:begin claim K-T-01 -->
<!-- cookbook:end claim K-T-01 -->

<!-- cookbook:begin law tighten stays -->
<!-- cookbook:end law tighten stays -->

<!-- cookbook:begin mutant can_lower -->
<!-- cookbook:end mutant can_lower -->

<!-- cookbook:begin snippet t-one -->
<!-- cookbook:end snippet t-one -->
'''


def observed(mode, clock):
    return {"mode": mode, "deadline": 2000, "clock": clock, "counter": 0, "actions": [], "access": []}


def result(status, *steps):
    return {"status": status, "steps": [{"observed": o, "failures": f} for o, f in steps]}


PASS = result("pass", (observed("restrict", 100), []), (observed("restrict", 200), []))
MUTANT_FAIL = result("fail", (observed("restrict", 100), []),
                     (observed("run", 200), [{"field": "mode", "expected": "restrict", "observed": "run"}]))


def fake(bend=PASS, wasm=PASS, mutant=MUTANT_FAIL):
    def toolchain(root, snippets, names):
        return {sid: {"bend": copy.deepcopy(bend), "wasm": copy.deepcopy(wasm), "mutant": copy.deepcopy(mutant)} for sid in names}
    return toolchain


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.put("claims.toml", CLAIMS)
        self.put("formal/LAWS.bend", LAWS)
        self.put("formal/kernel.bend", KERNEL)
        self.put("tools/kernel_mutants.py", MUTANTS)
        self.put("tools/snippet_run.mjs", (TOOLS / "snippet_run.mjs").read_text(encoding="utf-8"))
        self.put("docs/cookbook/t.md", RECIPE)
        self.snippet(SNIPPET)
        errors, _ = cb.check(self.root, write=True, toolchain=fake(), ci=False)
        self.assertEqual(errors, [])

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def get(self, path):
        return (self.root / path).read_text(encoding="utf-8")

    def snippet(self, data, name=None):
        self.put(f"docs/cookbook/snippets/{name or data['id']}.json", json.dumps(data, indent=2) + "\n")

    def errors(self, **kw):
        kw.setdefault("toolchain", fake())
        errors, _ = cb.check(self.root, ci=False, **kw)
        return errors

    def assertFails(self, needle, **kw):
        errors = self.errors(**kw)
        self.assertTrue(any(needle in e for e in errors), errors)


class GenerationTests(Fixture):
    def test_generated_recipe_passes_and_write_is_idempotent(self):
        before = self.get("docs/cookbook/t.md")
        self.assertEqual(self.errors(), [])
        errors, notes = cb.check(self.root, write=True, toolchain=fake(), ci=False)
        self.assertEqual(errors, [])
        self.assertEqual(self.get("docs/cookbook/t.md"), before)
        self.assertFalse(any(n.startswith("rewrote") for n in notes), notes)

    def test_generated_content(self):
        text = self.get("docs/cookbook/t.md")
        self.assertIn("> **Statement:** Nothing lowers the mode.", text)
        self.assertNotIn("proved", text)  # the claim block shows no status
        # Adjacent laws share one block, comments included, the section header not.
        self.assertIn("lines 3–11](../../formal/LAWS.bend#L3-L11)", text)
        self.assertIn("# Tighten only.\nlaw tighten:", text)
        self.assertNotIn("# Header for the section.", text)
        self.assertIn("```diff\n     case Restrict{}:\n-      Restrict{}\n+      Run{}\n```", text)
        self.assertIn(cb.TRANSCRIPT, text)
        self.assertIn("  step 2: mode expected \"restrict\", observed \"run\"", text)

    def test_check_mode_writes_nothing(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md").replace("Nothing lowers", "Nothing ever lowers"))
        before = self.get("docs/cookbook/t.md")
        self.assertFails("region claim K-T-01 is out of date")
        self.assertEqual(self.get("docs/cookbook/t.md"), before)
        self.assertFalse((self.root / "results").exists())

    def test_write_changes_nothing_when_there_are_errors(self):
        text = self.get("docs/cookbook/t.md").replace("Nothing lowers", "Nothing ever lowers")
        self.put("docs/cookbook/t.md", text)
        errors, _ = cb.check(self.root, write=True, toolchain=fake(mutant=PASS), ci=False)
        self.assertTrue(errors)
        self.assertEqual(self.get("docs/cookbook/t.md"), text)


class DriftTests(Fixture):
    def test_hand_edited_law_quote_fails(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md").replace("law stays:", "law stays_put:"))
        self.assertFails("region law tighten stays is out of date")

    def test_source_law_change_fails(self):
        self.put("formal/LAWS.bend", LAWS.replace("# Stays put.", "# Stays where it is."))
        self.assertFails("region law tighten stays is out of date")

    def test_kernel_change_moves_the_mutant_diff(self):
        self.put("formal/kernel.bend", "# a new first line\n" + KERNEL)
        self.assertFails("region mutant can_lower is out of date")

    def test_edited_transcript_fails(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md").replace("observed \"run\"", "observed \"hold\""))
        self.assertFails("region snippet t-one is out of date")

    def test_edited_snippet_source_fails_without_the_toolchain(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md").replace('"title": "Restrict stays"', '"title": "Changed"'))
        errors, notes = cb.check(self.root, toolchain=lambda *a: None, ci=False)
        self.assertTrue(any("region snippet t-one is out of date" in e for e in errors), errors)


class RegionTests(Fixture):
    def edit(self, old, new):
        text = self.get("docs/cookbook/t.md")
        self.assertIn(old, text)
        self.put("docs/cookbook/t.md", text.replace(old, new, 1))

    def test_unclosed_region(self):
        self.edit("<!-- cookbook:end snippet t-one -->", "")
        self.assertFails("region snippet is never closed")

    def test_end_without_begin(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md") + "\n<!-- cookbook:end law tighten -->\n")
        self.assertFails("does not close an open region")

    def test_region_inside_another(self):
        self.edit("<!-- cookbook:end mutant can_lower -->\n", "")
        self.assertFails("region snippet begins inside region mutant")

    def test_nested_region(self):
        self.edit("<!-- cookbook:end law tighten stays -->", "<!-- cookbook:begin mutant can_lower -->")
        self.assertFails("begins inside region law")

    def test_duplicate_region(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md")
                 + "\n<!-- cookbook:begin mutant can_lower -->\n<!-- cookbook:end mutant can_lower -->\n")
        self.assertFails("appears twice")

    def test_unknown_kind(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md") + "\n<!-- cookbook:begin quote x -->\n<!-- cookbook:end quote x -->\n")
        self.assertFails("unknown region kind 'quote'")

    def test_near_miss_marker(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md") + "\n  <!-- cookbook:begin law tighten -->\n")
        self.assertFails("malformed cookbook marker")

    def test_unknown_claim(self):
        self.edit("begin claim K-T-01 -->", "begin claim K-T-99 -->")
        self.edit("end claim K-T-01 -->", "end claim K-T-99 -->")
        self.assertFails("unknown claim K-T-99")

    def test_recipe_without_a_claim_region(self):
        self.put("docs/cookbook/v.md", "# A recipe with the markers deleted\n")
        self.assertFails("docs/cookbook/v.md: a recipe needs exactly one claim region, found 0")

    def test_readme_without_regions_is_fine(self):
        self.put("docs/cookbook/README.md", "# Index\n")
        self.assertEqual(self.errors(), [])

    def test_bend_kernel_recipe_must_keep_its_checked_regions(self):
        text = self.get("docs/cookbook/t.md")
        start, end = text.index("<!-- cookbook:begin law"), text.index("<!-- cookbook:begin mutant")
        self.put("docs/cookbook/t.md", text[:start] + "law tighten_FAKE:\n  {ok}\n\n" + text[end:])
        self.assertFails("a recipe for a bend-kernel claim needs a law region")

    def test_two_claim_regions(self):
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md") + "\n<!-- cookbook:begin claim K-T-02 -->\n<!-- cookbook:end claim K-T-02 -->\n")
        self.assertFails("needs exactly one claim region")

    def test_unknown_law(self):
        self.edit("law tighten stays -->\n", "law tighten nope -->\n")
        self.edit("end law tighten stays", "end law tighten nope")
        self.assertFails("no law nope")

    def test_law_the_claim_does_not_cite(self):
        self.edit("law tighten stays -->\n", "law tighten other -->\n")
        self.edit("end law tighten stays", "end law tighten other")
        self.assertFails("K-T-01 does not cite law other")

    def test_law_defined_twice(self):
        self.put("formal/LAWS.bend", LAWS + "\nlaw stays:\n  {ok}\n")
        with self.assertRaises(cb.CookbookError):
            self.errors()

    def test_mutant_the_claim_does_not_cite(self):
        self.edit("mutant can_lower -->\n", "mutant other_mutant -->\n")
        self.edit("end mutant can_lower", "end mutant other_mutant")
        self.assertFails("K-T-01 does not cite mutant:other_mutant")

    def test_unknown_mutant(self):
        self.edit("mutant can_lower -->\n", "mutant rust_one -->\n")
        self.edit("end mutant can_lower", "end mutant rust_one")
        self.assertFails("no Bend mutant rust_one")


class SnippetTests(Fixture):
    def test_zero_snippets(self):
        (self.root / "docs/cookbook/snippets/t-one.json").unlink()
        self.assertFails("no snippets found")

    def test_orphan_snippet(self):
        self.snippet({**SNIPPET, "id": "t-two"})
        self.assertFails("t-two.json: must be shown by exactly one recipe snippet region, found 0")

    def test_snippet_shown_twice(self):
        self.put("docs/cookbook/u.md", "<!-- cookbook:begin claim K-T-01 -->\n<!-- cookbook:end claim K-T-01 -->\n"
                 "<!-- cookbook:begin snippet t-one -->\n<!-- cookbook:end snippet t-one -->\n")
        self.assertFails("found 2")

    def test_id_must_match_file_name(self):
        self.snippet({**SNIPPET, "id": "t-other"}, name="t-one")
        self.assertFails("must equal the file name")

    def test_unknown_claim(self):
        self.snippet({**SNIPPET, "claim": "K-T-99"})
        self.assertFails("unknown claim 'K-T-99'")

    def test_breaks_must_be_a_cited_bend_mutant(self):
        self.snippet({**SNIPPET, "breaks": "rust-mutant:rust_one"})
        self.assertFails("breaks must name a Bend mutant")
        self.snippet({**SNIPPET, "breaks": "mutant:other_mutant"})
        self.assertFails("mutant:other_mutant is not in the evidence of K-T-01")

    def test_safe_kernel_failure(self):
        bad = result("fail", (observed("restrict", 100), []), (observed("hold", 200), [{"field": "mode", "expected": "restrict", "observed": "hold"}]))
        self.assertFails("fail on the bend kernel", toolchain=fake(bend=bad))
        self.assertFails("fail on the wasm kernel", toolchain=fake(wasm=bad))

    def test_schema_error_reported(self):
        bad = {"status": "error", "error": 'step 1.expect: unknown key "mdoe"', "steps": []}
        self.assertFails('unknown key "mdoe"', toolchain=fake(bend=bad, wasm=bad, mutant=bad))

    def test_bend_and_wasm_disagree(self):
        other = result("pass", (observed("restrict", 100), []), (observed("restrict", 201), []))
        self.assertFails("the Bend and wasm kernels disagree", toolchain=fake(wasm=other))

    def test_mutant_that_passes_has_no_teeth(self):
        self.assertFails("passes on mutant can_lower", toolchain=fake(mutant=PASS))

    def test_mutant_that_throws_is_not_teeth(self):
        self.assertFails("raised an error, which shows nothing", toolchain=fake(mutant={"status": "error", "error": "boom", "steps": []}))

    def test_mutant_must_break_the_teeth_expectation(self):
        elsewhere = result("fail", (observed("hold", 100), [{"field": "mode", "expected": "restrict", "observed": "hold"}]),
                           (observed("restrict", 200), []))
        self.assertFails("does not break the teeth expectation", toolchain=fake(mutant=elsewhere))

    def test_doc_evidence_into_the_cookbook(self):
        (self.root / "web").mkdir()
        (self.root / "notes").symlink_to(self.root / "docs/cookbook")
        for ref in ("docs/cookbook/t.md", "docs/./cookbook/t.md", "docs//cookbook/t.md", "web/../docs/cookbook/t.md",
                    "./docs/cookbook/t.md", "notes/t.md", "docs/cookbook"):
            with self.subTest(ref=ref):
                self.put("claims.toml", CLAIMS.replace('"mutant:can_lower"]', f'"mutant:can_lower", "doc:{ref}#Nothing"]'))
                self.assertFails("points into docs/cookbook/")

    def test_doc_evidence_elsewhere_is_fine(self):
        self.put("claims.toml", CLAIMS.replace('"mutant:can_lower"]', '"mutant:can_lower", "doc:docs/cookbookish.md#x"]'))
        self.assertEqual(self.errors(), [])

    def test_teeth_that_is_not_an_integer_step(self):
        self.snippet({**SNIPPET, "teeth": {"step": 2.0, "field": "mode"}})
        self.assertFails("teeth must be")
        bad = {k: v for k, v in SNIPPET.items() if k != "teeth"}
        self.snippet(bad)
        self.assertFails("teeth must be")

    def test_missing_toolchain_skips_locally_and_fails_in_ci(self):
        self.assertEqual(cb.missing_tools(self.root)[-2:], [cb.BEND_JS, cb.WASM])
        errors, notes = cb.check(self.root, ci=False)
        self.assertEqual(errors, [])
        self.assertTrue(any(n.startswith("SKIPPED: cookbook snippets") for n in notes), notes)
        errors, _ = cb.check(self.root, ci=True)
        self.assertTrue(any("cannot run cookbook snippets" in e for e in errors), errors)
        errors, _ = cb.check(self.root, write=True, ci=False)
        self.assertTrue(any("--write needs them" in e for e in errors), errors)


class PageTests(Fixture):
    def test_page_without_the_cookbook_is_not_checked(self):
        self.put(cb.PAGE, "<script>const X=1;</script>")
        self.assertEqual(self.errors(), [])

    def test_page_must_embed_the_current_sources(self):
        blocks = cb.page_blocks(self.root)
        page = "<script>const RUN=" + blocks[cb.PAGE_INTERPRETER[0]] + ";const S=" + blocks[cb.PAGE_SNIPPETS[0]] + ";</script>"
        self.put(cb.PAGE, page)
        # With the cookbook in the page, each snippet region links to it.
        self.assertFails("region snippet t-one is out of date")
        cb.check(self.root, write=True, toolchain=fake(), ci=False)
        self.assertIn("simulator.html#recipe=t-one", self.get("docs/cookbook/t.md"))
        self.assertEqual(self.errors(), [])
        self.snippet({**SNIPPET, "title": "Changed"})
        self.assertFails("the /*cookbook:snippets*/ block differs from the sources")
        self.snippet(SNIPPET)
        self.assertEqual(self.errors(), [])
        weakened = page.replace('return { status: steps.some((s) => s.failures.length) ? "fail" : "pass", steps };',
                                'return { status: "pass", steps };')
        self.assertNotEqual(weakened, page)
        self.put(cb.PAGE, weakened)
        self.assertFails("the /*cookbook:interpreter*/ block differs from the sources")

    def test_page_running_the_interpreter_without_its_blocks(self):
        self.put(cb.PAGE, "<script>const r = runSnippet(a, b);</script>")
        self.assertFails("needs exactly one /*cookbook:interpreter*/")

    def test_page_inputs_skip_the_page_and_regions(self):
        self.put(cb.PAGE, "<script>runSnippet()</script>")  # a stale page must not block its rebuild
        self.put("docs/cookbook/t.md", self.get("docs/cookbook/t.md").replace("Nothing lowers", "Nothing ever lowers"))
        errors, _ = cb.check(self.root, toolchain=fake(), ci=False, snippets_only=True)
        self.assertEqual(errors, [])
        errors, _ = cb.check(self.root, toolchain=fake(mutant=PASS), ci=False, snippets_only=True)
        self.assertTrue(any("passes on mutant" in e for e in errors), errors)

    def test_multiline_claim_text_round_trips(self):
        self.put("claims.toml", CLAIMS.replace('statement = "Nothing lowers the mode."', 'statement = "Nothing lowers\\n\\nthe mode."'))
        cb.check(self.root, write=True, toolchain=fake(), ci=False)
        self.assertIn("> **Statement:** Nothing lowers\n>\n> the mode.", self.get("docs/cookbook/t.md"))
        self.assertEqual(self.errors(), [])

    def test_snippet_json_is_escaped_for_a_script(self):
        self.snippet({**SNIPPET, "title": "</script><script>alert(1)</script> "})
        text = cb.page_blocks(self.root)[cb.PAGE_SNIPPETS[0]]
        for bad in ("</", "<script", " "):
            self.assertNotIn(bad, text)

    def test_interpreter_must_be_inlinable(self):
        source = (TOOLS / "snippet_run.mjs").read_text(encoding="utf-8")
        self.assertIn("(function(){", cb.inline_interpreter(source))
        tail = "\n" + cb.EXPORT_LINE + "\n"
        body = source.replace(tail, "\n")
        for bad in (source + "\nexport const x = 1;\n", source.replace(cb.EXPORT_LINE, ""), source + "// </script>\n",
                    'import fs from "node:fs";\n' + source, body + "eval(x);" + tail, body + "const f = Function('x');" + tail,
                    body + "fetch(u);" + tail, body + "require('fs');" + tail, body + "document.title = 1;" + tail):
            with self.assertRaises(cb.CookbookError):
                cb.inline_interpreter(bad)


# A toy kernel with the Bend module's calling convention: a classifier raises the mode to
# its level, nothing ever lowers it, and access is allowed only in Run.
TOY = '''
const RANK = ["ModeRun", "ModeRestrict", "ModeHold", "ModeFreeze", "ModeKill"];
const LEVEL = {ToRestrict: 1, ToHold: 2, ToFreeze: 3, ToKill: 4};
export default {
  step(cfg, c, e) {
    let mode = c.mode.$;
    if (e.$ === "Classifier") mode = RANK[Math.max(RANK.indexOf(mode), LEVEL[e.level.$])];
    if (__LOWER__ && e.$ === "Classifier" && c.mode.$ === "ModeRestrict") mode = "ModeRun";
    if (e.$ === "AgentRequest") throw new Error("toy kernel: agent requests are not modelled");
    const plan = mode !== c.mode.$ ? {$: "Next", head: {$: "RevokeSecrets"}, tail: {$: "NoMore"}} : {$: "NoMore"};
    return {control: {...c, mode: {$: mode}, clock: e.now}, actions: plan};
  },
  authorize(now, c, r) { return c.mode.$ === "ModeRun" && r.granted; },
};
'''


@unittest.skipUnless(shutil.which("node") or os.environ.get("CI"), "node is missing (in CI this is a failure)")
class InterpreterTests(unittest.TestCase):
    """tools/snippet_run.mjs under node, through tools/snippet_node.mjs."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "safe.mjs").write_text(TOY.replace("__LOWER__", "false"))
        (self.dir / "lower.mjs").write_text(TOY.replace("__LOWER__", "true"))

    def run_snippets(self, *snippets):
        request = {"kernels": [{"name": "safe", "kind": "bend", "path": str(self.dir / "safe.mjs")},
                               {"name": "lower", "kind": "bend", "path": str(self.dir / "lower.mjs")}],
                   "snippets": [{"id": str(i), "text": s if isinstance(s, str) else json.dumps(s)} for i, s in enumerate(snippets)]}
        out = subprocess.run(["node", str(TOOLS / "snippet_node.mjs")], input=json.dumps(request), text=True,
                             capture_output=True, check=True, timeout=60)
        return [json.loads(out.stdout)["results"][str(i)] for i in range(len(snippets))]

    def snippet(self, **changes):
        s = copy.deepcopy(SNIPPET)
        s["steps"][0]["expect"]["actions"] = ["revoke_secrets"]
        s["steps"][0]["access"] = [{"kind": "secret", "granted": True, "baseline": True, "allowed": False}]
        s.update(changes)
        return s

    def test_pass_on_safe_and_fail_on_mutant(self):
        [r] = self.run_snippets(self.snippet())
        self.assertEqual(r["safe"]["status"], "pass", r["safe"])
        self.assertEqual(r["safe"]["steps"][0]["observed"]["actions"], ["revoke_secrets"])
        self.assertEqual(r["safe"]["steps"][0]["observed"]["access"], [False])
        self.assertEqual(r["lower"]["status"], "fail")
        self.assertEqual(r["lower"]["steps"][1]["failures"], [{"field": "mode", "expected": "restrict", "observed": "run"}])

    def assertInvalid(self, snippet, needle):
        [r] = self.run_snippets(snippet)
        self.assertEqual(r["safe"]["status"], "error", r["safe"])
        self.assertIn(needle, r["safe"]["error"])

    def test_unknown_expectation_key(self):
        s = self.snippet()
        s["steps"][1]["expect"] = {"mdoe": "restrict"}
        self.assertInvalid(s, 'unknown key "mdoe"')

    def test_unknown_top_level_and_event_keys(self):
        self.assertInvalid(self.snippet(extra=1), 'unknown key "extra"')
        s = self.snippet()
        s["steps"][0]["event"]["ttl"] = 5
        self.assertInvalid(s, 'step 1.event: unknown key "ttl"')

    def test_bad_values(self):
        s = self.snippet()
        s["steps"][0]["expect"]["mode"] = "paused"
        self.assertInvalid(s, "step 1.expect.mode: expected one of")
        s = self.snippet()
        s["steps"][0]["event"]["now"] = -1
        self.assertInvalid(s, "step 1.event.now: expected an integer")
        s = self.snippet()
        s["steps"][0]["event"]["type"] = "constructor"
        self.assertInvalid(s, '"type" must be one of')
        s = self.snippet()
        s["steps"][0]["expect"]["actions"] = ["__proto__"]
        self.assertInvalid(s, "expect.actions[0]: expected one of")

    def test_step_that_asserts_nothing(self):
        s = self.snippet()
        s["steps"][1]["expect"] = {}
        self.assertInvalid(s, "step 2: asserts nothing")

    def test_teeth_must_name_an_asserted_field(self):
        self.assertInvalid(self.snippet(teeth={"step": 2, "field": "counter"}), 'step 2 does not assert "counter"')
        self.assertInvalid(self.snippet(teeth={"step": 9, "field": "mode"}), "teeth.step: expected a step number")

    def test_breaks_must_be_a_bend_mutant_ref(self):
        self.assertInvalid(self.snippet(breaks="rust-mutant:x"), "must be a Bend mutant reference")

    def test_too_many_steps(self):
        s = self.snippet()
        s["steps"] = s["steps"] * 40
        self.assertInvalid(s, "steps: expected a list of 1 to 64 steps")

    def test_not_json(self):
        [r] = self.run_snippets("{not json")
        self.assertEqual(r["safe"]["status"], "error")
        self.assertIn("not JSON", r["safe"]["error"])

    def test_kernel_that_throws_is_an_error_not_a_failure(self):
        s = self.snippet()
        s["steps"][1]["event"] = {"type": "agent", "now": 200}
        [r] = self.run_snippets(s)
        self.assertEqual(r["safe"]["status"], "error")
        self.assertIn("agent requests are not modelled", r["safe"]["error"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Browser checks for the showcase, with and without native WebAssembly."""
import json, sys, tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright

page_file, shots = Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) > 2 else None
html = "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1,viewport-fit=cover'><style>body{margin:0}[hidden]{display:none!important}</style></head><body>" + page_file.read_text() + "</body></html>"
tmp = Path(tempfile.mkdtemp()) / "index.html"
tmp.write_text(html)
report = []

ROOT = Path(__file__).resolve().parents[1]
SNIPPET_FILES = sorted(p.stem for p in (ROOT / "docs/cookbook/snippets").glob("*.json"))


def verdicts(page):
    return page.evaluate("[...document.querySelectorAll('#cbVerdicts .cbverdict')].map(d => d.textContent)")


def cookbook(page):
    """The cookbook panel: every committed snippet passes on both kernels and is caught by
    its mutant at its teeth expectation; an invalid edit is reported, not thrown."""
    out = {}
    ids = page.evaluate("[...document.querySelectorAll('#cbList button')].map(b => b.dataset.id)")
    out["recipes_match_files"] = sorted(ids) == SNIPPET_FILES and len(ids) > 0
    out["runs"] = {}
    for sid in ids:
        page.click(f"#cb-{sid}")
        page.click("#cbRunAll")
        page.wait_for_function("document.querySelectorAll('#cbVerdicts .cbverdict').length === 3", timeout=10000)
        v = verdicts(page)
        out["runs"][sid] = v
        ok = len(v) == 3 and v[0].startswith("Pass") and v[1].startswith("Pass") and v[2].startswith("Caught") and not v[2].startswith("Caught elsewhere")
        out["runs_ok"] = out.get("runs_ok", True) and ok
    page.fill("#cbSource", "{ not json")
    out["edited_banner"] = page.is_visible("#cbEdited")
    page.click("#cbRunAll")
    page.wait_for_selector("#cbErrors:not([hidden])", timeout=4000)
    out["invalid_reported"] = "Not JSON" in page.inner_text("#cbErrors")
    page.fill("#cbSource", '{"id": "x"}')
    page.click("#cbRunAll")
    out["schema_reported"] = "missing" in page.inner_text("#cbErrors")
    page.click("#cbReset")
    out["reset"] = not page.is_visible("#cbEdited") and not page.url.endswith("x")
    out["not_evidence_label"] = "not evidence" in page.inner_text("#cookbook")
    out["ok"] = all(out[k] for k in ("recipes_match_files", "runs_ok", "edited_banner", "invalid_reported", "schema_reported", "reset", "not_evidence_label"))
    return out


def mode(page):
    return page.evaluate("[...document.querySelectorAll('.step')].findIndex(e => e.classList.contains('on'))")

def run(browser, native, scheme, width, full):
    context = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "fonts.g" not in m.text and "ERR_" not in m.text else None)
    if not native:
        page.add_init_script("WebAssembly.instantiate=()=>Promise.reject(new Error('blocked'))")
    page.goto(tmp.as_uri())
    page.wait_for_function("document.getElementById('engine').textContent.includes('kernel') && !document.getElementById('engine').textContent.includes('Loading')")
    item = {"native": native, "scheme": scheme, "width": width, "engine": page.inner_text("#engine")}
    page.click("#sc-classifier")
    page.wait_for_function("document.querySelector('.step.m2').classList.contains('on')", timeout=4000)
    page.wait_for_timeout(4500)
    item["classifier_stays_hold"] = mode(page) == 2
    page.click("#sc-reset")
    page.wait_for_timeout(4600)
    log = page.inner_text("#log")
    item["reset_story"] = log.count("Reset rejected") >= 4 and log.count("Signed reset accepted") == 1
    page.click("#sc-dead")
    page.wait_for_selector("#failstop:not([hidden])", timeout=15000)
    item["fail_stop_shown"] = True
    item["cookbook"] = cookbook(page)
    if full:
        page.click("#fuzz")
        page.wait_for_function("document.getElementById('fuzzResult').textContent.includes('transitions checked') || document.getElementById('fuzzResult').textContent.includes('Failures')", timeout=60000)
        item["safe_kernel"] = page.inner_text("#fuzzResult")
        page.click("#runAll")
        page.wait_for_function("document.getElementById('runAll').textContent.startsWith('Caught')", timeout=120000)
        item["bench"] = page.inner_text("#runAll")
        item["bench_missed"] = page.locator("#bench .pill.bad").count()
    page.keyboard.press("Tab")
    item["focus"] = page.evaluate("document.activeElement && document.activeElement.tagName")
    item["overflow"] = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shots / f"{'native' if native else 'fallback'}-{scheme}-{width}.png"), full_page=True)
    context.close()
    item["errors"] = errors
    report.append(item)
    ok = item["classifier_stays_hold"] and item["reset_story"] and item["cookbook"]["ok"] and item["focus"] and item["overflow"] <= 0 and not errors
    ok = ok and (("WebAssembly" in item["engine"]) if native else ("JavaScript build" in item["engine"]))
    if full:
        total = len(json.loads(page_file.read_text().split("const KERNELS=")[1].split(";const EVIDENCE")[0])["variants"])
        ok = ok and "0 law failures" in item["safe_kernel"] and item["bench"] == f"Caught {total} of {total}" and item["bench_missed"] == 0
    return ok

with sync_playwright() as p:
    browser = p.chromium.launch()
    ok = [run(browser, True, "light", 1280, True), run(browser, True, "dark", 400, False), run(browser, False, "light", 1280, True)]
    browser.close()
print(json.dumps(report, indent=1))
sys.exit(0 if all(ok) else 1)

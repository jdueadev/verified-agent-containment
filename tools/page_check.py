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

def run(browser, native, scheme, width):
    context = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "fonts.g" not in m.text and "ERR_" not in m.text else None)
    if not native:
        page.add_init_script("WebAssembly.instantiate=()=>Promise.reject(new Error('blocked'))")
    page.goto(tmp.as_uri())
    page.wait_for_function("document.getElementById('engine').textContent.includes('kernel') && !document.getElementById('engine').textContent.includes('Loading')")
    engine = page.inner_text("#engine")
    page.select_option("#scenario", "classifier")
    page.click("#runScenario")
    page.wait_for_selector(".state.freeze.active", timeout=4000)
    page.wait_for_timeout(300)
    classifier_kill = page.locator(".state.kill.active").count()
    page.select_option("#scenario", "recovery")
    page.click("#runScenario")
    page.wait_for_selector(".state.freeze.active", timeout=4000)
    page.wait_for_selector(".state.run.active", timeout=5000)
    log = page.inner_text("#log")
    page.click("#fuzz")
    page.wait_for_function("document.getElementById('fuzz').textContent.startsWith('Tested')", timeout=30000)
    laws = page.locator("#laws code").all_inner_texts()
    page.keyboard.press("Tab")
    focus = page.evaluate("document.activeElement && document.activeElement.tagName")
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shots / f"{'native' if native else 'fallback'}-{scheme}-{width}.png"), full_page=True)
    context.close()
    item = {"native": native, "scheme": scheme, "width": width, "engine": engine, "classifier_kill": classifier_kill, "signed_reset_seen": "Signed reset" in log and "Forged reset" in log, "laws": laws, "focus": focus, "overflow": overflow, "errors": errors}
    report.append(item)
    return classifier_kill == 0 and item["signed_reset_seen"] and len(laws) == 6 and all(x == "0 failures" for x in laws) and focus and overflow <= 0 and not errors and ("WebAssembly kernel" in engine if native else "JavaScript build" in engine)

with sync_playwright() as p:
    browser = p.chromium.launch()
    ok = [run(browser, True, "light", 1280), run(browser, True, "dark", 400), run(browser, False, "light", 1280)]
    browser.close()
print(json.dumps(report, indent=1))
sys.exit(0 if all(ok) else 1)

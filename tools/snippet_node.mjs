#!/usr/bin/env node
// Node driver for tools/snippet_run.mjs, called by tools/cookbook_check.py. Trusted base (lane C).
//
// Reads one JSON request on stdin:
//   {"kernels": [{"name": str, "kind": "bend" | "wasm", "path": str}], "snippets": [{"id": str, "text": str}]}
// and prints {"results": {id: {kernel name: runSnippet result}}}. Each snippet's text is
// parsed here with JSON.parse, so the page and this driver read it the same way, and each
// wasm run gets a fresh instance.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { runSnippet, bendAdapter, wasmAdapter } from "./snippet_run.mjs";

const request = JSON.parse(readFileSync(0, "utf8"));
const loaded = [];
for (const k of request.kernels) {
  if (k.kind === "bend") loaded.push({ name: k.name, bend: (await import(pathToFileURL(k.path).href)).default });
  else if (k.kind === "wasm") loaded.push({ name: k.name, wasm: new WebAssembly.Module(readFileSync(k.path)) });
  else throw new Error(`unknown kernel kind ${k.kind}`);
}
const results = {};
for (const { id, text } of request.snippets) {
  let snippet;
  try {
    snippet = JSON.parse(text);
  } catch (err) {
    results[id] = Object.fromEntries(loaded.map((k) => [k.name, { status: "error", error: `not JSON: ${err.message}`, steps: [] }]));
    continue;
  }
  results[id] = {};
  for (const k of loaded) {
    let result;
    try {
      const adapter = k.bend ? bendAdapter(k.bend) : wasmAdapter(new WebAssembly.Instance(k.wasm).exports);
      result = runSnippet(adapter, snippet);
    } catch (err) {
      result = { status: "error", error: String(err && err.message ? err.message : err), steps: [] };
    }
    results[id][k.name] = result;
  }
}
process.stdout.write(JSON.stringify({ results }));

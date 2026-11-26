#!/usr/bin/env node
// Driver for the parts of this repository that run without root.
//
//   node driver.mjs sim [--page FILE] [--out DIR] [--file-url] [STEP ...]
//       Opens the browser simulator (the WebAssembly decision kernel) in headless
//       Chromium over CDP and runs STEPs. With no steps it runs a default flow.
//         click=CSS     click the first element matching CSS
//         text=CSS      print the element's innerText
//         expect=CSS=T  fail (exit 1) unless the element's innerText starts with T
//         eval=JS       evaluate JS in the page and print the result
//         wait=MS       sleep
//         ss=NAME       screenshot to DIR/NAME.png (full page)
//
//   node driver.mjs servers [--lab BIN] [--out DIR]
//       Starts `containment-lab mock-model` and `fixture-server` on free ports,
//       sends each a request, prints replies and request logs, and stops them.
//
// No dependencies: Node 22+ (built-in WebSocket and fetch) and a Chromium binary.
// It never needs root and writes only under --out (default: target/vac-driver, which git ignores).
// It deliberately does not wrap attack-suite, live, live-suite or redteam: those
// need root and a disposable Linux or WSL2 machine (AGENTS.md).
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const argv = process.argv.slice(2);
const command = argv.shift();
const flag = (name, fallback) => {
  const i = argv.indexOf(name);
  return i < 0 ? fallback : argv.splice(i, 2)[1];
};
const out = resolve(flag("--out", join(root, "target/vac-driver")));
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChromium() {
  if (process.env.CHROMIUM) return process.env.CHROMIUM;
  const cache = join(homedir(), ".cache/ms-playwright");
  const dirs = existsSync(cache) ? readdirSync(cache).sort().reverse() : [];
  for (const d of dirs) {
    for (const rel of ["chrome-linux/headless_shell", "chrome-headless-shell-linux64/chrome-headless-shell", "chrome-linux/chrome", "chrome-linux64/chrome"]) {
      if (existsSync(join(cache, d, rel))) return join(cache, d, rel);
    }
  }
  throw new Error("no Chromium found: set CHROMIUM=/path/to/chrome");
}

async function browser() {
  const child = spawn(findChromium(), ["--headless", "--no-sandbox", "--disable-gpu", "--remote-debugging-port=0",
    `--user-data-dir=${join(out, "chromium-profile")}`, "--window-size=1400,1000", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
  const url = await new Promise((ok, fail) => {
    let seen = "";
    child.stderr.on("data", (chunk) => {
      seen += chunk;
      const m = seen.match(/DevTools listening on (ws:\S+)/);
      if (m) ok(m[1]);
    });
    child.on("error", (error) => fail(new Error(`cannot start Chromium: ${error.message}`)));
    child.on("exit", (code) => fail(new Error(`chromium exited ${code}\n${seen}`)));
    setTimeout(() => fail(new Error(`chromium gave no DevTools URL in 15 s\n${seen}`)), 15000);
  });
  const ws = new WebSocket(url);
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = () => fail(new Error("CDP socket failed")); });
  let id = 0;
  const pending = new Map(), events = [];
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id && pending.has(message.id)) {
      const [ok, fail] = pending.get(message.id);
      pending.delete(message.id);
      message.error ? fail(new Error(message.error.message)) : ok(message.result);
    } else if (message.method) events.push(message);
  };
  const send = (method, params = {}, sessionId) => new Promise((ok, fail) => {
    pending.set(++id, [ok, fail]);
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
  const close = async () => { try { await send("Browser.close"); } catch {} child.kill(); };
  return { send, events, close };
}

async function sim() {
  const page = resolve(flag("--page", join(root, "web/dist/agent-containment-simulator.html")));
  // The default flow asserts what it reads; your own steps can too, with expect=.
  const steps = argv.length ? argv : [
    "expect=[aria-current=step]=Run", "ss=1-start",
    'click=[data-signal="2"][data-level="3"]', "expect=[aria-current=step]=Hold",
    'click=[data-signal="3"][data-level="3"]', "wait=500", "expect=[aria-current=step]=Kill", "text=#log", "ss=2-after-kill",
    "click=#runAll", "wait=3000", "expect=#runAll=Caught 10 of 10", "ss=3-sabotaged-kernels",
  ];
  // The page declares no charset, and headless Chromium reads a file:// page
  // without one as Latin-1 (arrows and middle dots turn into mojibake). Serve it
  // over loopback HTTP as UTF-8 instead. --file-url loads it the raw way.
  const raw = argv.includes("--file-url") && argv.splice(argv.indexOf("--file-url"), 1);
  const http = raw ? null : createServer((_, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(readFileSync(page));
  });
  if (http) await new Promise((ok) => http.listen(0, "127.0.0.1", ok));
  const url = http ? `http://127.0.0.1:${http.address().port}/` : pathToFileURL(page).href;
  const b = await browser();
  try {
    const { targetId } = await b.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await b.send("Target.attachToTarget", { targetId, flatten: true });
    const cdp = (method, params) => b.send(method, params, sessionId);
    await cdp("Page.enable");
    await cdp("Runtime.enable");
    await cdp("Page.navigate", { url });
    const run = async (expression) => {
      const r = await cdp("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
      return r.result.value;
    };
    for (let i = 0; i < 100 && (await run("document.readyState")) !== "complete"; i++) await sleep(100);
    await sleep(500);
    for (const step of steps) {
      const [verb, arg] = [step.slice(0, step.indexOf("=")), step.slice(step.indexOf("=") + 1)];
      const sel = JSON.stringify(arg);
      if (verb === "click") {
        await run(`(() => { const e = document.querySelector(${sel}); if (!e) throw new Error("no element: " + ${sel}); e.scrollIntoView(); e.click(); })()`);
        await sleep(250);
        console.log(`click ${arg}`);
      } else if (verb === "text") {
        console.log(`--- ${arg}\n${await run(`(() => { const e = document.querySelector(${sel}); if (!e) throw new Error("no element: " + ${sel}); return e.innerText; })()`)}`);
      } else if (verb === "expect") {
        // expect=CSS=TEXT: the element's innerText must start with TEXT.
        const cut = arg.lastIndexOf("="), css = JSON.stringify(arg.slice(0, cut)), want = arg.slice(cut + 1);
        const got = await run(`(() => { const e = document.querySelector(${css}); if (!e) throw new Error("no element: " + ${css}); return e.innerText; })()`);
        const ok = got.trim().startsWith(want);
        console.log(`${ok ? "ok  " : "FAIL"} ${arg.slice(0, cut)} is ${JSON.stringify(got.trim().split("\n")[0])}, expected ${JSON.stringify(want)}`);
        if (!ok) process.exitCode = 1;
      } else if (verb === "eval") {
        console.log(JSON.stringify(await run(arg)));
      } else if (verb === "wait") {
        await sleep(Number(arg));
      } else if (verb === "ss") {
        const { data } = await cdp("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
        const file = join(out, `${arg}.png`);
        writeFileSync(file, Buffer.from(data, "base64"));
        console.log(`screenshot ${file}`);
      } else throw new Error(`unknown step: ${step}`);
    }
    const errors = b.events.filter((e) => e.method === "Runtime.exceptionThrown");
    for (const e of errors) console.error("PAGE ERROR:", e.params.exceptionDetails.exception?.description ?? e.params.exceptionDetails.text);
    if (errors.length) process.exitCode = 1;
  } finally {
    await b.close();
    http?.close();
  }
}

// Starts a `containment-lab` test server on a free port; it prints the port on stdout.
function server(lab, kind, arg, log) {
  const child = spawn(lab, [kind, "0", arg, log], { stdio: ["ignore", "pipe", "inherit"] });
  return new Promise((ok, fail) => {
    child.stdout.once("data", (chunk) => ok({ child, port: Number(String(chunk).trim()) }));
    child.on("exit", (code) => fail(new Error(`${kind} exited ${code}`)));
  });
}

async function servers() {
  const lab = resolve(flag("--lab", join(root, "target/debug/containment-lab")));
  if (!existsSync(lab)) throw new Error(`${lab} missing: run \`cargo build -q --locked -p containment-host\``);
  // Own fixtures, not examples/ or redteam/: those carry prompt injections.
  const site = join(out, "site");
  mkdirSync(site, { recursive: true });
  writeFileSync(join(site, "index.html"), "<h1>driver fixture</h1>\n");
  const script = join(out, "script.json");
  writeFileSync(script, JSON.stringify([
    { content: "", tool_calls: [{ name: "read_file", arguments: { path: "notes.txt" } }] },
    { content: "done" },
  ]));
  const logs = { model: join(out, "mock-model.jsonl"), fixture: join(out, "fixture-server.jsonl") };
  for (const file of Object.values(logs)) writeFileSync(file, "");
  const model = await server(lab, "mock-model", script, logs.model);
  const fixture = await server(lab, "fixture-server", site, logs.fixture);
  try {
    console.log(`mock-model on 127.0.0.1:${model.port}, fixture-server on 127.0.0.1:${fixture.port}`);
    const chat = () => fetch(`http://127.0.0.1:${model.port}/v1/chat/completions`, { method: "POST",
      body: JSON.stringify({ model: "driver", messages: [{ role: "user", content: "hi" }] }) }).then((r) => r.json());
    const first = await chat(), second = await chat();
    console.log("model reply 1:", JSON.stringify(first.choices[0]));
    console.log("model reply 2:", JSON.stringify(second.choices[0]));
    const base = `http://127.0.0.1:${fixture.port}`;
    console.log("GET /      ->", (await (await fetch(base + "/")).text()).trim());
    console.log("GET /echo  ->", await (await fetch(base + "/echo", { headers: { authorization: "Bearer driver-dummy" } })).text());
    console.log("POST /sink ->", await (await fetch(base + "/sink", { method: "POST", body: "payload" })).text());
    console.log("GET /../x  ->", (await fetch(base + "/..%2Fx")).status);
    await sleep(100);
    for (const [name, file] of Object.entries(logs)) {
      const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      console.log(`${name} log (${file}): ${lines.length} requests`);
      for (const l of lines) console.log("  ", JSON.stringify({ ...l, body: String(l.body).slice(0, 60) }));
    }
    const ok = first.choices[0].finish_reason === "tool_calls" && second.choices[0].finish_reason === "stop";
    console.log(ok ? "servers: OK" : "servers: UNEXPECTED REPLIES");
    if (!ok) process.exitCode = 1;
  } finally {
    model.child.kill();
    fixture.child.kill();
  }
}

const commands = { sim, servers };
if (!commands[command]) {
  console.error(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 19).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
  process.exit(2);
}
commands[command]().catch((error) => { console.error(`driver: ${error.message}`); process.exit(1); });

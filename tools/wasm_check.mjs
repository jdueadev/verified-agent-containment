#!/usr/bin/env node
// Replays Rust kernel traces through the WebAssembly build shown in the browser.
import { readFileSync } from "node:fs";
import { fields, groups } from "./fingerprints.mjs";
const [wasmFile, casesFile, firstCases] = process.argv.slice(2);
const { instance } = await WebAssembly.instantiate(readFileSync(wasmFile));
const w = instance.exports;
const modes = ["run", "restrict", "hold", "freeze", "kill"];
const actions = ["revoke_secrets", "narrow_egress", "block_egress", "freeze_processes", "kill_processes", "thaw_processes", "recreate_sandbox", "restore_authority"];
const level = { restrict: 0, hold: 1, freeze: 2, kill: 3 };
const apply = (e) => {
  if (e.type === "tick") return w.apply_event(0, e.now, 0, 0);
  if (e.type === "renew") return w.apply_event(1, e.now, e.ttl, 0);
  if (e.type === "classifier") return w.apply_event(2, e.now, 0, level[e.level]);
  if (e.type === "hard") return w.apply_event(3, e.now, 0, level[e.level]);
  if (e.type === "agent") return w.apply_event(4, e.now, 0, 0);
  return w.apply_reset(e.signed ? 1 : 0, e.now, e.counter, modes.indexOf(e.from), e.not_after, e.ttl);
};
let transitions = 0;
const found = groups(firstCases);
for (const line of readFileSync(casesFile, "utf8").trim().split("\n")) {
  const item = JSON.parse(line);
  found.case(line);
  w.set_config(item.config.max, item.config.grace);
  w.set_control(modes.indexOf(item.initial.mode), item.initial.deadline, item.initial.clock, item.initial.counter);
  for (const step of item.steps) {
    transitions += 1;
    const fromMode = modes[w.current_mode()];
    const mode = modes[apply(step.event)];
    const plan = Array.from({ length: w.action_count() }, (_, i) => actions[w.action_at(i)]);
    const a = step.access;
    const allowed = w.access_allowed(step.event.now, a.kind === "egress" ? 0 : 1, a.granted ? 1 : 0, a.baseline ? 1 : 0) === 1;
    const want = { mode: step.mode, deadline: step.deadline, clock: step.clock, counter: step.counter, actions: step.actions, allowed: a.allowed };
    const got = { mode, deadline: w.current_deadline(), clock: w.current_clock(), counter: w.current_counter(), actions: plan, allowed };
    const differing = fields(want, got);
    if (differing.length) found.add(step.event, fromMode, differing, { event: step.event, rust: want, wasm: got });
  }
}
found.finish({ transitions });

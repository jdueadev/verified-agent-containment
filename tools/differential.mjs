#!/usr/bin/env bun
// Replays Rust kernel traces through the Bend kernel compiled to JavaScript.
import { readFileSync } from "node:fs";
const [moduleFile, casesFile] = process.argv.slice(2);
if (!moduleFile || !casesFile) throw new Error("usage: differential.mjs KERNEL_MJS CASES_JSONL");
const exports_ = (await import(new URL(moduleFile, `file://${process.cwd()}/`).href)).default;
const pick = (name) => exports_[name] ?? exports_[`kernel:${name}`];
const step = pick("step");
const authorize = pick("authorize");
const tag = ($, fields = {}) => ({ $, ...fields });
const modes = { run: "ModeRun", restrict: "ModeRestrict", freeze: "ModeFreeze", kill: "ModeKill" };
const modeNames = Object.fromEntries(Object.entries(modes).map(([k, v]) => [v, k]));
const levels = { restrict: "ToRestrict", freeze: "ToFreeze", kill: "ToKill" };
const actions = {
  RevokeSecrets: "revoke_secrets", NarrowEgress: "narrow_egress", BlockEgress: "block_egress",
  FreezeProcesses: "freeze_processes", KillProcesses: "kill_processes", ThawProcesses: "thaw_processes",
  RecreateSandbox: "recreate_sandbox", RestoreAuthority: "restore_authority",
};
const BOOL = (value) => value;
const unbool = (value) => value === true;
const event = (e) => {
  if (e.type === "tick") return tag("ClockTick", { now: e.now });
  if (e.type === "renew") return tag("Renew", { now: e.now, ttl: e.ttl });
  if (e.type === "classifier") return tag("Classifier", { now: e.now, level: tag(levels[e.level]) });
  if (e.type === "hard") return tag("HardRule", { now: e.now, level: tag(levels[e.level]) });
  if (e.type === "agent") return tag("AgentRequest", { now: e.now });
  return tag("Reset", { now: e.now, signed: BOOL(e.signed), ttl: e.ttl });
};
const plan = (value) => {
  const out = [];
  for (let p = value; p.$ === "Next"; p = p.tail) out.push(actions[p.head.$]);
  return out;
};
let sequences = 0, transitions = 0;
for (const line of readFileSync(casesFile, "utf8").trim().split("\n")) {
  const item = JSON.parse(line);
  sequences += 1;
  const config = tag("KernelConfig", { max_lease: item.config.max, freeze_grace: item.config.grace });
  let control = tag("ControlState", { mode: tag(modes[item.initial.mode]), deadline: item.initial.deadline });
  for (const expected of item.steps) {
    transitions += 1;
    const result = step(config, control, event(expected.event));
    control = result.control;
    const gotMode = modeNames[control.mode.$], gotPlan = plan(result.actions);
    const a = expected.access;
    const request = tag("AccessRequest", { kind: tag(a.kind === "egress" ? "EgressAccess" : "SecretAccess"), granted: BOOL(a.granted), baseline: BOOL(a.baseline) });
    const allowed = unbool(authorize(expected.event.now, control, request));
    if (gotMode !== expected.mode || control.deadline !== expected.deadline || JSON.stringify(gotPlan) !== JSON.stringify(expected.actions) || allowed !== a.allowed) {
      console.error(JSON.stringify({ mismatch: true, event: expected.event, rust: expected, bend: { mode: gotMode, deadline: control.deadline, actions: gotPlan, allowed } }));
      process.exit(1);
    }
  }
}
console.log(JSON.stringify({ sequences, transitions, mismatches: 0 }));

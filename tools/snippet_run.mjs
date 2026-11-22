// Runs cookbook snippets (docs/cookbook/snippets/*.json) on a kernel. Trusted base (lane C).
//
// This is the only snippet interpreter. tools/cookbook_check.py runs it under node, and
// the simulator page inlines this exact text (see page_blocks in cookbook_check.py), so
// the page and scripts/check.sh cannot disagree about what a snippet means. To keep it
// inlinable it has no imports, no I/O and no eval, and its last line is the only export.
//
// Snippets are documentation tests written in docs/** (lane A). Treat them as untrusted
// data: validate() rejects unknown keys and values, and names reach the kernels only
// through the fixed tables below, never as property lookups chosen by the snippet.

const MODES = ["run", "restrict", "hold", "freeze", "kill"];
const LEVELS = ["restrict", "hold", "freeze", "kill"];
const ACTIONS = ["revoke_secrets", "narrow_egress", "block_egress", "freeze_processes",
  "kill_processes", "thaw_processes", "recreate_sandbox", "restore_authority"];
const ACCESS = ["egress", "secret"];
// Event vocabulary of tools/differential.mjs and tools/wasm_check.mjs.
const EVENTS = {
  tick: ["now"], renew: ["now", "ttl"], classifier: ["now", "level"], hard: ["now", "level"],
  agent: ["now"], reset: ["now", "signed", "counter", "from", "not_after", "ttl"],
};
const EXPECT = ["mode", "deadline", "clock", "counter", "actions"];
// The Bend kernel compiled to JS rejects a Nat past 2^48 - 1. Kernels add two inputs (a
// time plus a lease or a grace period), so each input stays below 2^47.
const MAX_INT = 140737488355327;
const MAX_STEPS = 64;
const MAX_ACCESS = 8;
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v) => Number.isSafeInteger(v) && v >= 0 && v <= MAX_INT;

function keys(errors, where, obj, required, optional) {
  if (!isObj(obj)) { errors.push(`${where}: expected an object`); return false; }
  for (const k of Object.keys(obj)) {
    if (!required.includes(k) && !optional.includes(k)) errors.push(`${where}: unknown key "${k}"`);
  }
  for (const k of required) if (!has(obj, k)) errors.push(`${where}: missing "${k}"`);
  return true;
}

function field(errors, where, value, kind) {
  const ok = kind === "int" ? isInt(value)
    : kind === "bool" ? typeof value === "boolean"
    : kind === "text" ? typeof value === "string"
    : Array.isArray(kind) ? kind.includes(value) : false;
  if (!ok) {
    const want = kind === "int" ? `an integer from 0 to ${MAX_INT}` : kind === "bool" ? "true or false"
      : kind === "text" ? "a string" : `one of ${kind.join(", ")}`;
    errors.push(`${where}: expected ${want}, got ${JSON.stringify(value)}`);
  }
}

const EVENT_FIELDS = { now: "int", ttl: "int", counter: "int", not_after: "int", signed: "bool", level: LEVELS, from: MODES };

// Every problem with a snippet, as messages. An empty list means it is well formed.
function validate(s) {
  const errors = [];
  if (!keys(errors, "snippet", s, ["id", "claim", "recipe", "title", "breaks", "teeth", "config", "start", "steps"], ["note"])) return errors;
  for (const k of ["id", "claim", "recipe", "title", "breaks"]) if (has(s, k)) field(errors, k, s[k], "text");
  if (has(s, "note")) field(errors, "note", s.note, "text");
  if (typeof s.id === "string" && !/^[a-z0-9][a-z0-9-]*$/.test(s.id)) errors.push(`id: "${s.id}" must match [a-z0-9][a-z0-9-]*`);
  if (typeof s.recipe === "string" && !/^[a-z0-9][a-z0-9-]*$/.test(s.recipe)) errors.push(`recipe: "${s.recipe}" must match [a-z0-9][a-z0-9-]*`);
  if (typeof s.breaks === "string" && !/^mutant:[a-z0-9_]+$/.test(s.breaks)) errors.push(`breaks: "${s.breaks}" must be a Bend mutant reference, mutant:NAME`);
  if (keys(errors, "config", s.config, ["max_lease", "freeze_grace"], [])) {
    for (const k of ["max_lease", "freeze_grace"]) if (has(s.config, k)) field(errors, `config.${k}`, s.config[k], "int");
  }
  if (keys(errors, "start", s.start, ["mode", "deadline", "clock", "counter"], [])) {
    if (has(s.start, "mode")) field(errors, "start.mode", s.start.mode, MODES);
    for (const k of ["deadline", "clock", "counter"]) if (has(s.start, k)) field(errors, `start.${k}`, s.start[k], "int");
  }
  const steps = s.steps;
  if (!Array.isArray(steps) || steps.length === 0 || steps.length > MAX_STEPS) {
    errors.push(`steps: expected a list of 1 to ${MAX_STEPS} steps`);
    return errors;
  }
  steps.forEach((step, i) => {
    const at = `step ${i + 1}`;
    if (!keys(errors, at, step, ["event"], ["note", "expect", "access"])) return;
    if (has(step, "note")) field(errors, `${at}.note`, step.note, "text");
    const e = step.event;
    if (isObj(e) && typeof e.type === "string" && has(EVENTS, e.type)) {
      const names = EVENTS[e.type];
      if (keys(errors, `${at}.event`, e, ["type", ...names], [])) {
        for (const k of names) if (has(e, k)) field(errors, `${at}.event.${k}`, e[k], EVENT_FIELDS[k]);
      }
    } else {
      errors.push(`${at}.event: "type" must be one of ${Object.keys(EVENTS).join(", ")}`);
    }
    let count = 0;
    if (has(step, "expect")) {
      if (keys(errors, `${at}.expect`, step.expect, [], EXPECT)) {
        for (const k of Object.keys(step.expect)) {
          if (!EXPECT.includes(k)) continue;
          count += 1;
          const v = step.expect[k];
          if (k === "mode") field(errors, `${at}.expect.mode`, v, MODES);
          else if (k === "actions") {
            if (!Array.isArray(v) || v.length > ACTIONS.length) errors.push(`${at}.expect.actions: expected a list of actions`);
            else v.forEach((a, j) => field(errors, `${at}.expect.actions[${j}]`, a, ACTIONS));
          } else field(errors, `${at}.expect.${k}`, v, "int");
        }
      }
    }
    if (has(step, "access")) {
      if (!Array.isArray(step.access) || step.access.length > MAX_ACCESS) {
        errors.push(`${at}.access: expected a list of at most ${MAX_ACCESS} checks`);
      } else {
        step.access.forEach((a, j) => {
          const w = `${at}.access[${j}]`;
          if (!keys(errors, w, a, ["kind", "granted", "baseline", "allowed"], [])) return;
          count += 1;
          field(errors, `${w}.kind`, a.kind, ACCESS);
          for (const k of ["granted", "baseline", "allowed"]) field(errors, `${w}.${k}`, a[k], "bool");
        });
      }
    }
    if (count === 0) errors.push(`${at}: asserts nothing; give it an expect field or an access check`);
  });
  if (keys(errors, "teeth", s.teeth, ["step", "field"], [])) {
    const t = s.teeth;
    if (!Number.isSafeInteger(t.step) || t.step < 1 || t.step > steps.length) {
      errors.push(`teeth.step: expected a step number from 1 to ${steps.length}`);
    } else if (typeof t.field !== "string") {
      errors.push("teeth.field: expected a string");
    } else {
      const step = steps[t.step - 1];
      const m = /^access\.(\d+)$/.exec(t.field);
      const asserted = m ? Array.isArray(step?.access) && Number(m[1]) < step.access.length
        : EXPECT.includes(t.field) && isObj(step?.expect) && has(step.expect, t.field);
      if (!asserted) errors.push(`teeth: step ${t.step} does not assert "${t.field}"`);
    }
  }
  return errors;
}

// Adapter over the Bend kernel compiled to JS (`bend kernel.bend -o kernel.mjs`), with the
// calling convention of tools/differential.mjs.
function bendAdapter(mod) {
  const pick = (name) => {
    const f = has(mod, name) ? mod[name] : has(mod, `kernel:${name}`) ? mod[`kernel:${name}`] : null;
    if (typeof f !== "function") throw new Error(`the Bend module has no ${name} function`);
    return f;
  };
  const step = pick("step"), authorize = pick("authorize");
  const tag = ($, fields = {}) => ({ $, ...fields });
  const modeTag = { run: "ModeRun", restrict: "ModeRestrict", hold: "ModeHold", freeze: "ModeFreeze", kill: "ModeKill" };
  const levelTag = { restrict: "ToRestrict", hold: "ToHold", freeze: "ToFreeze", kill: "ToKill" };
  const actionName = { RevokeSecrets: "revoke_secrets", NarrowEgress: "narrow_egress", BlockEgress: "block_egress",
    FreezeProcesses: "freeze_processes", KillProcesses: "kill_processes", ThawProcesses: "thaw_processes",
    RecreateSandbox: "recreate_sandbox", RestoreAuthority: "restore_authority" };
  const modeName = { ModeRun: "run", ModeRestrict: "restrict", ModeHold: "hold", ModeFreeze: "freeze", ModeKill: "kill" };
  const named = (table, key, what) => {
    if (typeof key !== "string" || !has(table, key)) throw new Error(`the Bend kernel returned an unknown ${what}`);
    return table[key];
  };
  let config, control;
  const event = (e) => {
    if (e.type === "tick") return tag("ClockTick", { now: e.now });
    if (e.type === "renew") return tag("Renew", { now: e.now, ttl: e.ttl });
    if (e.type === "classifier") return tag("Classifier", { now: e.now, level: tag(levelTag[e.level]) });
    if (e.type === "hard") return tag("HardRule", { now: e.now, level: tag(levelTag[e.level]) });
    if (e.type === "agent") return tag("AgentRequest", { now: e.now });
    return tag("Reset", { now: e.now, signed: e.signed, counter: e.counter, from_mode: tag(modeTag[e.from]), not_after: e.not_after, ttl: e.ttl });
  };
  return {
    init(c, s) {
      config = tag("KernelConfig", { max_lease: c.max_lease, freeze_grace: c.freeze_grace });
      control = tag("ControlState", { mode: tag(modeTag[s.mode]), deadline: s.deadline, clock: s.clock, reset_counter: s.counter });
    },
    step(e) {
      const result = step(config, control, event(e));
      control = result.control;
      const actions = [];
      for (let p = result.actions, n = 0; p.$ === "Next"; p = p.tail, n += 1) {
        if (n >= ACTIONS.length * 4) throw new Error("the Bend kernel returned an unbounded action plan");
        actions.push(named(actionName, p.head.$, "action"));
      }
      return { mode: named(modeName, control.mode.$, "mode"), deadline: control.deadline, clock: control.clock, counter: control.reset_counter, actions };
    },
    authorize(now, a) {
      const request = tag("AccessRequest", { kind: tag(a.kind === "egress" ? "EgressAccess" : "SecretAccess"), granted: a.granted, baseline: a.baseline });
      return authorize(now, control, request) === true;
    },
  };
}

// Adapter over the exports of crates/containment-wasm. The module keeps one global
// machine, so give each run a fresh instance, or another user of it (the page's live
// simulator) and this run would overwrite each other.
function wasmAdapter(w) {
  const level = { restrict: 0, hold: 1, freeze: 2, kill: 3 };
  const kind = { tick: 0, renew: 1, classifier: 2, hard: 3, agent: 4 };
  const mode = (code) => {
    if (!Number.isInteger(code) || code < 0 || code >= MODES.length) throw new Error(`the wasm kernel returned mode ${code}`);
    return MODES[code];
  };
  return {
    init(c, s) {
      w.set_config(c.max_lease, c.freeze_grace);
      w.set_control(MODES.indexOf(s.mode), s.deadline, s.clock, s.counter);
    },
    step(e) {
      const code = e.type === "reset"
        ? w.apply_reset(e.signed ? 1 : 0, e.now, e.counter, MODES.indexOf(e.from), e.not_after, e.ttl)
        : w.apply_event(kind[e.type], e.now, e.ttl ?? 0, e.level === undefined ? 0 : level[e.level]);
      const actions = [];
      const n = w.action_count();
      for (let i = 0; i < n; i += 1) {
        const a = w.action_at(i);
        if (!Number.isInteger(a) || a < 0 || a >= ACTIONS.length) throw new Error(`the wasm kernel returned action ${a}`);
        actions.push(ACTIONS[a]);
      }
      return { mode: mode(code), deadline: w.current_deadline(), clock: w.current_clock(), counter: w.current_counter(), actions };
    },
    authorize(now, a) {
      return w.access_allowed(now, a.kind === "egress" ? 0 : 1, a.granted ? 1 : 0, a.baseline ? 1 : 0) === 1;
    },
  };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Run one snippet. status is "pass" (every expectation held), "fail" (the run finished and
// at least one expectation did not hold) or "error" (the snippet is malformed or the kernel
// threw). Only "fail" can show that a mutant breaks a snippet: an error shows nothing.
function runSnippet(adapter, snippet) {
  const problems = validate(snippet);
  if (problems.length) return { status: "error", error: problems.join("; "), steps: [] };
  const steps = [];
  try {
    adapter.init(snippet.config, snippet.start);
    for (const step of snippet.steps) {
      const got = adapter.step(step.event);
      const observed = { mode: got.mode, deadline: got.deadline, clock: got.clock, counter: got.counter, actions: got.actions, access: [] };
      const failures = [];
      for (const k of EXPECT) {
        if (isObj(step.expect) && has(step.expect, k) && !same(step.expect[k], observed[k])) {
          failures.push({ field: k, expected: step.expect[k], observed: observed[k] });
        }
      }
      (step.access || []).forEach((a, j) => {
        const allowed = adapter.authorize(step.event.now, a);
        observed.access.push(allowed);
        if (allowed !== a.allowed) failures.push({ field: `access.${j}`, expected: a.allowed, observed: allowed });
      });
      steps.push({ observed, failures });
    }
  } catch (err) {
    return { status: "error", error: String(err && err.message ? err.message : err), steps };
  }
  return { status: steps.some((s) => s.failures.length) ? "fail" : "pass", steps };
}

export { validate, runSnippet, bendAdapter, wasmAdapter };

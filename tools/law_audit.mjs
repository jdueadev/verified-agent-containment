#!/usr/bin/env bun
// Evaluates every law in formal/LAWS.bend on random inputs against a compiled Bend kernel.
// The mutation check uses it to show that a rejected mutant really violates a law.
const [moduleFile, count = "40000", seed = "24301"] = process.argv.slice(2);
const mod = (await import(new URL(moduleFile, `file://${process.cwd()}/`).href)).default;
const K = (name) => mod[name] ?? mod[`kernel:${name}`];
const step = K("step"), authorize = K("authorize"), resetOk = K("reset_ok"), accepted = K("is_accepted_reset"), eff = K("effective_time");
let s = Number(seed) | 0;
const rnd = () => { s = s + 0x6d2b79f5 | 0; let t = Math.imul(s ^ s >>> 15, 1 | s); t ^= t + Math.imul(t ^ t >>> 7, 61 | t); return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const int = (n) => Math.floor(rnd() * n), flag = () => rnd() < 0.5;
const MODES = ["ModeRun", "ModeRestrict", "ModeHold", "ModeFreeze", "ModeKill"], LEVELS = ["ToRestrict", "ToHold", "ToFreeze", "ToKill"];
const ACTIONS = ["RevokeSecrets", "NarrowEgress", "BlockEgress", "FreezeProcesses", "KillProcesses", "ThawProcesses", "RecreateSandbox", "RestoreAuthority"];
const RECOVERY = [[], [7], [5, 7], [5, 7], [6, 7]];
const tag = ($, f = {}) => ({ $, ...f }), mode = (i) => tag(MODES[i]), rank = (m) => MODES.indexOf(m.$);
const plan = (p) => { const out = []; for (; p.$ === "Next"; p = p.tail) out.push(ACTIONS.indexOf(p.head.$)); return out; };
const live = (r) => r < 2, num = (x) => Number(x);
const violated = {};
const fail = (law, detail) => { if (!violated[law]) violated[law] = { count: 0, example: detail }; violated[law].count++; };
function ordered(p, secrets, egress) {
  for (const a of p) { if (a === 0) secrets = true; if (a === 2) egress = true; if ((a === 3 || a === 4) && !(secrets && egress)) return false; }
  return true;
}
for (let i = 0; i < Number(count); i++) {
  const max = int(400), grace = int(400), cfg = tag("KernelConfig", { max_lease: max, freeze_grace: grace });
  const m = int(5), d = int(600), clock = int(600), counter = int(5);
  const c = tag("ControlState", { mode: mode(m), deadline: d, clock, reset_counter: counter });
  const pick = int(4), now = pick === 0 ? d : pick === 1 ? clock + int(3) : int(800);
  const kind = int(6), lvl = int(4), ttl = int(600);
  let e;
  if (kind === 0) e = tag("ClockTick", { now });
  else if (kind === 1) e = tag("Renew", { now, ttl });
  else if (kind === 2) e = tag("Classifier", { now, level: tag(LEVELS[lvl]) });
  else if (kind === 3) e = tag("HardRule", { now, level: tag(LEVELS[lvl]) });
  else if (kind === 4) e = tag("AgentRequest", { now });
  else {
    const good = flag(), at0 = Math.max(now, clock);
    e = tag("Reset", { now, signed: good || flag(), counter: good ? counter + 1 + int(2) : int(7), from_mode: good || flag() ? mode(m) : mode(int(5)), not_after: good ? at0 + int(50) : int(800), ttl });
  }
  const at = num(eff(now, clock)), acc = accepted(mode(m), counter, e, at) === true;
  const r = step(cfg, c, e), m2 = rank(r.control.mode), d2 = num(r.control.deadline), c2 = num(r.control.clock), n2 = num(r.control.reset_counter), p = plan(r.actions);
  const has = (a) => p.includes(a);
  const ex = { mode: MODES[m], deadline: d, clock, counter, event: e.$, now, level: LEVELS[lvl], after: { mode: MODES[m2], deadline: d2, clock: c2, counter: n2, plan: p.map((a) => ACTIONS[a]) } };
  const expired = !(at < d);
  if (expired && !acc && live(m2)) fail("fail_closed", ex);
  if (!acc && m2 < m) fail("tighten_only", ex);
  if (kind === 1 && live(m2) && d2 > at + max) fail("renewal_is_bounded", ex);
  if (c2 < clock) fail("clock_never_rewinds", ex);
  if (c2 !== at) fail("clock_is_effective_time", ex);
  if (now < clock && num(eff(now, clock)) !== clock) fail("stale_time_uses_clock", ex);
  if (kind === 2 && m !== 4 && !expired && m2 === 4) fail("classifier_cannot_kill", ex);
  if (kind === 2 && live(m) && lvl !== 0 && !expired && m2 !== 2) fail("classifier_stop_enters_hold", ex);
  const passive = kind !== 3 && !(kind === 5 && e.signed);
  if (m === 2 && passive && m2 !== 2) fail("hold_cannot_self_escalate", ex);
  if (!ordered(p, m !== 0, !live(m))) fail("authority_removed_first", ex);
  if (live(m) && !acc && !live(m2) && !(has(0) && has(2) && has(3))) fail("stop_plan_is_complete", ex);
  if (m !== 4 && !acc && m2 === 4 && !has(4)) fail("kill_plan_is_complete", ex);
  if (m === 3 && expired && !acc && m2 !== 4) fail("freeze_escalates", ex);
  if (m === 3 && !acc && m2 === 3 && d2 !== d) fail("freeze_deadline_is_fixed", ex);
  if (m < 3 && !acc && m2 === 3 && d2 !== at + grace) fail("freeze_entry_uses_grace", ex);
  if (kind !== 1 && !acc && live(m2) && d2 > d) fail("lease_only_renewal_extends", ex);
  if (m === 0 && !acc && m2 === 1 && !(has(0) && has(1))) fail("restrict_plan_is_complete", ex);
  if (!acc && (has(5) || has(6) || has(7))) fail("no_recovery_without_reset", ex);
  if (!acc && n2 !== counter) fail("counter_needs_accepted_reset", ex);
  if (kind === 3 && m2 < lvl + 1) fail("hard_rule_reaches_level", ex);
  if (m === 4 && !acc && m2 !== 4) fail("kill_needs_accepted_reset", ex);
  if (acc && n2 !== num(e.counter)) fail("accepted_reset_consumes_counter", ex);
  if (acc && d2 > at + max) fail("reset_is_bounded", ex);
  if (acc && JSON.stringify(p) !== JSON.stringify(RECOVERY[m])) fail("reset_plan_is_complete", ex);
  // Reset predicate laws, evaluated directly on reset_ok.
  const sg = flag(), rn = int(7), rf = int(5), rna = int(800), rat = int(800), ok = resetOk(mode(m), counter, sg, rn, mode(rf), rna, rat) === true;
  const rex = { mode: MODES[m], counter, signed: sg, n: rn, from: MODES[rf], not_after: rna, at: rat, ok };
  if (ok && !sg) fail("reset_requires_signature", rex);
  if (ok && !(counter < rn)) fail("reset_requires_fresh_counter", rex);
  if (ok && rf !== m) fail("reset_is_bound_to_mode", rex);
  if (ok && rat > rna) fail("reset_must_be_unexpired", rex);
  if (ok && m === 0) fail("reset_cannot_renew_run", rex);
  if (resetOk(mode(m), rn, sg, rn, mode(rf), rna, rat) === true) fail("reset_cannot_replay", rex);
  // Access laws, at a later time against the new state.
  const later = int(900), k = int(2), g = flag(), b = flag();
  const allowed = authorize(later, r.control, tag("AccessRequest", { kind: tag(k ? "SecretAccess" : "EgressAccess"), granted: g, baseline: b })) === true;
  const aex = { ...ex, access: { at: later, kind: k ? "secret" : "egress", granted: g, baseline: b, allowed } };
  if (allowed && !g) fail("access_requires_grant", aex);
  if (allowed && !(num(eff(later, c2)) < d2)) fail("expired_lease_denies", aex);
  if (allowed && !live(m2)) fail("stopped_denies", aex);
  if (allowed && m2 === 1 && k === 1) fail("restrict_denies_secrets", aex);
  if (allowed && m2 === 1 && k === 0 && !b) fail("restrict_egress_needs_baseline", aex);
}
console.log(JSON.stringify({ checked: Number(count), violated }));

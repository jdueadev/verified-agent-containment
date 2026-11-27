//! The JSON form of kernel steps that the Bend and wasm replayers read, and the
//! live run's kernel trace. The controller calls `kernel_line`, so this module
//! only reads events: `encode` names `Event`'s variants as match patterns, never
//! as values (tools/invariants_check.py, EVENT_PATTERNS). The random events live
//! in `differential`, which the controller may not reach.

use containment_kernel::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, BufRead, Write};

fn level_text(level: Level) -> &'static str {
    match level {
        Level::Restrict => "restrict",
        Level::Hold => "hold",
        Level::Freeze => "freeze",
        Level::Kill => "kill",
    }
}

fn mode_text(mode: Mode) -> &'static str {
    crate::common::mode_name(mode)
}

/// The one JSON form of a kernel event that the Bend and wasm replayers read.
pub fn encode(event: Event) -> Value {
    match event {
        Event::Tick { now_ms } => json!({"type":"tick","now":now_ms}),
        Event::Renew { now_ms, ttl_ms } => json!({"type":"renew","now":now_ms,"ttl":ttl_ms}),
        Event::Classifier { now_ms, level } => json!({"type":"classifier","now":now_ms,"level":level_text(level)}),
        Event::HardRule { now_ms, level } => json!({"type":"hard","now":now_ms,"level":level_text(level)}),
        Event::AgentRequest { now_ms } => json!({"type":"agent","now":now_ms}),
        Event::Reset { now_ms, signed, counter, from_mode, not_after_ms, ttl_ms } => {
            json!({"type":"reset","now":now_ms,"signed":signed,"counter":counter,"from":mode_text(from_mode),"not_after":not_after_ms,"ttl":ttl_ms})
        }
    }
}

pub fn control_json(control: Control) -> Value {
    json!({"mode": mode_text(control.mode), "deadline": control.deadline_ms, "clock": control.clock_ms, "counter": control.reset_counter})
}

/// One differential step: the event, the control after it, the plan, and one access decision.
pub fn step_json(event: Event, result: StepResult, access: (AccessKind, bool, bool)) -> Value {
    let (kind, granted, baseline) = access;
    let allowed = authorize(event.now_ms(), result.control, AccessRequest { kind, granted, baseline });
    let control = result.control;
    json!({
        "event": encode(event),
        "mode": mode_text(control.mode),
        "deadline": control.deadline_ms,
        "clock": control.clock_ms,
        "counter": control.reset_counter,
        "actions": result.actions.iter().map(crate::common::action_name).collect::<Vec<_>>(),
        "access": {"kind": if kind == AccessKind::Egress {"egress"} else {"secret"}, "granted": granted, "baseline": baseline, "allowed": allowed}
    })
}

/// One line of a live run's kernel trace: every step the controller commits, in
/// commit order, whether or not the mode changed. `kernel-cases` turns these
/// lines back into differential cases, so a shadowed live run replays through
/// the Bend and wasm kernels exactly like the random traces. The access field
/// is a fixed probe (granted egress, no baseline), asked of the kernel's
/// `authorize` at each step's state.
pub fn kernel_line(seq: u64, config: Config, before: Control, event: Event, result: StepResult) -> Value {
    let mut line = step_json(event, result, (AccessKind::Egress, true, false));
    line["seq"] = json!(seq);
    line["config"] = json!({"max": config.max_lease_ms, "grace": config.freeze_grace_ms});
    line["before"] = control_json(before);
    line
}

/// `kernel-cases FILE`: reads a kernel trace and prints differential cases.
/// A new case starts wherever the config changes or a step's `before` is not
/// the previous step's result, so a gap (a dropped line, a weakness that edits
/// control outside the kernel) never joins two runs into a false trace.
pub fn kernel_cases(args: &[String]) -> Result<(), Box<dyn Error>> {
    let path = args.first().ok_or_else(|| crate::common::UsageError("usage: containment-lab kernel-cases KERNEL_JSONL\n".to_owned()))?;
    let reader = io::BufReader::new(std::fs::File::open(path)?);
    let mut lines = BTreeMap::new();
    for line in reader.lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let seq = value["seq"].as_u64().ok_or("kernel line without seq")?;
        lines.insert(seq, value);
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for case in cases(lines.into_values()) {
        writeln!(out, "{case}")?;
    }
    Ok(())
}

pub(crate) fn cases(lines: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut cases: Vec<(Value, Value, Vec<Value>)> = Vec::new();
    let mut after: Option<(Value, Value)> = None;
    for line in lines {
        if line["truncated"] == json!(true) {
            eprintln!("kernel-cases: the trace was cut at seq {}; later steps were not logged", line["seq"]);
            break;
        }
        let Value::Object(mut obj) = line else {
            eprintln!("kernel-cases: skipped a kernel line that is not an object");
            continue;
        };
        let config = obj.remove("config").unwrap_or(Value::Null);
        let before = obj.remove("before").unwrap_or(Value::Null);
        obj.remove("seq");
        let joins = after.as_ref().is_some_and(|(c, a)| *c == config && *a == before);
        let field = |key: &str| obj.get(key).cloned().unwrap_or(Value::Null);
        let state = json!({"mode": field("mode"), "deadline": field("deadline"), "clock": field("clock"), "counter": field("counter")});
        match cases.last_mut() {
            Some((_, _, steps)) if joins => steps.push(Value::Object(obj)),
            _ => cases.push((config.clone(), before, vec![Value::Object(obj)])),
        }
        after = Some((config, state));
    }
    cases.into_iter().map(|(config, initial, steps)| json!({"config": config, "initial": initial, "steps": steps})).collect()
}

use containment_kernel::*;
use serde_json::{json, Value};
use std::error::Error;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn flag(&mut self) -> bool {
        self.below(2) == 1
    }
}

const MODES: [Mode; 5] = [Mode::Run, Mode::Restrict, Mode::Hold, Mode::Freeze, Mode::Kill];

fn level(rng: &mut Rng) -> Level {
    [Level::Restrict, Level::Hold, Level::Freeze, Level::Kill][rng.below(4) as usize]
}
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
fn event(rng: &mut Rng, now_ms: u64, control: Control) -> Event {
    let ttl_ms = rng.below(1_000);
    match rng.below(7) {
        0 => Event::Tick { now_ms },
        1 => Event::Renew { now_ms, ttl_ms },
        2 => Event::Classifier { now_ms, level: level(rng) },
        3 => Event::HardRule { now_ms, level: level(rng) },
        4 => Event::AgentRequest { now_ms },
        _ => {
            // Half of the resets are built to pass, so both branches get real coverage.
            let plausible = rng.flag();
            let at = effective_time(now_ms, control.clock_ms);
            let signed = plausible || rng.flag();
            let counter = if plausible { control.reset_counter + 1 + rng.below(3) } else { control.reset_counter.saturating_add(rng.below(3)).saturating_sub(1) };
            let from_mode = if plausible || rng.flag() { control.mode } else { MODES[rng.below(5) as usize] };
            let not_after_ms = if plausible { at + rng.below(100) } else { at.saturating_add(rng.below(100)).saturating_sub(50) };
            Event::Reset { now_ms, signed, counter, from_mode, not_after_ms, ttl_ms }
        }
    }
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

fn event_now(event: Event) -> u64 {
    match event {
        Event::Tick { now_ms } | Event::Renew { now_ms, .. } | Event::Classifier { now_ms, .. } | Event::HardRule { now_ms, .. }
        | Event::AgentRequest { now_ms } | Event::Reset { now_ms, .. } => now_ms,
    }
}

fn control_json(control: Control) -> Value {
    json!({"mode": mode_text(control.mode), "deadline": control.deadline_ms, "clock": control.clock_ms, "counter": control.reset_counter})
}

/// One differential step: the event, the control after it, the plan, and one access decision.
fn step_json(event: Event, result: StepResult, access: (AccessKind, bool, bool)) -> Value {
    let (kind, granted, baseline) = access;
    let allowed = authorize(event_now(event), result.control, AccessRequest { kind, granted, baseline });
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

fn cases(lines: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut cases: Vec<Value> = Vec::new();
    let mut after: Option<(Value, Value)> = None;
    for mut line in lines {
        if line["truncated"] == json!(true) {
            eprintln!("kernel-cases: the trace was cut at seq {}; later steps were not logged", line["seq"]);
            break;
        }
        let config = line["config"].take();
        let before = line["before"].take();
        let joins = after.as_ref().is_some_and(|(c, a)| *c == config && *a == before);
        let state = json!({"mode": line["mode"], "deadline": line["deadline"], "clock": line["clock"], "counter": line["counter"]});
        let obj = line.as_object_mut().expect("kernel line is an object");
        for key in ["seq", "config", "before"] {
            obj.remove(key);
        }
        if !joins {
            cases.push(json!({"config": config, "initial": before, "steps": []}));
        }
        cases.last_mut().expect("a case").get_mut("steps").and_then(Value::as_array_mut).expect("steps").push(line);
        after = Some((config, state));
    }
    cases
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let sequences: u64 = args.first().map_or(Ok(2_000), |v| v.parse())?;
    let mut rng = Rng(args.get(1).map_or(Ok(0x5eed), |v| v.parse())?);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for _ in 0..sequences {
        let config = Config { max_lease_ms: 1 + rng.below(500), freeze_grace_ms: rng.below(500) };
        let mode = MODES[rng.below(5) as usize];
        let mut control = Control { mode, deadline_ms: rng.below(1_000), clock_ms: rng.below(500), reset_counter: rng.below(4) };
        let initial = control_json(control);
        let mut now = rng.below(1_000);
        let mut steps = Vec::new();
        for _ in 0..(1 + rng.below(30)) {
            now += rng.below(250);
            // One event in eight carries an old timestamp.
            let stamped = if rng.below(8) == 0 { now.saturating_sub(rng.below(600)) } else { now };
            let input = event(&mut rng, stamped, control);
            let result = step(config, control, input);
            control = result.control;
            let kind = if rng.flag() { AccessKind::Egress } else { AccessKind::Secret };
            let (granted, baseline) = (rng.flag(), rng.flag());
            steps.push(step_json(input, result, (kind, granted, baseline)));
        }
        writeln!(out, "{}", json!({"config":{"max":config.max_lease_ms,"grace":config.freeze_grace_ms},"initial":initial,"steps":steps}))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(config: Config, mut control: Control, events: &[Event], first_seq: u64) -> Vec<Value> {
        events.iter().enumerate().map(|(i, &e)| {
            let result = step(config, control, e);
            let line = kernel_line(first_seq + i as u64, config, control, e, result);
            control = result.control;
            line
        }).collect()
    }

    #[test]
    fn a_kernel_trace_becomes_one_case_that_matches_the_random_case_shape() {
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let start = Control::new(Mode::Run, 100);
        let events = [Event::Tick { now_ms: 10 }, Event::Renew { now_ms: 20, ttl_ms: 200 }, Event::Classifier { now_ms: 30, level: Level::Hold }, Event::Tick { now_ms: 400 }];
        let mut lines = trace(config, start, &events, 0);
        lines.reverse();
        let mut sorted: BTreeMap<u64, Value> = BTreeMap::new();
        for line in lines { sorted.insert(line["seq"].as_u64().unwrap(), line); }
        let out = cases(sorted.into_values());
        assert_eq!(out.len(), 1);
        let case = &out[0];
        assert_eq!(case["config"], json!({"max": 300, "grace": 50}));
        assert_eq!(case["initial"], control_json(start));
        let steps = case["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4, "unchanged steps are kept, not only mode changes");
        assert_eq!(steps[1]["event"], json!({"type":"renew","now":20,"ttl":200}));
        for step in steps {
            let keys: Vec<_> = step.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, ["access", "actions", "clock", "counter", "deadline", "event", "mode"]);
        }
    }

    #[test]
    fn a_gap_in_the_trace_starts_a_new_case() {
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let mut lines = trace(config, Control::new(Mode::Run, 100), &[Event::Tick { now_ms: 10 }, Event::Tick { now_ms: 20 }], 0);
        // A step whose before is not the last result: something changed control outside the kernel.
        lines.extend(trace(config, Control::new(Mode::Hold, 900), &[Event::AgentRequest { now_ms: 30 }], 2));
        let out = cases(lines);
        assert_eq!(out.iter().map(|c| c["steps"].as_array().unwrap().len()).collect::<Vec<_>>(), [2, 1]);
    }

    #[test]
    fn a_cut_trace_stops_at_the_cut() {
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let mut lines = trace(config, Control::new(Mode::Run, 100), &[Event::Tick { now_ms: 10 }], 0);
        lines.push(json!({"seq": 1, "truncated": true}));
        lines.extend(trace(config, Control::new(Mode::Run, 100), &[Event::Tick { now_ms: 20 }], 2));
        let out = cases(lines);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["steps"].as_array().unwrap().len(), 1);
    }
}

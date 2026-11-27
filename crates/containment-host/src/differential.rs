use crate::kernel_trace::{control_json, step_json};
use containment_kernel::*;
use serde_json::json;
use std::error::Error;
use std::io::{self, Write};

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
    use crate::kernel_trace::{cases, encode, kernel_line};
    use serde_json::Value;
    use std::collections::BTreeMap;

    /// A kernel trace of `n` random events from `control`, as the controller logs it.
    fn trace(rng: &mut Rng, config: Config, mut control: Control, n: u64, first_seq: u64) -> (Vec<Value>, Vec<Event>) {
        let (mut lines, mut events) = (Vec::new(), Vec::new());
        for i in 0..n {
            let e = event(rng, 10 * (first_seq + i + 1), control);
            let result = step(config, control, e);
            lines.push(kernel_line(first_seq + i, config, control, e, result));
            events.push(e);
            control = result.control;
        }
        (lines, events)
    }

    #[test]
    fn a_kernel_trace_becomes_one_case_that_matches_the_random_case_shape() {
        let mut rng = Rng(7);
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let start = Control::new(Mode::Run, 100);
        let (mut lines, events) = trace(&mut rng, config, start, 4, 0);
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
        for (step, &e) in steps.iter().zip(&events) {
            assert_eq!(step["event"], encode(e));
            let keys: Vec<_> = step.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, ["access", "actions", "clock", "counter", "deadline", "event", "mode"]);
        }
    }

    #[test]
    fn a_gap_in_the_trace_starts_a_new_case() {
        let mut rng = Rng(7);
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let (mut lines, _) = trace(&mut rng, config, Control::new(Mode::Run, 100), 2, 0);
        // A step whose before is not the last result: something changed control outside the kernel.
        lines.extend(trace(&mut rng, config, Control::new(Mode::Hold, 900), 1, 2).0);
        let out = cases(lines);
        assert_eq!(out.iter().map(|c| c["steps"].as_array().unwrap().len()).collect::<Vec<_>>(), [2, 1]);
    }

    #[test]
    fn a_cut_trace_stops_at_the_cut() {
        let mut rng = Rng(7);
        let config = Config { max_lease_ms: 300, freeze_grace_ms: 50 };
        let (mut lines, _) = trace(&mut rng, config, Control::new(Mode::Run, 100), 1, 0);
        lines.push(json!({"seq": 1, "truncated": true}));
        lines.extend(trace(&mut rng, config, Control::new(Mode::Run, 100), 1, 2).0);
        let out = cases(lines);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["steps"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn every_random_event_encodes_with_its_kernel_timestamp() {
        let mut rng = Rng(11);
        let control = Control::new(Mode::Run, 100);
        for now in 0..200 {
            let e = event(&mut rng, now, control);
            assert_eq!(encode(e)["now"], json!(e.now_ms()));
        }
    }
}

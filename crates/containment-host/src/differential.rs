use containment_kernel::*;
use serde_json::{json, Value};
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

fn level(rng: &mut Rng) -> Level {
    [Level::Restrict, Level::Freeze, Level::Kill][rng.below(3) as usize]
}
fn level_text(level: Level) -> &'static str {
    match level {
        Level::Restrict => "restrict",
        Level::Freeze => "freeze",
        Level::Kill => "kill",
    }
}
fn mode_text(mode: Mode) -> &'static str {
    crate::common::mode_name(mode)
}
fn event(rng: &mut Rng, now_ms: u64) -> (Event, Value) {
    let ttl_ms = rng.below(1_000);
    match rng.below(6) {
        0 => (Event::Tick { now_ms }, json!({"type":"tick","now":now_ms})),
        1 => (Event::Renew { now_ms, ttl_ms }, json!({"type":"renew","now":now_ms,"ttl":ttl_ms})),
        2 => {
            let level = level(rng);
            (Event::Classifier { now_ms, level }, json!({"type":"classifier","now":now_ms,"level":level_text(level)}))
        }
        3 => {
            let level = level(rng);
            (Event::HardRule { now_ms, level }, json!({"type":"hard","now":now_ms,"level":level_text(level)}))
        }
        4 => (Event::AgentRequest { now_ms }, json!({"type":"agent","now":now_ms})),
        _ => {
            let signed = rng.flag();
            (Event::Reset { now_ms, signed, ttl_ms }, json!({"type":"reset","now":now_ms,"signed":signed,"ttl":ttl_ms}))
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
        let mode = [Mode::Run, Mode::Restrict, Mode::Freeze, Mode::Kill][rng.below(4) as usize];
        let mut control = Control { mode, deadline_ms: rng.below(1_000) };
        let initial = json!({"mode": mode_text(control.mode), "deadline": control.deadline_ms});
        let mut now = rng.below(1_000);
        let mut steps = Vec::new();
        for _ in 0..(1 + rng.below(30)) {
            now += rng.below(250);
            let (input, encoded) = event(&mut rng, now);
            let result = step(config, control, input);
            control = result.control;
            let kind = if rng.flag() { AccessKind::Egress } else { AccessKind::Secret };
            let (granted, baseline) = (rng.flag(), rng.flag());
            let allowed = authorize(now, control, AccessRequest { kind, granted, baseline });
            steps.push(json!({
                "event": encoded,
                "mode": mode_text(control.mode),
                "deadline": control.deadline_ms,
                "actions": result.actions.iter().map(crate::common::action_name).collect::<Vec<_>>(),
                "access": {"kind": if kind == AccessKind::Egress {"egress"} else {"secret"}, "granted": granted, "baseline": baseline, "allowed": allowed}
            }));
        }
        writeln!(out, "{}", json!({"config":{"max":config.max_lease_ms,"grace":config.freeze_grace_ms},"initial":initial,"steps":steps}))?;
    }
    Ok(())
}

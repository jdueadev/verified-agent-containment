use containment_kernel::*;

const MODES: [Mode; 4] = [Mode::Run, Mode::Restrict, Mode::Freeze, Mode::Kill];
const LEVELS: [Level; 3] = [Level::Restrict, Level::Freeze, Level::Kill];
const CONFIG: Config = Config { max_lease_ms: 5, freeze_grace_ms: 3 };

fn events(now_ms: u64, ttl_ms: u64) -> Vec<Event> {
    let mut out = vec![
        Event::Tick { now_ms },
        Event::Renew { now_ms, ttl_ms },
        Event::AgentRequest { now_ms },
        Event::Reset { now_ms, signed: false, ttl_ms },
    ];
    for level in LEVELS {
        out.push(Event::Classifier { now_ms, level });
        out.push(Event::HardRule { now_ms, level });
    }
    out
}

#[test]
fn unsigned_events_keep_or_tighten_containment() {
    for mode in MODES {
        for deadline_ms in 0..8 {
            for now_ms in 0..8 {
                for ttl_ms in 0..8 {
                    for event in events(now_ms, ttl_ms) {
                        let result = step(CONFIG, Control { mode, deadline_ms }, event);
                        assert!(result.control.mode >= mode, "{mode:?} {event:?} {result:?}");
                        if now_ms >= deadline_ms {
                            assert!(result.control.mode >= Mode::Freeze, "{mode:?} {event:?} {result:?}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn classifier_is_capped_and_renewal_is_bounded() {
    for mode in [Mode::Run, Mode::Restrict, Mode::Freeze] {
        let result = step(CONFIG, Control { mode, deadline_ms: 10 }, Event::Classifier { now_ms: 1, level: Level::Kill });
        assert_eq!(result.control.mode, Mode::Freeze);
    }
    let result = step(CONFIG, Control { mode: Mode::Run, deadline_ms: 10 }, Event::Renew { now_ms: 2, ttl_ms: 100 });
    assert_eq!(result.control.deadline_ms, 7);
}

#[test]
fn access_stops_at_the_deadline_without_a_tick() {
    let request = AccessRequest { kind: AccessKind::Egress, granted: true, baseline: true };
    assert!(authorize(4, Control { mode: Mode::Run, deadline_ms: 5 }, request));
    assert!(!authorize(5, Control { mode: Mode::Run, deadline_ms: 5 }, request));
}

use containment_kernel::*;

const MODES: [Mode; 5] = [
    Mode::Run,
    Mode::Restrict,
    Mode::Hold,
    Mode::Freeze,
    Mode::Kill,
];
const LEVELS: [Level; 4] = [Level::Restrict, Level::Hold, Level::Freeze, Level::Kill];
const CONFIG: Config = Config {
    max_lease_ms: 5,
    freeze_grace_ms: 3,
};

fn control(mode: Mode, deadline_ms: u64, clock_ms: u64, reset_counter: u64) -> Control {
    Control {
        mode,
        deadline_ms,
        clock_ms,
        reset_counter,
    }
}

fn reset(now_ms: u64, signed: bool, counter: u64, from_mode: Mode, not_after_ms: u64) -> Event {
    Event::Reset {
        now_ms,
        signed,
        counter,
        from_mode,
        not_after_ms,
        ttl_ms: 100,
    }
}

fn events(now_ms: u64, ttl_ms: u64) -> Vec<Event> {
    let mut out = vec![
        Event::Tick { now_ms },
        Event::Renew { now_ms, ttl_ms },
        Event::AgentRequest { now_ms },
    ];
    for from_mode in MODES {
        out.push(Event::Reset {
            now_ms,
            signed: false,
            counter: 9,
            from_mode,
            not_after_ms: 9,
            ttl_ms,
        });
    }
    for level in LEVELS {
        out.push(Event::Classifier { now_ms, level });
        out.push(Event::HardRule { now_ms, level });
    }
    out
}

fn each_case(mut check: impl FnMut(Control, Event, u64, StepResult)) {
    for mode in MODES {
        for deadline_ms in 0..7 {
            for clock_ms in 0..4 {
                for now_ms in 0..7 {
                    for ttl_ms in [0, 3, 9] {
                        for event in events(now_ms, ttl_ms) {
                            let before = control(mode, deadline_ms, clock_ms, 2);
                            check(
                                before,
                                event,
                                effective_time(now_ms, clock_ms),
                                step(CONFIG, before, event),
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn unsigned_events_keep_or_tighten_and_fail_closed() {
    each_case(|before, event, at, result| {
        assert!(
            result.control.mode >= before.mode,
            "{before:?} {event:?} {result:?}"
        );
        assert!(result.control.clock_ms >= before.clock_ms);
        assert_eq!(result.control.reset_counter, before.reset_counter);
        if at >= before.deadline_ms {
            assert!(
                result.control.mode >= Mode::Hold,
                "{before:?} {event:?} {result:?}"
            );
        }
    });
}

#[test]
fn every_stop_has_a_real_enforcement_plan() {
    each_case(|before, _event, _at, result| {
        if before.mode < Mode::Hold && result.control.mode >= Mode::Hold {
            assert!(result.actions.contains(Action::RevokeSecrets));
            assert!(result.actions.contains(Action::BlockEgress));
            assert!(result.actions.contains(Action::FreezeProcesses));
        }
        if before.mode != Mode::Kill && result.control.mode == Mode::Kill {
            assert!(result.actions.contains(Action::KillProcesses));
        }
    });
}

#[test]
fn classifier_stops_at_hold_and_hold_does_not_expire() {
    for mode in [Mode::Run, Mode::Restrict] {
        for level in [Level::Hold, Level::Freeze, Level::Kill] {
            let result = step(
                CONFIG,
                control(mode, 10, 0, 0),
                Event::Classifier { now_ms: 1, level },
            );
            assert_eq!(result.control.mode, Mode::Hold);
            let later = step(CONFIG, result.control, Event::Tick { now_ms: u64::MAX });
            assert_eq!(later.control.mode, Mode::Hold);
            assert!(later.actions.is_empty());
        }
    }
}

#[test]
fn freeze_escalates_at_its_fixed_deadline() {
    let frozen = step(
        CONFIG,
        control(Mode::Run, 10, 0, 0),
        Event::HardRule {
            now_ms: 1,
            level: Level::Freeze,
        },
    )
    .control;
    assert_eq!((frozen.mode, frozen.deadline_ms), (Mode::Freeze, 4));
    assert_eq!(
        step(
            CONFIG,
            frozen,
            Event::Renew {
                now_ms: 2,
                ttl_ms: 5
            }
        )
        .control
        .deadline_ms,
        4
    );
    let killed = step(CONFIG, frozen, Event::Tick { now_ms: 4 });
    assert_eq!(killed.control.mode, Mode::Kill);
    assert!(killed.actions.contains(Action::KillProcesses));
}

#[test]
fn stale_time_cannot_revive_authority() {
    let state = control(Mode::Run, 5, 6, 0);
    assert_eq!(
        step(
            CONFIG,
            state,
            Event::Renew {
                now_ms: 1,
                ttl_ms: 5
            }
        )
        .control
        .mode,
        Mode::Freeze
    );
    let request = AccessRequest {
        kind: AccessKind::Egress,
        granted: true,
        baseline: true,
    };
    assert!(!authorize(1, state, request));
    assert!(authorize(4, control(Mode::Run, 5, 0, 0), request));
    assert!(!authorize(5, control(Mode::Run, 5, 0, 0), request));
}

#[test]
fn reset_checks_every_signed_field() {
    let state = control(Mode::Kill, 0, 10, 4);
    let good = step(CONFIG, state, reset(10, true, 5, Mode::Kill, 10));
    assert_eq!(good.control.mode, Mode::Run);
    assert_eq!(good.control.reset_counter, 5);
    assert_eq!(good.control.deadline_ms, 15);
    assert!(good.actions.contains(Action::RecreateSandbox));
    assert!(!good.actions.contains(Action::ThawProcesses));
    for bad in [
        reset(10, false, 5, Mode::Kill, 10),
        reset(10, true, 4, Mode::Kill, 10),
        reset(10, true, 5, Mode::Freeze, 10),
        reset(11, true, 5, Mode::Kill, 10),
    ] {
        let result = step(CONFIG, state, bad);
        assert_eq!(result.control.mode, Mode::Kill, "{bad:?}");
        assert_eq!(result.control.reset_counter, 4);
    }
    let run = step(
        CONFIG,
        control(Mode::Run, 10, 0, 0),
        reset(1, true, 1, Mode::Run, 10),
    );
    assert_eq!(run.control.deadline_ms, 10);
    assert_eq!(run.control.reset_counter, 0);
}

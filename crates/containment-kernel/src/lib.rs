//! Pure decision kernel for agent containment.
//!
//! This is the production-language counterpart of `formal/kernel.bend`.
//! It has no clock, I/O, allocation, or dependency beyond `core`.
#![no_std]
#![forbid(unsafe_code)]
// A panic in the kernel stops the controller (release builds abort), so explicit
// panics and unwrapping are refused. clippy::indexing_slicing follows once
// Actions::extend has a fail-stop that is not an index panic (#56).
#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

/// Current containment mode, ordered from least to most contained.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Mode {
    Run,
    Restrict,
    /// Stopped for review. Hold has no deadline, so it cannot escalate by itself.
    Hold,
    /// Stopped with a fixed deadline that escalates to Kill.
    Freeze,
    Kill,
}

/// Requested containment level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Restrict,
    Hold,
    Freeze,
    Kill,
}

/// Ordered action for the host to apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    RevokeSecrets,
    NarrowEgress,
    BlockEgress,
    FreezeProcesses,
    KillProcesses,
    ThawProcesses,
    RecreateSandbox,
    RestoreAuthority,
}

/// Kernel limits, in milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub max_lease_ms: u64,
    pub freeze_grace_ms: u64,
}

/// Complete kernel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Control {
    pub mode: Mode,
    /// Lease deadline in Run and Restrict, escalation deadline in Freeze.
    pub deadline_ms: u64,
    /// Latest time the kernel has observed.
    pub clock_ms: u64,
    /// Highest accepted reset counter.
    pub reset_counter: u64,
}

impl Control {
    pub const fn new(mode: Mode, deadline_ms: u64) -> Self {
        Self {
            mode,
            deadline_ms,
            clock_ms: 0,
            reset_counter: 0,
        }
    }
}

/// Verified input to the kernel. `signed` is true only after the host has
/// verified the signature over every signed reset field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Tick {
        now_ms: u64,
    },
    Renew {
        now_ms: u64,
        ttl_ms: u64,
    },
    Classifier {
        now_ms: u64,
        level: Level,
    },
    HardRule {
        now_ms: u64,
        level: Level,
    },
    AgentRequest {
        now_ms: u64,
    },
    Reset {
        now_ms: u64,
        signed: bool,
        counter: u64,
        from_mode: Mode,
        not_after_ms: u64,
        ttl_ms: u64,
    },
}

impl Event {
    pub const fn now_ms(self) -> u64 {
        match self {
            Event::Tick { now_ms }
            | Event::Renew { now_ms, .. }
            | Event::Classifier { now_ms, .. }
            | Event::HardRule { now_ms, .. }
            | Event::AgentRequest { now_ms }
            | Event::Reset { now_ms, .. } => now_ms,
        }
    }
}

/// Access category checked at the host boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessKind {
    Egress,
    Secret,
}

/// Access request after policy lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub kind: AccessKind,
    pub granted: bool,
    pub baseline: bool,
}

/// Maximum number of actions returned by a single transition.
pub const MAX_ACTIONS: usize = 5;

/// Fixed-capacity ordered action list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Actions {
    items: [Option<Action>; MAX_ACTIONS],
    len: usize,
}

impl Actions {
    pub const fn none() -> Self {
        Self {
            items: [None; MAX_ACTIONS],
            len: 0,
        }
    }

    fn from_slice(values: &[Action]) -> Self {
        let mut out = Self::none();
        out.extend(values);
        out
    }

    fn extend(&mut self, values: &[Action]) {
        for value in values {
            self.items[self.len] = Some(*value);
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, action: Action) -> bool {
        self.iter().any(|value| value == action)
    }

    pub fn iter(&self) -> impl Iterator<Item = Action> + '_ {
        self.items.iter().take(self.len).filter_map(|value| *value)
    }
}

/// New control state plus the actions required to enter it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepResult {
    pub control: Control,
    pub actions: Actions,
}

const STOP_PLAN: &[Action] = &[
    Action::RevokeSecrets,
    Action::BlockEgress,
    Action::FreezeProcesses,
];
const KILL_PLAN: &[Action] = &[
    Action::RevokeSecrets,
    Action::BlockEgress,
    Action::FreezeProcesses,
    Action::KillProcesses,
];

#[derive(Clone, Copy)]
struct Core {
    mode: Mode,
    deadline_ms: u64,
}

#[derive(Clone, Copy)]
struct CoreResult {
    core: Core,
    actions: Actions,
}

fn raise(config: Config, now_ms: u64, control: Core, level: Level) -> CoreResult {
    let freeze_deadline = now_ms.saturating_add(config.freeze_grace_ms);
    let (mode, deadline_ms, plan): (Mode, u64, &[Action]) = match (control.mode, level) {
        (Mode::Run, Level::Restrict) => (
            Mode::Restrict,
            control.deadline_ms,
            &[Action::RevokeSecrets, Action::NarrowEgress],
        ),
        (Mode::Run | Mode::Restrict, Level::Hold) => (Mode::Hold, 0, STOP_PLAN),
        (Mode::Run | Mode::Restrict, Level::Freeze) => (Mode::Freeze, freeze_deadline, STOP_PLAN),
        (Mode::Run | Mode::Restrict, Level::Kill) => (Mode::Kill, 0, KILL_PLAN),
        (Mode::Hold, Level::Freeze) => (Mode::Freeze, freeze_deadline, &[]),
        (Mode::Hold | Mode::Freeze, Level::Kill) => (Mode::Kill, 0, &[Action::KillProcesses]),
        (mode, _) => (mode, control.deadline_ms, &[]),
    };
    CoreResult {
        core: Core { mode, deadline_ms },
        actions: Actions::from_slice(plan),
    }
}

fn settle(config: Config, now_ms: u64, control: Core) -> CoreResult {
    let unchanged = CoreResult {
        core: control,
        actions: Actions::none(),
    };
    if now_ms < control.deadline_ms {
        return unchanged;
    }
    match control.mode {
        Mode::Run | Mode::Restrict => raise(config, now_ms, control, Level::Freeze),
        Mode::Freeze => raise(config, now_ms, control, Level::Kill),
        Mode::Hold | Mode::Kill => unchanged,
    }
}

fn raise_after(config: Config, now_ms: u64, level: Level, first: CoreResult) -> CoreResult {
    let second = raise(config, now_ms, first.core, level);
    let mut actions = first.actions;
    for action in second.actions.iter() {
        actions.extend(&[action]);
    }
    CoreResult {
        core: second.core,
        actions,
    }
}

fn bounded_deadline(config: Config, now_ms: u64, ttl_ms: u64) -> u64 {
    now_ms.saturating_add(ttl_ms.min(config.max_lease_ms))
}

fn cap_classifier(level: Level) -> Level {
    match level {
        Level::Restrict => Level::Restrict,
        Level::Hold | Level::Freeze | Level::Kill => Level::Hold,
    }
}

fn reset_actions(mode: Mode) -> &'static [Action] {
    match mode {
        Mode::Run => &[],
        Mode::Restrict => &[Action::RestoreAuthority],
        Mode::Hold | Mode::Freeze => &[Action::ThawProcesses, Action::RestoreAuthority],
        Mode::Kill => &[Action::RecreateSandbox, Action::RestoreAuthority],
    }
}

/// Returns the time used for a timestamp. Stale time is clamped to the clock.
pub const fn effective_time(now_ms: u64, clock_ms: u64) -> u64 {
    if now_ms < clock_ms {
        clock_ms
    } else {
        now_ms
    }
}

fn reset_accepted(control: Control, event: Event, at_ms: u64) -> Option<u64> {
    let Event::Reset {
        signed: true,
        counter,
        from_mode,
        not_after_ms,
        ..
    } = event
    else {
        return None;
    };
    let ok = control.mode != Mode::Run
        && control.reset_counter < counter
        && from_mode == control.mode
        && at_ms <= not_after_ms;
    ok.then_some(counter)
}

/// Applies one verified event.
pub fn step(config: Config, control: Control, event: Event) -> StepResult {
    let at_ms = effective_time(event.now_ms(), control.clock_ms);
    let core = Core {
        mode: control.mode,
        deadline_ms: control.deadline_ms,
    };
    let accepted = reset_accepted(control, event, at_ms);
    let result = match event {
        Event::Tick { .. } | Event::AgentRequest { .. } => settle(config, at_ms, core),
        Event::Renew { ttl_ms, .. } => {
            let mut result = settle(config, at_ms, core);
            if matches!(result.core.mode, Mode::Run | Mode::Restrict) {
                result.core.deadline_ms = bounded_deadline(config, at_ms, ttl_ms);
            }
            result
        }
        Event::Classifier { level, .. } => raise_after(
            config,
            at_ms,
            cap_classifier(level),
            settle(config, at_ms, core),
        ),
        Event::HardRule { level, .. } => {
            raise_after(config, at_ms, level, settle(config, at_ms, core))
        }
        Event::Reset { ttl_ms, .. } if accepted.is_some() => CoreResult {
            core: Core {
                mode: Mode::Run,
                deadline_ms: bounded_deadline(config, at_ms, ttl_ms),
            },
            actions: Actions::from_slice(reset_actions(control.mode)),
        },
        Event::Reset { .. } => settle(config, at_ms, core),
    };
    StepResult {
        control: Control {
            mode: result.core.mode,
            deadline_ms: result.core.deadline_ms,
            clock_ms: at_ms,
            reset_counter: accepted.unwrap_or(control.reset_counter),
        },
        actions: result.actions,
    }
}

/// Checks one access request. An expired lease is denied even before a tick.
pub fn authorize(now_ms: u64, control: Control, request: AccessRequest) -> bool {
    if effective_time(now_ms, control.clock_ms) >= control.deadline_ms {
        return false;
    }
    match control.mode {
        Mode::Run => request.granted,
        Mode::Restrict => request.kind == AccessKind::Egress && request.granted && request.baseline,
        Mode::Hold | Mode::Freeze | Mode::Kill => false,
    }
}

//! Pure decision kernel for agent containment.
//!
//! This is the production-language counterpart of `formal/kernel.bend`.
//! It has no clock, I/O, allocation, or dependency beyond `core`.
#![no_std]
#![forbid(unsafe_code)]

/// Current containment mode, ordered from least to most contained.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Mode {
    Run,
    Restrict,
    Freeze,
    Kill,
}

/// Requested containment level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Restrict,
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

/// Mode plus its deadline. Run and Restrict use the lease deadline.
/// Freeze uses the deadline for escalation to Kill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Control {
    pub mode: Mode,
    pub deadline_ms: u64,
}

/// Verified input to the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Tick { now_ms: u64 },
    Renew { now_ms: u64, ttl_ms: u64 },
    Classifier { now_ms: u64, level: Level },
    HardRule { now_ms: u64, level: Level },
    AgentRequest { now_ms: u64 },
    Reset { now_ms: u64, signed: bool, ttl_ms: u64 },
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
        Self { items: [None; MAX_ACTIONS], len: 0 }
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

    pub fn iter(&self) -> impl Iterator<Item = Action> + '_ {
        self.items[..self.len].iter().filter_map(|value| *value)
    }
}

/// New control state plus the actions required to enter it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepResult {
    pub control: Control,
    pub actions: Actions,
}

const FREEZE_PLAN: &[Action] = &[Action::RevokeSecrets, Action::BlockEgress, Action::FreezeProcesses];
const KILL_PLAN: &[Action] = &[
    Action::RevokeSecrets,
    Action::BlockEgress,
    Action::FreezeProcesses,
    Action::KillProcesses,
];

fn raise(config: Config, now_ms: u64, control: Control, level: Level) -> StepResult {
    let freeze_deadline = now_ms.saturating_add(config.freeze_grace_ms);
    let (mode, deadline_ms, plan): (Mode, u64, &[Action]) = match (control.mode, level) {
        (Mode::Run, Level::Restrict) => (
            Mode::Restrict,
            control.deadline_ms,
            &[Action::RevokeSecrets, Action::NarrowEgress],
        ),
        (Mode::Run | Mode::Restrict, Level::Freeze) => (Mode::Freeze, freeze_deadline, FREEZE_PLAN),
        (Mode::Run | Mode::Restrict, Level::Kill) => (Mode::Kill, 0, KILL_PLAN),
        (Mode::Freeze, Level::Kill) => (Mode::Kill, 0, &[Action::KillProcesses]),
        (mode, _) => (mode, control.deadline_ms, &[]),
    };
    StepResult {
        control: Control { mode, deadline_ms },
        actions: Actions::from_slice(plan),
    }
}

fn settle(config: Config, now_ms: u64, control: Control) -> StepResult {
    if now_ms < control.deadline_ms {
        return StepResult { control, actions: Actions::none() };
    }
    match control.mode {
        Mode::Run | Mode::Restrict => raise(config, now_ms, control, Level::Freeze),
        Mode::Freeze => raise(config, now_ms, control, Level::Kill),
        Mode::Kill => StepResult { control, actions: Actions::none() },
    }
}

fn raise_after(config: Config, now_ms: u64, level: Level, first: StepResult) -> StepResult {
    let second = raise(config, now_ms, first.control, level);
    let mut actions = first.actions;
    for action in second.actions.iter() {
        actions.extend(&[action]);
    }
    StepResult { control: second.control, actions }
}

fn bounded_deadline(config: Config, now_ms: u64, ttl_ms: u64) -> u64 {
    now_ms.saturating_add(ttl_ms.min(config.max_lease_ms))
}

/// Applies one verified event.
pub fn step(config: Config, control: Control, event: Event) -> StepResult {
    match event {
        Event::Tick { now_ms } | Event::AgentRequest { now_ms } => settle(config, now_ms, control),
        Event::Renew { now_ms, ttl_ms } => {
            let mut result = settle(config, now_ms, control);
            if matches!(result.control.mode, Mode::Run | Mode::Restrict) {
                result.control.deadline_ms = bounded_deadline(config, now_ms, ttl_ms);
            }
            result
        }
        Event::Classifier { now_ms, level } => {
            let capped = if level == Level::Kill { Level::Freeze } else { level };
            raise_after(config, now_ms, capped, settle(config, now_ms, control))
        }
        Event::HardRule { now_ms, level } => {
            raise_after(config, now_ms, level, settle(config, now_ms, control))
        }
        Event::Reset { now_ms, signed: true, ttl_ms } => {
            let plan: &[Action] = match control.mode {
                Mode::Run => &[],
                Mode::Restrict => &[Action::RestoreAuthority],
                Mode::Freeze => &[Action::ThawProcesses, Action::RestoreAuthority],
                Mode::Kill => &[Action::RecreateSandbox, Action::RestoreAuthority],
            };
            StepResult {
                control: Control { mode: Mode::Run, deadline_ms: bounded_deadline(config, now_ms, ttl_ms) },
                actions: Actions::from_slice(plan),
            }
        }
        Event::Reset { now_ms, signed: false, .. } => settle(config, now_ms, control),
    }
}

/// Checks one access request. An expired lease is denied even before a tick.
pub fn authorize(now_ms: u64, control: Control, request: AccessRequest) -> bool {
    if now_ms >= control.deadline_ms {
        return false;
    }
    match control.mode {
        Mode::Run => request.granted,
        Mode::Restrict => {
            request.kind == AccessKind::Egress && request.granted && request.baseline
        }
        Mode::Freeze | Mode::Kill => false,
    }
}

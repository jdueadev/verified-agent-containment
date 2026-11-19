//! Small C ABI over the kernel for the browser showcase.
#![no_std]

use containment_kernel::*;
use core::cell::UnsafeCell;

struct Machine {
    config: Config,
    control: Control,
    actions: [u32; MAX_ACTIONS],
    action_count: u32,
}

struct Slot(UnsafeCell<Machine>);
// SAFETY: WebAssembly modules used by this page run on one thread.
unsafe impl Sync for Slot {}

static MACHINE: Slot = Slot(UnsafeCell::new(Machine {
    config: Config { max_lease_ms: 250, freeze_grace_ms: 400 },
    control: Control::new(Mode::Run, 200),
    actions: [0; MAX_ACTIONS],
    action_count: 0,
}));

fn with<T>(f: impl FnOnce(&mut Machine) -> T) -> T {
    // SAFETY: exports are not reentrant and the page is single-threaded.
    f(unsafe { &mut *MACHINE.0.get() })
}

fn mode_code(mode: Mode) -> u32 {
    match mode { Mode::Run => 0, Mode::Restrict => 1, Mode::Hold => 2, Mode::Freeze => 3, Mode::Kill => 4 }
}

fn mode_from(code: u32) -> Mode {
    match code { 0 => Mode::Run, 1 => Mode::Restrict, 2 => Mode::Hold, 3 => Mode::Freeze, _ => Mode::Kill }
}

fn action_code(action: Action) -> u32 {
    match action {
        Action::RevokeSecrets => 0,
        Action::NarrowEgress => 1,
        Action::BlockEgress => 2,
        Action::FreezeProcesses => 3,
        Action::KillProcesses => 4,
        Action::ThawProcesses => 5,
        Action::RecreateSandbox => 6,
        Action::RestoreAuthority => 7,
    }
}

fn level(value: u32) -> Level {
    match value { 0 => Level::Restrict, 1 => Level::Hold, 2 => Level::Freeze, _ => Level::Kill }
}

fn ms(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 { value as u64 } else { 0 }
}

fn commit(m: &mut Machine, event: Event) -> u32 {
    let result = step(m.config, m.control, event);
    m.control = result.control;
    m.action_count = 0;
    for action in result.actions.iter() {
        m.actions[m.action_count as usize] = action_code(action);
        m.action_count += 1;
    }
    mode_code(m.control.mode)
}

#[no_mangle]
pub extern "C" fn reset_machine(max_lease_ms: f64, freeze_grace_ms: f64, now_ms: f64, ttl_ms: f64) {
    with(|m| {
        m.config = Config { max_lease_ms: ms(max_lease_ms), freeze_grace_ms: ms(freeze_grace_ms) };
        m.control = Control {
            mode: Mode::Run,
            deadline_ms: ms(now_ms).saturating_add(ms(ttl_ms).min(m.config.max_lease_ms)),
            clock_ms: ms(now_ms),
            reset_counter: 0,
        };
        m.action_count = 0;
    });
}

#[no_mangle]
pub extern "C" fn set_control(mode: u32, deadline_ms: f64, clock_ms: f64, reset_counter: f64) {
    with(|m| {
        m.control = Control { mode: mode_from(mode), deadline_ms: ms(deadline_ms), clock_ms: ms(clock_ms), reset_counter: ms(reset_counter) };
        m.action_count = 0;
    });
}

#[no_mangle]
pub extern "C" fn set_config(max_lease_ms: f64, freeze_grace_ms: f64) {
    with(|m| m.config = Config { max_lease_ms: ms(max_lease_ms), freeze_grace_ms: ms(freeze_grace_ms) });
}

/// Event kinds: 0 tick, 1 renew, 2 classifier, 3 hard rule, 4 agent request.
#[no_mangle]
pub extern "C" fn apply_event(kind: u32, now_ms: f64, ttl_ms: f64, severity: u32) -> u32 {
    let now_ms = ms(now_ms);
    let ttl_ms = ms(ttl_ms);
    let event = match kind {
        1 => Event::Renew { now_ms, ttl_ms },
        2 => Event::Classifier { now_ms, level: level(severity) },
        3 => Event::HardRule { now_ms, level: level(severity) },
        4 => Event::AgentRequest { now_ms },
        _ => Event::Tick { now_ms },
    };
    with(|m| commit(m, event))
}

#[no_mangle]
pub extern "C" fn apply_reset(signed: u32, now_ms: f64, counter: f64, from_mode: u32, not_after_ms: f64, ttl_ms: f64) -> u32 {
    let event = Event::Reset {
        now_ms: ms(now_ms),
        signed: signed != 0,
        counter: ms(counter),
        from_mode: mode_from(from_mode),
        not_after_ms: ms(not_after_ms),
        ttl_ms: ms(ttl_ms),
    };
    with(|m| commit(m, event))
}

#[no_mangle]
pub extern "C" fn current_mode() -> u32 { with(|m| mode_code(m.control.mode)) }
#[no_mangle]
pub extern "C" fn current_deadline() -> f64 { with(|m| m.control.deadline_ms as f64) }
#[no_mangle]
pub extern "C" fn current_clock() -> f64 { with(|m| m.control.clock_ms as f64) }
#[no_mangle]
pub extern "C" fn current_counter() -> f64 { with(|m| m.control.reset_counter as f64) }
#[no_mangle]
pub extern "C" fn action_count() -> u32 { with(|m| m.action_count) }
#[no_mangle]
pub extern "C" fn action_at(index: u32) -> u32 {
    with(|m| if index < m.action_count { m.actions[index as usize] } else { u32::MAX })
}

/// Access kinds: 0 egress, 1 secret.
#[no_mangle]
pub extern "C" fn access_allowed(now_ms: f64, kind: u32, granted: u32, baseline: u32) -> u32 {
    let request = AccessRequest {
        kind: if kind == 0 { AccessKind::Egress } else { AccessKind::Secret },
        granted: granted != 0,
        baseline: baseline != 0,
    };
    with(|m| u32::from(authorize(ms(now_ms), m.control, request)))
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

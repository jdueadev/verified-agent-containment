//! The harnesses. Each states one promise of `decide`, `Limit::admits` or
//! `Cost::settled` and checks it for every input: every u64, every mode, every
//! kind of attempt, with and without a grant. Kani also checks every harness
//! for panics and arithmetic overflow, so each one that calls `decide` proves
//! too that no input makes it panic.

use crate::admission::{decide, Attempt, Cost, Grant, Kind, Layer, Limit, Verdict};
use containment_kernel::{Control, Level, Mode};

// Inputs, built from free values. The matches name every variant and the
// struct literals every field, so when a type gains one this file stops
// compiling instead of leaving the new case unchecked.

fn any_mode() -> Mode {
    let mode = match kani::any::<u8>() {
        0 => Mode::Run,
        1 => Mode::Restrict,
        2 => Mode::Hold,
        3 => Mode::Freeze,
        _ => Mode::Kill,
    };
    match mode {
        Mode::Run | Mode::Restrict | Mode::Hold | Mode::Freeze | Mode::Kill => mode,
    }
}

fn any_control() -> Control {
    Control { mode: any_mode(), deadline_ms: kani::any(), clock_ms: kani::any(), reset_counter: kani::any() }
}

impl kani::Arbitrary for Kind {
    fn any() -> Self {
        let kind = match kani::any::<u8>() {
            0 => Kind::Model { local: kani::any() },
            1 => Kind::Web { write: kani::any() },
            2 => Kind::LabEgress { secret: kani::any() },
            _ => Kind::LabSecret,
        };
        match kind {
            Kind::Model { .. } | Kind::Web { .. } | Kind::LabEgress { .. } | Kind::LabSecret => kind,
        }
    }
}

impl kani::Arbitrary for Cost {
    fn any() -> Self {
        Cost { requests: kani::any(), bytes: kani::any(), tokens: kani::any() }
    }
}

impl kani::Arbitrary for Limit {
    fn any() -> Self {
        Limit { requests: kani::any(), bytes: kani::any(), tokens: kani::any() }
    }
}

impl kani::Arbitrary for Grant {
    fn any() -> Self {
        Grant { write: kani::any(), baseline: kani::any(), limit: kani::any() }
    }
}

impl kani::Arbitrary for Attempt {
    fn any() -> Self {
        Attempt { kind: kani::any(), cost: kani::any(), carries_canary: kani::any() }
    }
}

/// One call of `decide`, on inputs Kani chooses freely.
struct Case {
    grant: Option<Grant>,
    control: Control,
    now_ms: u64,
    ready: bool,
    used: Cost,
    attempt: Attempt,
    verdict: Verdict,
}

fn any_case() -> Case {
    let grant: Option<Grant> = kani::any();
    let control = any_control();
    let now_ms = kani::any();
    let ready = kani::any();
    let used = kani::any();
    let attempt = kani::any();
    let verdict = decide(grant.as_ref(), control, now_ms, ready, &used, &attempt);
    Case { grant, control, now_ms, ready, used, attempt, verdict }
}

impl Case {
    fn allowed(&self) -> bool {
        matches!(self.verdict, Verdict::Allow { .. })
    }
}

// The rules, restated in plain terms and not by calling the code they check.

/// The brokered secret travels with these.
fn carries_secret(kind: Kind) -> bool {
    matches!(kind, Kind::LabSecret | Kind::LabEgress { secret: true })
}

/// The grant that covers the attempt: its destination's, if that allows what
/// the attempt does. Only a web request other than GET or HEAD writes.
fn covering(grant: Option<Grant>, kind: Kind) -> Option<Grant> {
    grant.filter(|grant| grant.write || kind != Kind::Web { write: true })
}

/// What the kernel's `authorize` allows: nothing once the lease deadline is
/// reached by the later of the caller's time and the kernel's clock; in Run,
/// whatever the policy granted; in Restrict, baseline egress and no secret; in
/// Hold, Freeze and Kill, nothing. The refusals are the laws
/// access_requires_grant, expired_lease_denies, stopped_denies,
/// restrict_denies_secrets and restrict_egress_needs_baseline in
/// formal/LAWS.bend; what it allows is `authorize` in the kernel's lib.rs.
fn kernel_admits(control: Control, now_ms: u64, grant: Grant, kind: Kind) -> bool {
    let live = now_ms.max(control.clock_ms) < control.deadline_ms;
    let mode = match control.mode {
        Mode::Run => true,
        Mode::Restrict => grant.baseline && !carries_secret(kind),
        Mode::Hold | Mode::Freeze | Mode::Kill => false,
    };
    live && mode
}

/// Each count: its limit, what was used, what the attempt costs.
fn counts(limit: Limit, used: Cost, cost: Cost) -> [(Option<u64>, u64, u64); 3] {
    [
        (limit.requests, used.requests, cost.requests),
        (limit.bytes, used.bytes, cost.bytes),
        (limit.tokens, used.tokens, cost.tokens),
    ]
}

fn totals(cost: Cost) -> [u64; 3] {
    [cost.requests, cost.bytes, cost.tokens]
}

/// Every limited count stays within its limit once the cost is added.
fn within(limit: Limit, used: Cost, cost: Cost) -> bool {
    counts(limit, used, cost)
        .iter()
        .all(|&(limit, used, cost)| limit.is_none_or(|limit| used.checked_add(cost).is_some_and(|total| total <= limit)))
}

/// Every count of `total` is `used` plus `cost`: exactly where there is a
/// limit, and saturating only where there is none.
fn charged_exactly(limit: Limit, used: Cost, cost: Cost, total: Cost) -> bool {
    counts(limit, used, cost).iter().zip(totals(total)).all(|(&(limit, used, cost), total)| match limit {
        Some(_) => used.checked_add(cost) == Some(total),
        None => used.saturating_add(cost) == total,
    })
}

/// No authority without a grant: an attempt whose destination the policy does
/// not grant is never allowed.
/// Harm if broken: an agent reaches a destination nobody approved.
#[kani::proof]
fn an_ungranted_destination_is_never_allowed() {
    let case = any_case();
    assert!(case.grant.is_some() || !case.allowed(), "allowed with no grant");
}

/// The mode binds: nothing is allowed in Hold, Freeze or Kill, once the lease
/// deadline is reached, or while authority is not ready, and in Restrict only
/// baseline egress without the secret is allowed.
/// Harm if broken: a contained agent keeps acting.
#[kani::proof]
fn the_mode_binds() {
    let case = any_case();
    if case.allowed() {
        assert!(case.ready, "allowed while authority is not ready");
        assert!(matches!(case.control.mode, Mode::Run | Mode::Restrict), "allowed in Hold, Freeze or Kill");
        assert!(case.now_ms.max(case.control.clock_ms) < case.control.deadline_ms, "allowed once the lease deadline is reached");
        let baseline = case.grant.is_some_and(|grant| grant.baseline);
        assert!(
            case.control.mode != Mode::Restrict || (baseline && !carries_secret(case.attempt.kind)),
            "Restrict allowed more than baseline egress"
        );
    }
}

/// The budget holds: an allowed attempt's new total is what was used plus the
/// attempt's cost and never exceeds any limit of its grant, and the budget
/// refuses only an attempt that would take some count over its limit.
/// Harm if broken: a budget that can be overspent, or that refuses, and
/// restricts, work it has room for.
#[kani::proof]
#[kani::unwind(4)]
fn the_budget_holds() {
    let case = any_case();
    let cost = case.attempt.cost;
    match (case.verdict, case.grant) {
        (Verdict::Allow { used: total }, Some(grant)) => {
            assert!(charged_exactly(grant.limit, case.used, cost, total), "allowed and not charged exactly its cost");
            assert!(within(grant.limit, case.used, cost), "allowed over a limit");
        }
        (Verdict::Refuse { by: Layer::Budget, .. }, grant) => {
            assert!(grant.is_some_and(|grant| !within(grant.limit, case.used, cost)), "refused for its budget with room left");
        }
        _ => {}
    }
}

/// The canary rule fires first and always raises a hard rule: an attempt that
/// carries the canary is refused by the canary step whatever else holds,
/// raising Restrict when it is bound for a model on this host and Freeze
/// otherwise, and no other attempt is refused as the canary.
/// Harm if broken: a canary leaves quietly, or leaves the host and only restricts.
#[kani::proof]
fn the_canary_rule_fires_first_and_raises() {
    let case = any_case();
    let level = if case.attempt.kind == (Kind::Model { local: true }) { Level::Restrict } else { Level::Freeze };
    let as_canary = matches!(case.verdict, Verdict::Refuse { by: Layer::Canary, .. });
    if case.attempt.carries_canary {
        assert!(case.verdict == Verdict::Refuse { by: Layer::Canary, raise: Some(level) }, "a canary not refused by its rule");
    } else {
        assert!(!as_canary, "refused as the canary without one");
    }
}

/// A write is never allowed on a read-only grant: a web request other than GET
/// or HEAD is allowed only by a grant that allows writes.
/// Harm if broken: a read grant is used to change something.
#[kani::proof]
fn a_read_grant_never_allows_a_write() {
    let case = any_case();
    if case.attempt.kind == (Kind::Web { write: true }) && case.allowed() {
        assert!(case.grant.is_some_and(|grant| grant.write), "a write allowed on a read grant");
    }
}

/// Each refusal names the first step that refused, in the order canary,
/// policy, kernel, budget, and raises what that step raises; an attempt that
/// every step passes is allowed.
/// Harm if broken: the gateway restricts an agent on its third policy refusal
/// (`Shared::admit` in gate.rs) and on any budget refusal, so a refusal blamed
/// on the wrong step lets an agent probe ungranted destinations uncounted, or
/// restricts it for nothing; and an attempt every step passes is lost work.
#[kani::proof]
#[kani::unwind(4)]
fn each_refusal_names_the_step_that_refused() {
    let case = any_case();
    if case.attempt.carries_canary {
        return; // the_canary_rule_fires_first_and_raises checks the first step.
    }
    let kind = case.attempt.kind;
    let expected = if let Some(grant) = covering(case.grant, kind) {
        if !(case.ready && kernel_admits(case.control, case.now_ms, grant, kind)) {
            Some((Layer::Kernel, None))
        } else if !within(grant.limit, case.used, case.attempt.cost) {
            Some((Layer::Budget, Some(Level::Restrict)))
        } else {
            None
        }
    } else {
        Some((Layer::Policy, None))
    };
    match (case.verdict, expected) {
        (Verdict::Allow { .. }, None) => {}
        (Verdict::Allow { .. }, Some(_)) => panic!("allowed although a step refuses it"),
        (Verdict::Refuse { .. }, None) => panic!("refused although every step passes it"),
        (Verdict::Refuse { by, raise }, Some((step, raises))) => {
            assert!(by == step, "refused by the wrong step");
            assert!(raise == raises, "raised the wrong rule");
        }
    }
}

/// Budget arithmetic never wraps: for every limit, spend and cost,
/// `Limit::admits` gives a total only when every limited count stays within
/// its limit, and each count it gives is the spend plus the cost, saturating
/// only where there is no limit.
/// Harm if broken: a wrapped count reads as almost nothing spent, and the
/// budget admits again.
#[kani::proof]
#[kani::unwind(4)]
fn admits_never_wraps() {
    let (limit, used, cost): (Limit, Cost, Cost) = (kani::any(), kani::any(), kani::any());
    match limit.admits(&used, &cost) {
        Some(total) => {
            assert!(within(limit, used, cost), "admitted over a limit");
            assert!(charged_exactly(limit, used, cost, total), "a total is not the spend plus the cost");
        }
        None => assert!(!within(limit, used, cost), "refused with room left"),
    }
}

/// Settling never wraps: replacing a reservation with what was really spent
/// never panics, never comes to less than what was really spent, and is exact
/// whenever the spend still holds the reservation and the sum fits.
/// Harm if broken: a settled count wraps to almost nothing, and the lease's
/// budget is spent again.
#[kani::proof]
#[kani::unwind(4)]
fn settling_never_wraps() {
    let (spent, reserved, actual): (Cost, Cost, Cost) = (kani::any(), kani::any(), kani::any());
    let settled = spent.settled(reserved, actual);
    for ((spent, reserved), (actual, settled)) in totals(spent).into_iter().zip(totals(reserved)).zip(totals(actual).into_iter().zip(totals(settled))) {
        assert!(settled >= actual, "settled to less than was really spent");
        if let Some(exact) = spent.checked_sub(reserved).and_then(|rest| rest.checked_add(actual)) {
            assert!(settled == exact, "settled to other than the spend less the reservation plus the actual cost");
        }
    }
}

//! Kani proofs of the gate's lease handling. gate.rs compiles this file as
//! `controller::gate::proofs` when Kani builds the host crate, so the harnesses
//! reach the gate's private `Lease` and `Charge`. scripts/kani.sh runs them.
//!
//! Only the model's account and the unmetered one are checked. A host's
//! account lives in a BTreeMap keyed by origin, and CBMC runs out of memory in
//! the map's code, so per-host accounts are left to the unit tests in gate.rs.

use super::*;

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

fn any_kind() -> Kind {
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

fn any_cost() -> Cost {
    Cost { requests: kani::any(), bytes: kani::any(), tokens: kani::any() }
}

fn any_grant() -> Option<Grant> {
    let limit = Limit { requests: kani::any(), bytes: kani::any(), tokens: kani::any() };
    kani::any::<bool>().then(|| Grant { write: kani::any(), baseline: kani::any(), limit })
}

fn any_control() -> Control {
    Control { mode: any_mode(), deadline_ms: kani::any(), clock_ms: kani::any(), reset_counter: kani::any() }
}

/// Stands in for `Gate::open`, which records the slot in BTreeMaps CBMC
/// cannot get through and stamps it with the boot clock, a libc call. Nothing
/// here asserts anything about slots.
fn no_slot(gate: &Gate, _baseline: bool) -> Slot<'_> {
    Slot { upstreams: &gate.upstreams, id: 0, admitted_ns: 0 }
}

/// One admission on `account`, which must be the model's or the unmetered one.
fn admits_and_charges(account: Account) {
    let metered = matches!(account, Account::Model);
    let gate = Gate::new(Weakness::default());
    let (number, model) = (kani::any(), any_cost());
    *lock(&gate.lease) = Lease { number, model, hosts: BTreeMap::new() };
    let control = Mutex::new(any_control());
    let held = lock(&control);
    let seen = *held;
    let (now_ms, ready) = (kani::any(), kani::any());
    let attempt = Attempt { kind: any_kind(), cost: any_cost(), carries_canary: kani::any() };
    let grant = any_grant();
    let admitted = gate.admit(&held, now_ms, ready, attempt, grant, account);

    // The lease is the latest reset's the kernel has accepted, and a newer
    // one starts with nothing spent. `decide` should see what that lease has
    // spent on the account.
    let current = number.max(seen.reset_counter);
    let spent = if seen.reset_counter > number { Cost::default() } else { model };
    let charged = if metered { spent } else { Cost::default() };
    let expected = decide(grant.as_ref(), seen, now_ms, ready, &charged, &attempt);
    let (number_after, model_after) = {
        let lease = lock(&gate.lease);
        (lease.number, lease.model)
    };
    assert!(number_after == current, "the gate is not in the latest reset's lease");
    match (admitted, expected) {
        (Err(refused), Verdict::Refuse { by, raise }) => {
            assert!(refused == (by, raise), "the gate refused for another reason than decide");
            assert!(model_after == spent, "a refusal charged");
        }
        (Ok(permit), Verdict::Allow { used }) => {
            assert!(model_after == if metered { used } else { spent }, "an admission was not charged decide's total");
            assert!(permit.charge.number == current, "the charge names another lease");
            // Dropping the permit runs the slot's BTreeMap code; see below.
            std::mem::forget(permit);
        }
        (Ok(_), Verdict::Refuse { .. }) => panic!("the gate admitted what decide refuses"),
        (Err(_), Verdict::Allow { .. }) => panic!("the gate refused what decide allows"),
    };
    drop(held);
    // Dropping the gate runs the BTreeMap drop code, which CBMC cannot finish
    // in memory. Nothing asserted here happens in a drop.
    std::mem::forget(gate);
}

/// A refusal never charges, and an admission charges its own lease: the gate
/// refuses exactly what `decide` refuses, with the same step and rule, and
/// leaves the lease's spending as it was; it charges an allowed attempt
/// `decide`'s new total, in the lease of the latest reset the kernel has
/// accepted, and the charge records that lease.
/// Harm if broken: refused work drains a budget, or an attempt is decided and
/// charged against a lease the kernel has already replaced.
#[kani::proof]
#[kani::stub(Gate::open, no_slot)]
#[kani::unwind(3)]
fn a_refusal_never_charges_and_an_admission_charges_its_lease() {
    admits_and_charges(Account::Model);
    admits_and_charges(Account::Unmetered);
}

/// One charge on `account`, which must be the model's or the unmetered one,
/// settled after the kernel may have accepted a reset.
fn settles_in_its_lease(account: Account) {
    let metered = matches!(account, Account::Model);
    let (made, model) = (kani::any(), any_cost());
    let lease = Mutex::new(Lease { number: made, model, hosts: BTreeMap::new() });
    let cost = any_cost();
    let charge = Charge { lease: &lease, number: made, account, cost };
    let reset = kani::any();
    lock(&lease).start(reset);
    let actual = any_cost();
    let reported = charge.settle(actual);
    let after = lock(&lease);
    if reset > made {
        assert!(after.number == reset, "a later reset's lease did not start");
        assert!(after.model == Cost::default() && reported == Cost::default(), "an earlier lease's charge moved into the new lease");
    } else {
        assert!(after.number == made, "a lease number went back");
        let settled = if metered { model.settled(cost, actual) } else { model };
        assert!(after.model == settled, "the charge did not settle in its own lease");
        assert!(reported == if metered { settled } else { Cost::default() }, "settling reported another spend");
    }
    assert!(after.hosts.is_empty(), "settling touched a host's account");
}

/// A charge settles only into the lease that made it, and a lease number
/// never goes back: once a later reset's lease has started, settling an
/// earlier charge changes nothing; in its own lease, settling replaces the
/// reservation with the real cost on its own account.
/// Harm if broken: work from before a reset spends, or refunds, the budget the
/// reset renewed, or an old reset's number wipes a lease's spending.
#[kani::proof]
#[kani::unwind(3)]
fn a_charge_settles_only_into_the_lease_that_made_it() {
    settles_in_its_lease(Account::Model);
    settles_in_its_lease(Account::Unmetered);
}

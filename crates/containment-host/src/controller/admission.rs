//! What the gateway decides about one attempt, as a pure function of plain
//! data: no locks, clock, I/O, strings or collections. The gate gathers the
//! inputs under the control lock and acts on the verdict, so this module can
//! be read, tested and model-checked on its own.

use containment_kernel::{authorize, AccessKind, AccessRequest, Control, Level};

/// What the agent is trying to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A model call. `local` is a model on this host: a canary sent there has
    /// not left the host.
    Model { local: bool },
    /// A live web request. `write` is any method but GET and HEAD.
    Web { write: bool },
    /// Lab egress, carrying the brokered secret when `secret`.
    LabEgress { secret: bool },
    /// A lab request for the brokered secret's handle.
    LabSecret,
}

/// What an attempt costs, or what an account has spent in a lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Cost {
    pub(super) requests: u64,
    pub(super) bytes: u64,
    pub(super) tokens: u64,
}

/// The most an account may spend in one lease. `None` is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Limit {
    pub(super) requests: Option<u64>,
    pub(super) bytes: Option<u64>,
    pub(super) tokens: Option<u64>,
}

/// What the policy grants one destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Grant {
    /// Requests that change something are allowed, not only GET and HEAD.
    pub(super) write: bool,
    /// Baseline egress, which Restrict keeps.
    pub(super) baseline: bool,
    pub(super) limit: Limit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    pub(super) kind: Kind,
    pub(super) cost: Cost,
    pub(super) carries_canary: bool,
}

/// The step that refused an attempt. Later steps were not consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Layer {
    Canary,
    Policy,
    Kernel,
    Budget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Admitted. `used` is what the account has spent once the attempt is charged.
    Allow { used: Cost },
    /// Refused by `by`, which raises the hard rule `raise` if it has one.
    Refuse { by: Layer, raise: Option<Level> },
}

impl Limit {
    pub(super) const NONE: Self = Self { requests: None, bytes: None, tokens: None };

    /// What `used` comes to with `cost` added, if that stays within every limit.
    /// A limited count that would overflow is over its limit; an unlimited one
    /// saturates.
    pub(super) fn admits(&self, used: &Cost, cost: &Cost) -> Option<Cost> {
        Some(Cost {
            requests: within(self.requests, used.requests, cost.requests)?,
            bytes: within(self.bytes, used.bytes, cost.bytes)?,
            tokens: within(self.tokens, used.tokens, cost.tokens)?,
        })
    }
}

fn within(limit: Option<u64>, used: u64, cost: u64) -> Option<u64> {
    match limit {
        None => Some(used.saturating_add(cost)),
        Some(limit) => used.checked_add(cost).filter(|total| *total <= limit),
    }
}

impl Cost {
    /// What was spent once a reservation of `reserved` turns out to have cost
    /// `actual`. Saturating, so a settled count never wraps.
    pub(super) fn settled(self, reserved: Cost, actual: Cost) -> Cost {
        let settle = |spent: u64, reserved: u64, actual: u64| spent.saturating_sub(reserved).saturating_add(actual);
        Cost {
            requests: settle(self.requests, reserved.requests, actual.requests),
            bytes: settle(self.bytes, reserved.bytes, actual.bytes),
            tokens: settle(self.tokens, reserved.tokens, actual.tokens),
        }
    }
}

/// Decides one attempt. The steps run in one order for every kind: the canary,
/// the policy, the kernel, the budget. `grant` is what the policy grants the
/// attempt's destination, `used` what its account has spent in this lease.
pub(super) fn decide(grant: Option<&Grant>, control: Control, now_ms: u64, authority_ready: bool, used: &Cost, attempt: &Attempt) -> Verdict {
    // First, so the canary's rule fires however else the attempt would end.
    if attempt.carries_canary {
        // A canary bound for a model on this host has not left it.
        let level = if attempt.kind == (Kind::Model { local: true }) { Level::Restrict } else { Level::Freeze };
        return Verdict::Refuse { by: Layer::Canary, raise: Some(level) };
    }
    let covered = grant.filter(|grant| grant.write || attempt.kind != Kind::Web { write: true });
    let Some(grant) = covered else {
        return Verdict::Refuse { by: Layer::Policy, raise: None };
    };
    if !(kernel_allows(control, now_ms, grant, attempt.kind)) {
        return Verdict::Refuse { by: Layer::Kernel, raise: None };
    }
    match grant.limit.admits(used, &attempt.cost) {
        Some(used) => Verdict::Allow { used },
        None => Verdict::Refuse { by: Layer::Budget, raise: Some(Level::Restrict) },
    }
}

/// The kernel's answer for an attempt the policy granted.
fn kernel_allows(control: Control, now_ms: u64, grant: &Grant, kind: Kind) -> bool {
    let egress = AccessRequest { kind: AccessKind::Egress, granted: true, baseline: grant.baseline };
    let brokered = AccessRequest { kind: AccessKind::Secret, granted: true, baseline: false };
    let allows = |request| authorize(now_ms, control, request);
    match kind {
        Kind::Model { .. } | Kind::Web { .. } | Kind::LabEgress { secret: false } => allows(egress),
        Kind::LabEgress { secret: true } => allows(egress) && allows(brokered),
        Kind::LabSecret => allows(brokered),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use containment_kernel::Mode;

    const NOW: u64 = 1_000;
    const LIVE: u64 = 5_000;
    const KINDS: [Kind; 7] = [
        Kind::Model { local: true }, Kind::Model { local: false }, Kind::Web { write: false }, Kind::Web { write: true },
        Kind::LabEgress { secret: false }, Kind::LabEgress { secret: true }, Kind::LabSecret,
    ];
    const MODES: [Mode; 5] = [Mode::Run, Mode::Restrict, Mode::Hold, Mode::Freeze, Mode::Kill];
    const CAP: Limit = Limit { requests: Some(5), bytes: Some(100), tokens: Some(1_000) };
    const ONE: Cost = Cost { requests: 1, bytes: 10, tokens: 100 };

    fn control(mode: Mode, deadline_ms: u64) -> Control {
        Control { mode, deadline_ms, clock_ms: NOW, reset_counter: 0 }
    }

    fn grant(write: bool, baseline: bool, limit: Limit) -> Grant {
        Grant { write, baseline, limit }
    }

    fn attempt(kind: Kind) -> Attempt {
        Attempt { kind, cost: ONE, carries_canary: false }
    }

    fn refused(by: Layer) -> Verdict {
        Verdict::Refuse { by, raise: None }
    }

    fn holds_secret(kind: Kind) -> bool {
        matches!(kind, Kind::LabSecret | Kind::LabEgress { secret: true })
    }

    /// One row per kind and per step that refuses it, then the allowed case.
    /// Each row changes one input from an attempt that would be allowed.
    #[test]
    fn each_step_refuses_each_kind_and_the_rest_is_allowed() {
        let full = grant(true, true, CAP);
        let run = control(Mode::Run, LIVE);
        for kind in KINDS {
            let at = attempt(kind);
            let canary = if kind == (Kind::Model { local: true }) { Level::Restrict } else { Level::Freeze };
            let over = Cost { tokens: 901, ..Cost::default() };
            let rows = [
                ("carries the canary", Some(full), run, true, Cost::default(), Attempt { carries_canary: true, ..at },
                    Verdict::Refuse { by: Layer::Canary, raise: Some(canary) }),
                ("no grant", None, run, true, Cost::default(), at, refused(Layer::Policy)),
                ("held", Some(full), control(Mode::Hold, LIVE), true, Cost::default(), at, refused(Layer::Kernel)),
                ("authority pending", Some(full), run, false, Cost::default(), at, refused(Layer::Kernel)),
                ("over its budget", Some(full), run, true, over, at, Verdict::Refuse { by: Layer::Budget, raise: Some(Level::Restrict) }),
                ("allowed", Some(full), run, true, Cost::default(), at, Verdict::Allow { used: ONE }),
            ];
            for (name, grant, control, ready, used, attempt, expected) in rows {
                assert_eq!(decide(grant.as_ref(), control, NOW, ready, &used, &attempt), expected, "{kind:?}: {name}");
            }
        }
    }

    #[test]
    fn a_read_grant_allows_reads_only() {
        let read = grant(false, false, Limit::NONE);
        let run = control(Mode::Run, LIVE);
        let at = |write| attempt(Kind::Web { write });
        assert_eq!(decide(Some(&read), run, NOW, true, &Cost::default(), &at(true)), refused(Layer::Policy));
        assert_eq!(decide(Some(&read), run, NOW, true, &Cost::default(), &at(false)), Verdict::Allow { used: ONE });
    }

    #[test]
    fn restrict_keeps_baseline_egress_and_nothing_else() {
        let restrict = control(Mode::Restrict, LIVE);
        for kind in KINDS {
            for baseline in [false, true] {
                let verdict = decide(Some(&grant(true, baseline, Limit::NONE)), restrict, NOW, true, &Cost::default(), &attempt(kind));
                let kept = baseline && !holds_secret(kind);
                assert_eq!(verdict == (Verdict::Allow { used: ONE }), kept, "{kind:?} baseline {baseline}: {verdict:?}");
            }
        }
    }

    #[test]
    fn an_expired_lease_admits_nothing() {
        for kind in KINDS {
            let verdict = decide(Some(&grant(true, true, Limit::NONE)), control(Mode::Run, NOW), NOW, true, &Cost::default(), &attempt(kind));
            assert_eq!(verdict, refused(Layer::Kernel), "{kind:?}");
        }
    }

    #[test]
    fn a_budget_admits_up_to_its_limit_exactly() {
        let at = attempt(Kind::Web { write: true });
        let full = grant(true, false, CAP);
        let run = control(Mode::Run, LIVE);
        let last = Cost { requests: 4, bytes: 90, tokens: 900 };
        assert_eq!(decide(Some(&full), run, NOW, true, &last, &at), Verdict::Allow { used: Cost { requests: 5, bytes: 100, tokens: 1_000 } });
        for over in [Cost { requests: 5, ..last }, Cost { bytes: 91, ..last }, Cost { tokens: 901, ..last }] {
            assert_eq!(decide(Some(&full), run, NOW, true, &over, &at), Verdict::Refuse { by: Layer::Budget, raise: Some(Level::Restrict) }, "{over:?}");
        }
    }

    #[test]
    fn counts_never_wrap() {
        let at = Attempt { cost: Cost { requests: 2, bytes: 2, tokens: 2 }, ..attempt(Kind::Model { local: true }) };
        let full = Cost { requests: u64::MAX, bytes: u64::MAX, tokens: u64::MAX };
        let run = control(Mode::Run, LIVE);
        let limited = grant(true, true, Limit { requests: Some(u64::MAX), bytes: Some(u64::MAX), tokens: Some(u64::MAX) });
        assert_eq!(decide(Some(&limited), run, NOW, true, &full, &at), Verdict::Refuse { by: Layer::Budget, raise: Some(Level::Restrict) });
        assert_eq!(decide(Some(&grant(true, true, Limit::NONE)), run, NOW, true, &full, &at), Verdict::Allow { used: full });
    }

    #[test]
    fn settling_replaces_the_reservation_with_what_was_spent() {
        let spent = Cost { requests: 3, bytes: 300, tokens: 3_000 };
        let reserved = Cost { requests: 1, bytes: 100, tokens: 1_000 };
        assert_eq!(spent.settled(reserved, Cost { requests: 1, bytes: 100, tokens: 400 }), Cost { requests: 3, bytes: 300, tokens: 2_400 });
        assert_eq!(spent.settled(reserved, Cost::default()), Cost { requests: 2, bytes: 200, tokens: 2_000 });
        assert_eq!(Cost::default().settled(reserved, ONE), ONE);
        let most = Cost { tokens: u64::MAX, ..Cost::default() };
        assert_eq!(most.settled(Cost::default(), ONE).tokens, u64::MAX);
    }

    /// Every combination of a small domain, held to the properties a model
    /// checker would be asked to prove.
    #[test]
    fn the_properties_hold_over_the_whole_small_domain() {
        let limits = [Limit::NONE, CAP];
        let mut grants = vec![None];
        for write in [false, true] {
            for baseline in [false, true] {
                grants.extend(limits.map(|limit| Some(grant(write, baseline, limit))));
            }
        }
        let spends = [Cost::default(), Cost { requests: 4, bytes: 90, tokens: 900 }, Cost { requests: 5, bytes: 100, tokens: 1_000 },
            Cost { requests: u64::MAX, bytes: u64::MAX, tokens: u64::MAX }];
        let mut checked = 0;
        for kind in KINDS {
            for grant in &grants {
                for mode in MODES {
                    for deadline in [NOW, LIVE] {
                        for ready in [false, true] {
                            for canary in [false, true] {
                                for used in spends {
                                    let at = Attempt { kind, cost: ONE, carries_canary: canary };
                                    let control = control(mode, deadline);
                                    let verdict = decide(grant.as_ref(), control, NOW, ready, &used, &at);
                                    check(grant.as_ref(), control, ready, &used, &at, verdict);
                                    checked += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 7 * 9 * 5 * 2 * 2 * 2 * 4);
    }

    fn check(grant: Option<&Grant>, control: Control, ready: bool, used: &Cost, at: &Attempt, verdict: Verdict) {
        let case = format!("{grant:?} {control:?} ready {ready} used {used:?} {at:?}: {verdict:?}");
        // The canary is refused first, always, and always raises its rule.
        if at.carries_canary {
            let level = if at.kind == (Kind::Model { local: true }) { Level::Restrict } else { Level::Freeze };
            assert_eq!(verdict, Verdict::Refuse { by: Layer::Canary, raise: Some(level) }, "{case}");
            return;
        }
        match verdict {
            Verdict::Allow { used: after } => {
                let grant = grant.expect("an attempt with no grant is never allowed");
                assert!(ready, "nothing is allowed while authority is pending: {case}");
                assert!(matches!(control.mode, Mode::Run | Mode::Restrict), "nothing is allowed in Hold or above: {case}");
                assert!(NOW < control.deadline_ms, "nothing is allowed once the lease has expired: {case}");
                assert!(control.mode == Mode::Run || (grant.baseline && !holds_secret(at.kind)), "Restrict keeps only baseline egress: {case}");
                assert!(grant.write || at.kind != Kind::Web { write: true }, "a write needs a write grant: {case}");
                // The charge is exactly the attempt's cost, and a limited count stays within its limit.
                for (limit, before, cost, total) in [
                    (grant.limit.requests, used.requests, at.cost.requests, after.requests),
                    (grant.limit.bytes, used.bytes, at.cost.bytes, after.bytes),
                    (grant.limit.tokens, used.tokens, at.cost.tokens, after.tokens),
                ] {
                    assert_eq!(total, before.saturating_add(cost), "{case}");
                    assert!(limit.is_none_or(|limit| total <= limit), "a charge never exceeds its limit: {case}");
                }
            }
            Verdict::Refuse { by, raise } => {
                let raises = match by {
                    Layer::Canary => panic!("only the canary is refused as the canary: {case}"),
                    Layer::Policy | Layer::Kernel => None,
                    Layer::Budget => Some(Level::Restrict),
                };
                assert_eq!(raise, raises, "{case}");
                // A step refuses only an attempt every earlier step passed: with the
                // refusing step out of the way, the attempt gets further.
                let free = Limit::NONE;
                let unlimited = grant.map(|g| Grant { limit: free, ..*g });
                let open = Control { mode: Mode::Run, deadline_ms: u64::MAX, ..control };
                let past = |grant: Option<&Grant>, control, ready| decide(grant, control, NOW, ready, used, at);
                match by {
                    Layer::Budget => assert!(matches!(past(unlimited.as_ref(), control, ready), Verdict::Allow { .. }), "{case}"),
                    Layer::Kernel => assert!(matches!(past(unlimited.as_ref(), open, true), Verdict::Allow { .. }), "{case}"),
                    Layer::Policy => {
                        let any = Grant { write: true, baseline: true, limit: free };
                        assert!(matches!(past(Some(&any), open, true), Verdict::Allow { .. }), "{case}");
                    }
                    Layer::Canary => unreachable!(),
                }
            }
        }
    }
}

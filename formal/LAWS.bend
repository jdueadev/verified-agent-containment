# Containment laws. These state what the decision kernel must guarantee.
# PROOF.bend proves them; `bend PROOF.bend --verdict` rechecks the proofs.

import Base
import ./kernel.bend as K

def control_of(r: K.StepResult) -> K.ControlState:
  match r:
    case K.StepResult{c, _}:
      c

def state_mode(c: K.ControlState) -> K.ContainmentMode:
  match c:
    case K.ControlState{m, _, _, _}:
      m

def mode_of(r: K.StepResult) -> K.ContainmentMode:
  state_mode(control_of(r))

def deadline_of(r: K.StepResult) -> Nat:
  match r:
    case K.StepResult{K.ControlState{_, d, _, _}, _}:
      d

def clock_of(r: K.StepResult) -> Nat:
  match r:
    case K.StepResult{K.ControlState{_, _, c, _}, _}:
      c

def counter_of(r: K.StepResult) -> Nat:
  match r:
    case K.StepResult{K.ControlState{_, _, _, n}, _}:
      n

def plan_of(r: K.StepResult) -> K.ActionPlan:
  match r:
    case K.StepResult{_, a}:
      a

def is_live(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeRun{}:
      True{}
    case K.ModeRestrict{}:
      True{}
    case _:
      False{}

def is_hold(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeHold{}:
      True{}
    case _:
      False{}

def is_freeze(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeFreeze{}:
      True{}
    case _:
      False{}

def is_kill(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeKill{}:
      True{}
    case _:
      False{}

def is_restrict(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeRestrict{}:
      True{}
    case _:
      False{}

def before_freeze(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeFreeze{}:
      False{}
    case K.ModeKill{}:
      False{}
    case _:
      True{}

def is_renew(e: K.ControlEvent) -> Bool:
  match e:
    case K.Renew{_, _}:
      True{}
    case _:
      False{}

def is_stopped(m: K.ContainmentMode) -> Bool:
  Bool.not(is_live(m))

def is_restrict_level(l: K.SeverityLevel) -> Bool:
  match l:
    case K.ToRestrict{}:
      True{}
    case _:
      False{}

def rank(m: K.ContainmentMode) -> Nat:
  match m:
    case K.ModeRun{}:
      0n
    case K.ModeRestrict{}:
      1n
    case K.ModeHold{}:
      2n
    case K.ModeFreeze{}:
      3n
    case K.ModeKill{}:
      4n

def rank_at_least(a: K.ContainmentMode, b: K.ContainmentMode) -> Bool:
  Nat.is_le(rank(b), rank(a))

def level_mode(l: K.SeverityLevel) -> K.ContainmentMode:
  match l:
    case K.ToRestrict{}:
      K.ModeRestrict{}
    case K.ToHold{}:
      K.ModeHold{}
    case K.ToFreeze{}:
      K.ModeFreeze{}
    case K.ToKill{}:
      K.ModeKill{}

def implies(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      True{}

def at_time(+e: K.ControlEvent, +clock: Nat) -> Nat:
  K.effective_time(K.event_time(e), clock)

def accepted(+m: K.ContainmentMode, +counter: Nat, +e: K.ControlEvent, +clock: Nat) -> Bool:
  K.is_accepted_reset(m, counter, e, at_time(e, clock))

def signed_of(e: K.ControlEvent) -> Bool:
  match e:
    case K.Reset{_, s, _, _, _, _}:
      s
    case _:
      False{}

def is_passive(e: K.ControlEvent) -> Bool:
  match e:
    case K.HardRule{_, _}:
      False{}
    case K.Reset{_, s, _, _, _, _}:
      Bool.not(s)
    case _:
      True{}

def secrets_gone(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeRun{}:
      False{}
    case _:
      True{}

def egress_gone(m: K.ContainmentMode) -> Bool:
  Bool.not(is_live(m))

def action_code(a: K.ContainAction) -> Nat:
  match a:
    case K.RevokeSecrets{}:
      0n
    case K.NarrowEgress{}:
      1n
    case K.BlockEgress{}:
      2n
    case K.FreezeProcesses{}:
      3n
    case K.KillProcesses{}:
      4n
    case K.ThawProcesses{}:
      5n
    case K.RecreateSandbox{}:
      6n
    case K.RestoreAuthority{}:
      7n

def plan_has(a: K.ActionPlan, +x: Nat) -> Bool:
  match a:
    case K.NoMore{}:
      False{}
    case K.Next{h, t}:
      Nat.is_eq(action_code(h), x) || plan_has(t, x)

def has_recovery(+a: K.ActionPlan) -> Bool:
  plan_has(a, 5n) || (plan_has(a, 6n) || plan_has(a, 7n))

def has_stop_plan(+a: K.ActionPlan) -> Bool:
  plan_has(a, 0n) && (plan_has(a, 2n) && plan_has(a, 3n))

def stop_is_ordered(a: K.ActionPlan, +s: Bool, +n: Bool) -> Bool:
  match a:
    case K.NoMore{}:
      True{}
    case K.Next{K.RevokeSecrets{}, t}:
      stop_is_ordered(t, True{}, n)
    case K.Next{K.BlockEgress{}, t}:
      stop_is_ordered(t, s, True{})
    case K.Next{K.FreezeProcesses{}, t}:
      (s && n) && stop_is_ordered(t, s, n)
    case K.Next{K.KillProcesses{}, t}:
      (s && n) && stop_is_ordered(t, s, n)
    case K.Next{_, t}:
      stop_is_ordered(t, s, n)

def recovery_plan(m: K.ContainmentMode) -> K.ActionPlan:
  match m:
    case K.ModeRun{}:
      K.NoMore{}
    case K.ModeRestrict{}:
      K.Next{K.RestoreAuthority{}, K.NoMore{}}
    case K.ModeHold{}:
      K.Next{K.ThawProcesses{}, K.Next{K.RestoreAuthority{}, K.NoMore{}}}
    case K.ModeFreeze{}:
      K.Next{K.ThawProcesses{}, K.Next{K.RestoreAuthority{}, K.NoMore{}}}
    case K.ModeKill{}:
      K.Next{K.RecreateSandbox{}, K.Next{K.RestoreAuthority{}, K.NoMore{}}}

def replay(es: List<&2, K.ControlEvent>, +cfg: K.KernelConfig, c: K.ControlState) -> K.ControlState:
  match es:
    case Nil{}:
      c
    case Con{e, t}:
      replay(t, cfg, control_of(K.step(cfg, c, e)))

def Unsigned(es: List<&2, K.ControlEvent>) -> Type:
  match es:
    case Nil{}:
      Unit
    case Con{e, t}:
      {signed_of(e) == False{} : Bool} & Unsigned(t)

def Passive(es: List<&2, K.ControlEvent>) -> Type:
  match es:
    case Nil{}:
      Unit
    case Con{e, t}:
      {is_passive(e) == True{} : Bool} & Passive(t)

# LEASE AND MONOTONICITY

# At or after the deadline, no event except an accepted reset leaves Run or Restrict active.
law fail_closed:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for h: {Nat.is_lt(at_time(e, clock), d) == False{} : Bool}
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {is_live(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))) == False{} : Bool}

# Without an accepted reset, no event lowers containment.
law tighten_only:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {rank_at_least(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)), m) == True{} : Bool}

# No unsigned event sequence lowers containment.
law no_sequence_lowers_containment:
  for +es: List<&2, K.ControlEvent>
  for +cfg: K.KernelConfig
  for +c: K.ControlState
  for u: Unsigned(es)
  {rank_at_least(state_mode(replay(es, cfg, c)), state_mode(c)) == True{} : Bool}

# Renewal cannot extend authority beyond the observed time plus the maximum lease.
law renewal_is_bounded:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for ttl: Nat
  {implies(is_live(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Renew{now, ttl}))),
    Nat.is_le(deadline_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Renew{now, ttl})), Nat.add(K.effective_time(now, clock), K.max_lease_of(cfg)))) == True{} : Bool}

# TIME

# The kernel's observed clock never moves backward.
law clock_never_rewinds:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  {Nat.is_le(clock, clock_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))) == True{} : Bool}

# The kernel's clock is exactly the effective time of the event it just handled.
law clock_is_effective_time:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  {clock_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)) == at_time(e, clock) : Nat}

# A stale timestamp is evaluated at the latest observed time.
law stale_time_uses_clock:
  for +now: Nat
  for +clock: Nat
  for h: {Nat.is_lt(now, clock) == True{} : Bool}
  {K.effective_time(now, clock) == clock : Nat}

# CLASSIFIER

# A classifier cannot cause Kill in one step while authority remains in time.
law classifier_cannot_kill:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for level: K.SeverityLevel
  for k: {is_kill(m) == False{} : Bool}
  for h: {Nat.is_lt(K.effective_time(now, clock), d) == True{} : Bool}
  {is_kill(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Classifier{now, level}))) == False{} : Bool}

# A classifier stop request enters Hold, never the escalating Freeze state.
law classifier_stop_enters_hold:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for level: K.SeverityLevel
  for l: {is_live(m) == True{} : Bool}
  for s: {is_restrict_level(level) == False{} : Bool}
  for h: {Nat.is_lt(K.effective_time(now, clock), d) == True{} : Bool}
  {is_hold(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Classifier{now, level}))) == True{} : Bool}

# Passive events cannot escalate Hold, across any trace.
law hold_cannot_self_escalate:
  for +es: List<&2, K.ControlEvent>
  for +cfg: K.KernelConfig
  for +c: K.ControlState
  for h: {is_hold(state_mode(c)) == True{} : Bool}
  for p: Passive(es)
  {is_hold(state_mode(replay(es, cfg, c))) == True{} : Bool}

# ENFORCEMENT PLANS

# Stop actions always remove authority before processes are frozen or killed.
law authority_removed_first:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  {stop_is_ordered(plan_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)), secrets_gone(m), egress_gone(m)) == True{} : Bool}

# Leaving Run or Restrict for a stopped mode emits the complete stop plan.
law stop_plan_is_complete:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for l: {is_live(m) == True{} : Bool}
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {implies(is_stopped(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))), has_stop_plan(plan_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)))) == True{} : Bool}

# Entering Kill emits KillProcesses.
law kill_plan_is_complete:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for k: {is_kill(m) == False{} : Bool}
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {implies(is_kill(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))), plan_has(plan_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)), 4n)) == True{} : Bool}

# An expired Freeze escalates to Kill unless a reset is accepted.
law freeze_escalates:
  for +cfg: K.KernelConfig
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for h: {Nat.is_lt(at_time(e, clock), d) == False{} : Bool}
  for r: {accepted(K.ModeFreeze{}, counter, e, clock) == False{} : Bool}
  {is_kill(mode_of(K.step(cfg, K.ControlState{K.ModeFreeze{}, d, clock, counter}, e))) == True{} : Bool}

# Nothing except an accepted reset can extend or shorten a Freeze deadline.
law freeze_deadline_is_fixed:
  for +cfg: K.KernelConfig
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(K.ModeFreeze{}, counter, e, clock) == False{} : Bool}
  {implies(is_freeze(mode_of(K.step(cfg, K.ControlState{K.ModeFreeze{}, d, clock, counter}, e))), Nat.is_eq(deadline_of(K.step(cfg, K.ControlState{K.ModeFreeze{}, d, clock, counter}, e)), d)) == True{} : Bool}

# Entering Freeze from Run, Restrict or Hold starts exactly one configured grace period.
law freeze_entry_uses_grace:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for l: {before_freeze(m) == True{} : Bool}
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {implies(is_freeze(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))), Nat.is_eq(deadline_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)), Nat.add(at_time(e, clock), K.grace_of(cfg)))) == True{} : Bool}

# Only renewal or an accepted reset can extend a live lease.
law lease_only_renewal_extends:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for n: {is_renew(e) == False{} : Bool}
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {implies(is_live(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))), Nat.is_le(deadline_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)), d)) == True{} : Bool}

# Entering Restrict from Run revokes secrets and narrows egress.
law restrict_plan_is_complete:
  for +cfg: K.KernelConfig
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(K.ModeRun{}, counter, e, clock) == False{} : Bool}
  {implies(is_restrict(mode_of(K.step(cfg, K.ControlState{K.ModeRun{}, d, clock, counter}, e))), plan_has(plan_of(K.step(cfg, K.ControlState{K.ModeRun{}, d, clock, counter}, e)), 0n) && plan_has(plan_of(K.step(cfg, K.ControlState{K.ModeRun{}, d, clock, counter}, e)), 1n)) == True{} : Bool}

# Without an accepted reset, no plan thaws, rebuilds or restores authority.
law no_recovery_without_reset:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {has_recovery(plan_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e))) == False{} : Bool}

# Without an accepted reset, the reset counter does not change.
law counter_needs_accepted_reset:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(m, counter, e, clock) == False{} : Bool}
  {counter_of(K.step(cfg, K.ControlState{m, d, clock, counter}, e)) == counter : Nat}

# A hard rule always reaches at least its requested level.
law hard_rule_reaches_level:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for +level: K.SeverityLevel
  {rank_at_least(mode_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.HardRule{now, level})), level_mode(level)) == True{} : Bool}

# Kill is absorbing until a reset is accepted.
law kill_needs_accepted_reset:
  for +cfg: K.KernelConfig
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +e: K.ControlEvent
  for r: {accepted(K.ModeKill{}, counter, e, clock) == False{} : Bool}
  {is_kill(mode_of(K.step(cfg, K.ControlState{K.ModeKill{}, d, clock, counter}, e))) == True{} : Bool}

# RESET

# Accepted resets require a signature, a fresh counter, the current mode and an unexpired time.
law reset_requires_signature:
  for +m: K.ContainmentMode
  for +counter: Nat
  for +n: Nat
  for f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {K.reset_ok(m, counter, False{}, n, f, not_after, at) == False{} : Bool}

law reset_requires_fresh_counter:
  for +m: K.ContainmentMode
  for +counter: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {implies(K.reset_ok(m, counter, s, n, f, not_after, at), Nat.is_lt(counter, n)) == True{} : Bool}

law reset_is_bound_to_mode:
  for +m: K.ContainmentMode
  for +counter: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {implies(K.reset_ok(m, counter, s, n, f, not_after, at), K.same_mode(f, m)) == True{} : Bool}

law reset_must_be_unexpired:
  for +m: K.ContainmentMode
  for +counter: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {implies(K.reset_ok(m, counter, s, n, f, not_after, at), Nat.is_le(at, not_after)) == True{} : Bool}

# A reset cannot be used as a lease renewal from Run.
law reset_cannot_renew_run:
  for +counter: Nat
  for s: Bool
  for +n: Nat
  for f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {K.reset_ok(K.ModeRun{}, counter, s, n, f, not_after, at) == False{} : Bool}

# After an accepted reset, its counter is consumed.
law accepted_reset_consumes_counter:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for ttl: Nat
  for h: {K.reset_ok(m, counter, s, n, f, not_after, K.effective_time(now, clock)) == True{} : Bool}
  {counter_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Reset{now, s, n, f, not_after, ttl})) == n : Nat}

# A counter equal to the state's counter is rejected.
law reset_cannot_replay:
  for +m: K.ContainmentMode
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for +at: Nat
  {K.reset_ok(m, n, s, n, f, not_after, at) == False{} : Bool}

# An accepted reset receives a bounded lease and the exact recovery plan for its mode:
# survivors are never resumed by a sandbox rebuild, and authority returns last.
law reset_is_bounded:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for ttl: Nat
  for h: {K.reset_ok(m, counter, s, n, f, not_after, K.effective_time(now, clock)) == True{} : Bool}
  {Nat.is_le(deadline_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Reset{now, s, n, f, not_after, ttl})), Nat.add(K.effective_time(now, clock), K.max_lease_of(cfg))) == True{} : Bool}

law reset_plan_is_complete:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for +counter: Nat
  for +now: Nat
  for s: Bool
  for +n: Nat
  for +f: K.ContainmentMode
  for +not_after: Nat
  for ttl: Nat
  for h: {K.reset_ok(m, counter, s, n, f, not_after, K.effective_time(now, clock)) == True{} : Bool}
  {plan_of(K.step(cfg, K.ControlState{m, d, clock, counter}, K.Reset{now, s, n, f, not_after, ttl})) == recovery_plan(m) : K.ActionPlan}

# ACCESS

law access_requires_grant:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for counter: Nat
  for k: K.AccessKind
  for +g: Bool
  for b: Bool
  {implies(K.authorize(now, K.ControlState{m, d, clock, counter}, K.AccessRequest{k, g, b}), g) == True{} : Bool}

# An expired lease denies access even before the controller handles a tick.
law expired_lease_denies:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for counter: Nat
  for r: K.AccessRequest
  for h: {Nat.is_lt(K.effective_time(now, clock), d) == False{} : Bool}
  {K.authorize(now, K.ControlState{m, d, clock, counter}, r) == False{} : Bool}

law stopped_denies:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for +clock: Nat
  for counter: Nat
  for r: K.AccessRequest
  for s: {is_stopped(m) == True{} : Bool}
  {K.authorize(now, K.ControlState{m, d, clock, counter}, r) == False{} : Bool}

law restrict_denies_secrets:
  for +now: Nat
  for +d: Nat
  for +clock: Nat
  for counter: Nat
  for g: Bool
  for b: Bool
  {K.authorize(now, K.ControlState{K.ModeRestrict{}, d, clock, counter}, K.AccessRequest{K.SecretAccess{}, g, b}) == False{} : Bool}

law restrict_egress_needs_baseline:
  for +now: Nat
  for +d: Nat
  for +clock: Nat
  for counter: Nat
  for g: Bool
  for +b: Bool
  {implies(K.authorize(now, K.ControlState{K.ModeRestrict{}, d, clock, counter}, K.AccessRequest{K.EgressAccess{}, g, b}), b) == True{} : Bool}

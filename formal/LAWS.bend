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
    case K.ControlState{m, _}:
      m

def mode_of(r: K.StepResult) -> K.ContainmentMode:
  state_mode(control_of(r))

def deadline_of(r: K.StepResult) -> Nat:
  match r:
    case K.StepResult{K.ControlState{_, d}, _}:
      d

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
    case K.ModeFreeze{}:
      False{}
    case K.ModeKill{}:
      False{}

def is_kill(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeKill{}:
      True{}
    case _:
      False{}

def is_stopped(m: K.ContainmentMode) -> Bool:
  Bool.not(is_live(m))

def rank_at_least(a: K.ContainmentMode, b: K.ContainmentMode) -> Bool:
  match a b:
    case K.ModeKill{} _:
      True{}
    case K.ModeFreeze{} K.ModeKill{}:
      False{}
    case K.ModeFreeze{} _:
      True{}
    case K.ModeRestrict{} K.ModeRun{}:
      True{}
    case K.ModeRestrict{} K.ModeRestrict{}:
      True{}
    case K.ModeRestrict{} _:
      False{}
    case K.ModeRun{} K.ModeRun{}:
      True{}
    case K.ModeRun{} _:
      False{}

def implies(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      True{}

def event_time(e: K.ControlEvent) -> Nat:
  match e:
    case K.ClockTick{n}:
      n
    case K.Renew{n, _}:
      n
    case K.Classifier{n, _}:
      n
    case K.HardRule{n, _}:
      n
    case K.AgentRequest{n}:
      n
    case K.Reset{n, _, _}:
      n

def is_signed_reset(e: K.ControlEvent) -> Bool:
  match e:
    case K.Reset{_, s, _}:
      s
    case _:
      False{}

def secrets_gone(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeRun{}:
      False{}
    case _:
      True{}

def egress_gone(m: K.ContainmentMode) -> Bool:
  match m:
    case K.ModeFreeze{}:
      True{}
    case K.ModeKill{}:
      True{}
    case _:
      False{}

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
      {is_signed_reset(e) == False{} : Bool} & Unsigned(t)

# Fail closed: at or after the deadline, no event except a signed reset can
# leave the sandbox in Run or Restrict.
law fail_closed:
  for +cfg: K.KernelConfig
  for m: K.ContainmentMode
  for +d: Nat
  for e: K.ControlEvent
  for h: {Nat.is_lt(event_time(e), d) == False{} : Bool}
  for r: {is_signed_reset(e) == False{} : Bool}
  {is_live(mode_of(K.step(cfg, K.ControlState{m, d}, e))) == False{} : Bool}

# Tighten only: without a signed reset, no event lowers containment.
law tighten_only:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for e: K.ControlEvent
  for r: {is_signed_reset(e) == False{} : Bool}
  {rank_at_least(mode_of(K.step(cfg, K.ControlState{m, d}, e)), m) == True{} : Bool}

# A classifier can restrict or freeze, but cannot cause Kill by itself.
law classifier_cannot_kill:
  for +cfg: K.KernelConfig
  for m: K.ContainmentMode
  for +d: Nat
  for +now: Nat
  for level: K.SeverityLevel
  for k: {is_kill(m) == False{} : Bool}
  for h: {Nat.is_lt(now, d) == True{} : Bool}
  {is_kill(mode_of(K.step(cfg, K.ControlState{m, d}, K.Classifier{now, level}))) == False{} : Bool}

# Renewal cannot extend authority beyond now plus the maximum lease.
law renewal_is_bounded:
  for +cfg: K.KernelConfig
  for m: K.ContainmentMode
  for +d: Nat
  for +now: Nat
  for ttl: Nat
  {implies(is_live(mode_of(K.step(cfg, K.ControlState{m, d}, K.Renew{now, ttl}))),
    Nat.is_le(deadline_of(K.step(cfg, K.ControlState{m, d}, K.Renew{now, ttl})), Nat.add(now, K.max_lease_of(cfg)))) == True{} : Bool}

# A signed reset receives a bounded lease as well.
law reset_is_bounded:
  for +cfg: K.KernelConfig
  for m: K.ContainmentMode
  for +d: Nat
  for +now: Nat
  for ttl: Nat
  {Nat.is_le(deadline_of(K.step(cfg, K.ControlState{m, d}, K.Reset{now, True{}, ttl})), Nat.add(now, K.max_lease_of(cfg))) == True{} : Bool}

# Kill is absorbing until a signed reset.
law kill_needs_signed_reset:
  for +cfg: K.KernelConfig
  for +d: Nat
  for e: K.ControlEvent
  for r: {is_signed_reset(e) == False{} : Bool}
  {is_kill(mode_of(K.step(cfg, K.ControlState{K.ModeKill{}, d}, e))) == True{} : Bool}

# Secrets and egress are removed before processes are frozen or killed.
law authority_removed_first:
  for +cfg: K.KernelConfig
  for +m: K.ContainmentMode
  for +d: Nat
  for e: K.ControlEvent
  {stop_is_ordered(plan_of(K.step(cfg, K.ControlState{m, d}, e)), secrets_gone(m), egress_gone(m)) == True{} : Bool}

# Access always requires an explicit policy grant.
law access_requires_grant:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for k: K.AccessKind
  for +g: Bool
  for b: Bool
  {implies(K.authorize(now, K.ControlState{m, d}, K.AccessRequest{k, g, b}), g) == True{} : Bool}

# An expired lease denies access even before the controller handles a tick.
law expired_lease_denies:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for r: K.AccessRequest
  for h: {Nat.is_lt(now, d) == False{} : Bool}
  {K.authorize(now, K.ControlState{m, d}, r) == False{} : Bool}

# Freeze and Kill deny all access.
law stopped_denies:
  for +now: Nat
  for m: K.ContainmentMode
  for +d: Nat
  for r: K.AccessRequest
  for s: {is_stopped(m) == True{} : Bool}
  {K.authorize(now, K.ControlState{m, d}, r) == False{} : Bool}

# Restrict denies every secret request.
law restrict_denies_secrets:
  for +now: Nat
  for +d: Nat
  for g: Bool
  for b: Bool
  {K.authorize(now, K.ControlState{K.ModeRestrict{}, d}, K.AccessRequest{K.SecretAccess{}, g, b}) == False{} : Bool}

# No sequence of events without a signed reset can lower containment.
law no_sequence_lowers_containment:
  for +es: List<&2, K.ControlEvent>
  for +cfg: K.KernelConfig
  for +c: K.ControlState
  for u: Unsigned(es)
  {rank_at_least(state_mode(replay(es, cfg, c)), state_mode(c)) == True{} : Bool}

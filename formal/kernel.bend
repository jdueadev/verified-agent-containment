# Decision kernel for agent containment.
#
# This file is pure: it has no clock, network, process or file access. The
# controller supplies observed time and verified event facts, and applies the
# returned actions in order. Stale time is clamped to the latest observed time.

import Base

type ContainmentMode is Data:
  ModeRun{}
  ModeRestrict{}
  ModeHold{}
  ModeFreeze{}
  ModeKill{}

type SeverityLevel is Data:
  ToRestrict{}
  ToHold{}
  ToFreeze{}
  ToKill{}

type ContainAction is Data:
  RevokeSecrets{}
  NarrowEgress{}
  BlockEgress{}
  FreezeProcesses{}
  KillProcesses{}
  ThawProcesses{}
  RecreateSandbox{}
  RestoreAuthority{}

type ActionPlan is Data:
  NoMore{}
  Next{head: ContainAction, tail: ActionPlan}

type KernelConfig is Data:
  KernelConfig{max_lease: Nat, freeze_grace: Nat}

type ControlState is Data:
  ControlState{mode: ContainmentMode, deadline: Nat, clock: Nat, reset_counter: Nat}

type StepResult is Data:
  StepResult{control: ControlState, actions: ActionPlan}

type ControlEvent is Data:
  ClockTick{now: Nat}
  Renew{now: Nat, ttl: Nat}
  Classifier{now: Nat, level: SeverityLevel}
  HardRule{now: Nat, level: SeverityLevel}
  AgentRequest{now: Nat}
  Reset{now: Nat, signed: Bool, counter: Nat, from_mode: ContainmentMode, not_after: Nat, ttl: Nat}

type AccessKind is Data:
  EgressAccess{}
  SecretAccess{}

type AccessRequest is Data:
  AccessRequest{kind: AccessKind, granted: Bool, baseline: Bool}

def grace_of(c: KernelConfig) -> Nat:
  match c:
    case KernelConfig{_, g}:
      g

def max_lease_of(c: KernelConfig) -> Nat:
  match c:
    case KernelConfig{m, _}:
      m

def join(a: ActionPlan, b: ActionPlan) -> ActionPlan:
  match a:
    case NoMore{}:
      b
    case Next{h, t}:
      Next{h, join(t, b)}

def core_state(m: ContainmentMode, d: Nat) -> ControlState:
  ControlState{m, d, 0n, 0n}

def stop_plan() -> ActionPlan:
  Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, NoMore{}}}}

def kill_plan() -> ActionPlan:
  Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, Next{KillProcesses{}, NoMore{}}}}}

def raise(+cfg: KernelConfig, now: Nat, m: ContainmentMode, d: Nat, level: SeverityLevel) -> StepResult:
  match m level:
    case ModeRun{} ToRestrict{}:
      StepResult{core_state(ModeRestrict{}, d), Next{RevokeSecrets{}, Next{NarrowEgress{}, NoMore{}}}}
    case ModeRun{} ToHold{}:
      StepResult{core_state(ModeHold{}, 0n), stop_plan()}
    case ModeRun{} ToFreeze{}:
      StepResult{core_state(ModeFreeze{}, Nat.add(now, grace_of(cfg))), stop_plan()}
    case ModeRun{} ToKill{}:
      StepResult{core_state(ModeKill{}, 0n), kill_plan()}
    case ModeRestrict{} ToRestrict{}:
      StepResult{core_state(ModeRestrict{}, d), NoMore{}}
    case ModeRestrict{} ToHold{}:
      StepResult{core_state(ModeHold{}, 0n), stop_plan()}
    case ModeRestrict{} ToFreeze{}:
      StepResult{core_state(ModeFreeze{}, Nat.add(now, grace_of(cfg))), stop_plan()}
    case ModeRestrict{} ToKill{}:
      StepResult{core_state(ModeKill{}, 0n), kill_plan()}
    case ModeHold{} ToRestrict{}:
      StepResult{core_state(ModeHold{}, d), NoMore{}}
    case ModeHold{} ToHold{}:
      StepResult{core_state(ModeHold{}, d), NoMore{}}
    case ModeHold{} ToFreeze{}:
      StepResult{core_state(ModeFreeze{}, Nat.add(now, grace_of(cfg))), NoMore{}}
    case ModeHold{} ToKill{}:
      StepResult{core_state(ModeKill{}, 0n), Next{KillProcesses{}, NoMore{}}}
    case ModeFreeze{} ToKill{}:
      StepResult{core_state(ModeKill{}, 0n), Next{KillProcesses{}, NoMore{}}}
    case ModeFreeze{} ToRestrict{}:
      StepResult{core_state(ModeFreeze{}, d), NoMore{}}
    case ModeFreeze{} ToHold{}:
      StepResult{core_state(ModeFreeze{}, d), NoMore{}}
    case ModeFreeze{} ToFreeze{}:
      StepResult{core_state(ModeFreeze{}, d), NoMore{}}
    case ModeKill{} _:
      StepResult{core_state(ModeKill{}, d), NoMore{}}

def settle_with(+cfg: KernelConfig, in_time: Bool, now: Nat, m: ContainmentMode, +d: Nat) -> StepResult:
  match in_time:
    case True{}:
      StepResult{core_state(m, d), NoMore{}}
    case False{}:
      match m:
        case ModeRun{}:
          raise(cfg, now, ModeRun{}, d, ToFreeze{})
        case ModeRestrict{}:
          raise(cfg, now, ModeRestrict{}, d, ToFreeze{})
        case ModeHold{}:
          StepResult{core_state(ModeHold{}, d), NoMore{}}
        case ModeFreeze{}:
          raise(cfg, now, ModeFreeze{}, d, ToKill{})
        case ModeKill{}:
          StepResult{core_state(ModeKill{}, d), NoMore{}}

def settle(+cfg: KernelConfig, +now: Nat, m: ContainmentMode, +d: Nat) -> StepResult:
  settle_with(cfg, Nat.is_lt(now, d), now, m, d)

def cap_classifier(level: SeverityLevel) -> SeverityLevel:
  match level:
    case ToRestrict{}:
      ToRestrict{}
    case ToHold{}:
      ToHold{}
    case ToFreeze{}:
      ToHold{}
    case ToKill{}:
      ToHold{}

def prepend(a: ActionPlan, r: StepResult) -> StepResult:
  match r:
    case StepResult{c, b}:
      StepResult{c, join(a, b)}

def raise_after(+cfg: KernelConfig, now: Nat, level: SeverityLevel, o: StepResult) -> StepResult:
  match o:
    case StepResult{ControlState{m, d, _, _}, a}:
      prepend(a, raise(cfg, now, m, d, level))

def renew_control(+cfg: KernelConfig, +now: Nat, ttl: Nat, m: ContainmentMode, d: Nat) -> ControlState:
  match m:
    case ModeRun{}:
      core_state(ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg))))
    case ModeRestrict{}:
      core_state(ModeRestrict{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg))))
    case ModeHold{}:
      core_state(ModeHold{}, d)
    case ModeFreeze{}:
      core_state(ModeFreeze{}, d)
    case ModeKill{}:
      core_state(ModeKill{}, d)

def renew_after(+cfg: KernelConfig, +now: Nat, ttl: Nat, o: StepResult) -> StepResult:
  match o:
    case StepResult{ControlState{m, d, _, _}, a}:
      StepResult{renew_control(cfg, now, ttl, m, d), a}

def reset_actions(m: ContainmentMode) -> ActionPlan:
  match m:
    case ModeRun{}:
      NoMore{}
    case ModeRestrict{}:
      Next{RestoreAuthority{}, NoMore{}}
    case ModeHold{}:
      Next{ThawProcesses{}, Next{RestoreAuthority{}, NoMore{}}}
    case ModeFreeze{}:
      Next{ThawProcesses{}, Next{RestoreAuthority{}, NoMore{}}}
    case ModeKill{}:
      Next{RecreateSandbox{}, Next{RestoreAuthority{}, NoMore{}}}

def same_mode(a: ContainmentMode, b: ContainmentMode) -> Bool:
  match a b:
    case ModeRun{} ModeRun{}:
      True{}
    case ModeRestrict{} ModeRestrict{}:
      True{}
    case ModeHold{} ModeHold{}:
      True{}
    case ModeFreeze{} ModeFreeze{}:
      True{}
    case ModeKill{} ModeKill{}:
      True{}
    case _ _:
      False{}

def not_run(m: ContainmentMode) -> Bool:
  match m:
    case ModeRun{}:
      False{}
    case _:
      True{}

# A reset is accepted only when the host verified its signature and all signed
# fields match this kernel state: fresh counter, current mode, unexpired, not Run.
def reset_ok(+m: ContainmentMode, +counter: Nat, signed: Bool, +n: Nat, from_mode: ContainmentMode, +not_after: Nat, +at: Nat) -> Bool:
  match signed:
    case True{}:
      not_run(m) && (Nat.is_lt(counter, n) && (same_mode(from_mode, m) && Nat.is_le(at, not_after)))
    case False{}:
      False{}

def reset_with(+cfg: KernelConfig, accepted: Bool, +now: Nat, ttl: Nat, +m: ContainmentMode, +d: Nat) -> StepResult:
  match accepted:
    case True{}:
      StepResult{core_state(ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))), reset_actions(m)}
    case False{}:
      settle(cfg, now, m, d)

def event_time(e: ControlEvent) -> Nat:
  match e:
    case ClockTick{n}:
      n
    case Renew{n, _}:
      n
    case Classifier{n, _}:
      n
    case HardRule{n, _}:
      n
    case AgentRequest{n}:
      n
    case Reset{n, _, _, _, _, _}:
      n

def effective_with(stale: Bool, now: Nat, clock: Nat) -> Nat:
  match stale:
    case True{}:
      clock
    case False{}:
      now

def effective_time(+now: Nat, +clock: Nat) -> Nat:
  effective_with(Nat.is_lt(now, clock), now, clock)

def is_accepted_reset(+m: ContainmentMode, +counter: Nat, e: ControlEvent, +at: Nat) -> Bool:
  match e:
    case Reset{_, s, +n, f, +na, _}:
      reset_ok(m, counter, s, n, f, na, at)
    case _:
      False{}

def next_counter_with(accepted: Bool, old: Nat, n: Nat) -> Nat:
  match accepted:
    case True{}:
      n
    case False{}:
      old

def next_counter(+m: ContainmentMode, +counter: Nat, e: ControlEvent, +at: Nat) -> Nat:
  match e:
    case Reset{_, s, +n, f, +na, _}:
      next_counter_with(reset_ok(m, counter, s, n, f, na, at), counter, n)
    case _:
      counter

def seal(at: Nat, counter: Nat, r: StepResult) -> StepResult:
  match r:
    case StepResult{ControlState{m, d, _, _}, a}:
      StepResult{ControlState{m, d, at, counter}, a}

def core_step(+cfg: KernelConfig, +m: ContainmentMode, +d: Nat, +counter: Nat, e: ControlEvent, +at: Nat) -> StepResult:
  match e:
    case ClockTick{_}:
      settle(cfg, at, m, d)
    case AgentRequest{_}:
      settle(cfg, at, m, d)
    case Renew{_, ttl}:
      renew_after(cfg, at, ttl, settle(cfg, at, m, d))
    case Classifier{_, level}:
      raise_after(cfg, at, cap_classifier(level), settle(cfg, at, m, d))
    case HardRule{_, level}:
      raise_after(cfg, at, level, settle(cfg, at, m, d))
    case Reset{_, s, +n, f, +na, ttl}:
      reset_with(cfg, reset_ok(m, counter, s, n, f, na, at), at, ttl, m, d)

def step(+cfg: KernelConfig, c: ControlState, +e: ControlEvent) -> StepResult:
  match c:
    case ControlState{+m, +d, +clock, +counter}:
      +at = effective_time(event_time(e), clock)
      seal(at, next_counter(m, counter, e, at), core_step(cfg, m, d, counter, e, at))

def allow_mode(m: ContainmentMode, k: AccessKind, granted: Bool, baseline: Bool) -> Bool:
  match m:
    case ModeRun{}:
      granted
    case ModeRestrict{}:
      match k:
        case EgressAccess{}:
          granted && baseline
        case SecretAccess{}:
          False{}
    case ModeHold{}:
      False{}
    case ModeFreeze{}:
      False{}
    case ModeKill{}:
      False{}

def allow_with(in_time: Bool, m: ContainmentMode, r: AccessRequest) -> Bool:
  match in_time:
    case True{}:
      match r:
        case AccessRequest{k, g, b}:
          allow_mode(m, k, g, b)
    case False{}:
      False{}

def authorize(+now: Nat, c: ControlState, r: AccessRequest) -> Bool:
  match c:
    case ControlState{m, +d, +clock, _}:
      allow_with(Nat.is_lt(effective_time(now, clock), d), m, r)

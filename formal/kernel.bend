# Decision kernel for agent containment.
#
# This file is pure: it has no clock, network, process or file access. The
# controller supplies a monotonic time and verified event facts, and applies
# the returned actions in order.

import Base

type ContainmentMode is Data:
  ModeRun{}
  ModeRestrict{}
  ModeFreeze{}
  ModeKill{}

type SeverityLevel is Data:
  ToRestrict{}
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
  ControlState{mode: ContainmentMode, deadline: Nat}

type StepResult is Data:
  StepResult{control: ControlState, actions: ActionPlan}

type ControlEvent is Data:
  ClockTick{now: Nat}
  Renew{now: Nat, ttl: Nat}
  Classifier{now: Nat, level: SeverityLevel}
  HardRule{now: Nat, level: SeverityLevel}
  AgentRequest{now: Nat}
  Reset{now: Nat, signed: Bool, ttl: Nat}

type AccessKind is Data:
  EgressAccess{}
  SecretAccess{}

type AccessRequest is Data:
  AccessRequest{kind: AccessKind, granted: Bool, baseline: Bool}

def join(a: ActionPlan, b: ActionPlan) -> ActionPlan:
  match a:
    case NoMore{}:
      b
    case Next{h, t}:
      Next{h, join(t, b)}

def grace_of(c: KernelConfig) -> Nat:
  match c:
    case KernelConfig{_, g}:
      g

def max_lease_of(c: KernelConfig) -> Nat:
  match c:
    case KernelConfig{m, _}:
      m

def raise(+cfg: KernelConfig, now: Nat, m: ContainmentMode, d: Nat, level: SeverityLevel) -> StepResult:
  match m level:
    case ModeRun{} ToRestrict{}:
      StepResult{ControlState{ModeRestrict{}, d}, Next{RevokeSecrets{}, Next{NarrowEgress{}, NoMore{}}}}
    case ModeRun{} ToFreeze{}:
      StepResult{ControlState{ModeFreeze{}, Nat.add(now, grace_of(cfg))}, Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, NoMore{}}}}}
    case ModeRun{} ToKill{}:
      StepResult{ControlState{ModeKill{}, 0n}, Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, Next{KillProcesses{}, NoMore{}}}}}}
    case ModeRestrict{} ToRestrict{}:
      StepResult{ControlState{ModeRestrict{}, d}, NoMore{}}
    case ModeRestrict{} ToFreeze{}:
      StepResult{ControlState{ModeFreeze{}, Nat.add(now, grace_of(cfg))}, Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, NoMore{}}}}}
    case ModeRestrict{} ToKill{}:
      StepResult{ControlState{ModeKill{}, 0n}, Next{RevokeSecrets{}, Next{BlockEgress{}, Next{FreezeProcesses{}, Next{KillProcesses{}, NoMore{}}}}}}
    case ModeFreeze{} ToKill{}:
      StepResult{ControlState{ModeKill{}, 0n}, Next{KillProcesses{}, NoMore{}}}
    case ModeFreeze{} ToRestrict{}:
      StepResult{ControlState{ModeFreeze{}, d}, NoMore{}}
    case ModeFreeze{} ToFreeze{}:
      StepResult{ControlState{ModeFreeze{}, d}, NoMore{}}
    case ModeKill{} _:
      StepResult{ControlState{ModeKill{}, d}, NoMore{}}

def settle_with(+cfg: KernelConfig, in_time: Bool, now: Nat, m: ContainmentMode, +d: Nat) -> StepResult:
  match in_time:
    case True{}:
      StepResult{ControlState{m, d}, NoMore{}}
    case False{}:
      match m:
        case ModeRun{}:
          raise(cfg, now, ModeRun{}, d, ToFreeze{})
        case ModeRestrict{}:
          raise(cfg, now, ModeRestrict{}, d, ToFreeze{})
        case ModeFreeze{}:
          raise(cfg, now, ModeFreeze{}, d, ToKill{})
        case ModeKill{}:
          StepResult{ControlState{ModeKill{}, d}, NoMore{}}

def settle(+cfg: KernelConfig, +now: Nat, m: ContainmentMode, +d: Nat) -> StepResult:
  settle_with(cfg, Nat.is_lt(now, d), now, m, d)

def cap_classifier(level: SeverityLevel) -> SeverityLevel:
  match level:
    case ToRestrict{}:
      ToRestrict{}
    case ToFreeze{}:
      ToFreeze{}
    case ToKill{}:
      ToFreeze{}

def prepend(a: ActionPlan, r: StepResult) -> StepResult:
  match r:
    case StepResult{c, b}:
      StepResult{c, join(a, b)}

def raise_after(+cfg: KernelConfig, now: Nat, level: SeverityLevel, o: StepResult) -> StepResult:
  match o:
    case StepResult{ControlState{m, d}, a}:
      prepend(a, raise(cfg, now, m, d, level))

def renew_control(+cfg: KernelConfig, +now: Nat, ttl: Nat, m: ContainmentMode, d: Nat) -> ControlState:
  match m:
    case ModeRun{}:
      ControlState{ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))}
    case ModeRestrict{}:
      ControlState{ModeRestrict{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))}
    case ModeFreeze{}:
      ControlState{ModeFreeze{}, d}
    case ModeKill{}:
      ControlState{ModeKill{}, d}

def renew_after(+cfg: KernelConfig, +now: Nat, ttl: Nat, o: StepResult) -> StepResult:
  match o:
    case StepResult{ControlState{m, d}, a}:
      StepResult{renew_control(cfg, now, ttl, m, d), a}

def reset_actions(m: ContainmentMode) -> ActionPlan:
  match m:
    case ModeRun{}:
      NoMore{}
    case ModeRestrict{}:
      Next{RestoreAuthority{}, NoMore{}}
    case ModeFreeze{}:
      Next{ThawProcesses{}, Next{RestoreAuthority{}, NoMore{}}}
    case ModeKill{}:
      Next{RecreateSandbox{}, Next{RestoreAuthority{}, NoMore{}}}

def reset_with(+cfg: KernelConfig, signed: Bool, +now: Nat, ttl: Nat, m: ContainmentMode, +d: Nat) -> StepResult:
  match signed:
    case True{}:
      StepResult{ControlState{ModeRun{}, Nat.add(now, Nat.min(ttl, max_lease_of(cfg)))}, reset_actions(m)}
    case False{}:
      settle(cfg, now, m, d)

def step(+cfg: KernelConfig, c: ControlState, e: ControlEvent) -> StepResult:
  match c:
    case ControlState{m, +d}:
      match e:
        case ClockTick{+now}:
          settle(cfg, now, m, d)
        case AgentRequest{+now}:
          settle(cfg, now, m, d)
        case Renew{+now, ttl}:
          renew_after(cfg, now, ttl, settle(cfg, now, m, d))
        case Classifier{+now, level}:
          raise_after(cfg, now, cap_classifier(level), settle(cfg, now, m, d))
        case HardRule{+now, level}:
          raise_after(cfg, now, level, settle(cfg, now, m, d))
        case Reset{+now, signed, ttl}:
          reset_with(cfg, signed, now, ttl, m, d)

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

def authorize(now: Nat, c: ControlState, r: AccessRequest) -> Bool:
  match c:
    case ControlState{m, d}:
      allow_with(Nat.is_lt(now, d), m, r)

def demo_authorize() -> Bool:
  authorize(1n, ControlState{ModeRun{}, 3n}, AccessRequest{EgressAccess{}, True{}, False{}})

---------------------------- MODULE HostModel ----------------------------
(* Bounded model of the host wiring around the decision kernel for one sandbox:
   monitor renewals, the renewal health gate, the lease clock, System One
   (working, slow, stalled, crashed, or emitting any verdict), trace events from
   the agent, and the lag rules of design-spec section 5.

   The kernel is abstracted to what the Bend laws prove, for runs without a
   reset: modes only rise, a classifier signal is capped at Hold, an expired
   lease (now >= deadline) in Run or Restrict freezes, Hold ignores the lease,
   and Freeze escalates to Kill after its grace period.

   Renewal is its own action. The monitor tries at least every RenewEvery
   ticks (Tick is disabled once an attempt is that overdue), and an attempt
   succeeds only if the health gate passes. Expiry is checked against the
   deadline as it stood before the tick, so Ttl and RenewEvery matter.

   Claim C-MOD-1 is conditional, as in the claims table: the monitor is alive
   and renews on that schedule, the enforcer and tick heartbeats are fresh, no
   non-classifier hard rule at Freeze or above fires, and no actuator fails.

   tools/tla_check.sh runs four configurations:
   - HostModel: the v3 wiring. Must pass.
   - HostModelPre1: the health gate also requires a recent classifier
     heartbeat (the wiring before #1). Must violate ClassifierCannotForceStop.
   - HostModelLagUncapped: check_lag raises a hard rule instead of a classifier
     signal. Must violate ClassifierCannotForceStop.
   - HostModelNoMonitor: the monitor never renews. Must violate
     ClassifierCannotForceStop, which shows the lease clock is live and the
     good configuration does not pass vacuously. *)
EXTENDS Naturals

CONSTANTS
    ClassifierInHealth, \* TRUE: pre-#1 wiring (sabotage).
    LagUncapped,        \* TRUE: lag raised as a hard rule (sabotage).
    MonitorAlive,       \* FALSE: the monitor never renews (vacuity check).
    MaxTime,            \* ticks explored
    Ttl,                \* lease length in ticks
    RenewEvery,         \* the monitor attempts a renewal at least this often
    HealthLimit,        \* heartbeat age the health gate accepts
    LagLimit,           \* lag (ticks) that raises Classifier{Restrict}
    BlindLimit,         \* restricted ticks before a blind window may hold
    BlindEvents,        \* unscored events needed for a blind-window hold
    MaxPending,         \* bound on queued trace events
    Grace               \* Freeze grace in ticks

ASSUME RenewEvery < Ttl

Run == 0  Restrict == 1  Hold == 2  Freeze == 3  Kill == 4
Modes == Run..Kill
Max(a, b) == IF a >= b THEN a ELSE b
CapClassifier(level) == IF level > Hold THEN Hold ELSE level   \* law classifier_stop_enters_hold
Never == MaxTime + 1

VARIABLES
    now, mode, deadline, freezeAt,
    lastAttempt,  \* tick of the monitor's last renewal attempt
    cls,          \* "ok" | "slow" | "stalled" | "crashed"
    clsBeat,      \* last tick the classifier thread made progress
    pending,      \* unscored trace events (saturating)
    oldest,       \* enqueue tick of the oldest unscored event
    restrictedAt, \* tick lag first restricted, or Never
    unscored,     \* events since the lag episode opened (saturating)
    held,
    denied        \* 1 once any renewal was refused by the health gate

vars == <<now, mode, deadline, freezeAt, lastAttempt, cls, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>

Init ==
    /\ now = 0 /\ mode = Run /\ deadline = Ttl /\ freezeAt = Never /\ lastAttempt = 0
    /\ cls = "ok" /\ clsBeat = 0
    /\ pending = 0 /\ oldest = 0
    /\ restrictedAt = Never /\ unscored = 0 /\ held = FALSE
    /\ denied = 0

\* Raising the mode records when Freeze was entered, whichever path raised it.
FreezeTime(old, new, t) == IF old < Freeze /\ new >= Freeze THEN t ELSE freezeAt

Healthy == ~ClassifierInHealth \/ now - clsBeat <= HealthLimit

\* The monitor's renewal attempt. The kernel only extends a live lease
\* (law lease_only_renewal_extends; Hold and above ignore renewals).
Renew ==
    /\ MonitorAlive
    /\ lastAttempt' = now
    /\ IF mode \in {Run, Restrict} /\ now < deadline
          THEN /\ deadline' = IF Healthy THEN now + Ttl ELSE deadline
               /\ denied' = IF Healthy THEN denied ELSE 1
          ELSE UNCHANGED <<deadline, denied>>
    /\ UNCHANGED <<now, mode, freezeAt, cls, clsBeat, pending, oldest, restrictedAt, unscored, held>>

(* One tick of the controller's tick thread: the kernel's clock step, then
   check_lag. Time cannot pass while the monitor is overdue. *)
Tick ==
    /\ now < MaxTime
    /\ ~MonitorAlive \/ now - lastAttempt < RenewEvery
    /\ LET t == now + 1
           m1 == IF mode \in {Run, Restrict} /\ t >= deadline THEN Freeze
                 ELSE IF mode = Freeze /\ t >= freezeAt + Grace THEN Kill
                 ELSE mode
           lagging == pending > 0 /\ t - oldest > LagLimit
           startRestrict == lagging /\ restrictedAt = Never
           blind == /\ restrictedAt # Never /\ ~held /\ lagging
                    /\ t - restrictedAt > BlindLimit /\ unscored >= BlindEvents
           \* check_lag only emits Event::Classifier, so it is capped. The sabotage
           \* raises a blind window one step further, as a hard rule could.
           LagSignal(level) == IF LagUncapped THEN level ELSE CapClassifier(level)
           m2 == IF startRestrict THEN Max(m1, LagSignal(Restrict))
                 ELSE IF blind THEN Max(m1, LagSignal(IF LagUncapped THEN Freeze ELSE Hold))
                 ELSE m1
       IN /\ now' = t
          /\ mode' = m2
          /\ freezeAt' = FreezeTime(mode, m2, t)
          /\ restrictedAt' = IF startRestrict THEN t ELSE restrictedAt
          /\ unscored' = IF startRestrict THEN 0 ELSE unscored
          /\ held' = (held \/ blind)
          /\ clsBeat' = IF cls = "ok" THEN t ELSE clsBeat
          /\ UNCHANGED <<deadline, lastAttempt, cls, pending, oldest, denied>>

\* The agent produces a trace event or a gateway decision. Dropped events and
\* untraced decisions still count while an episode is open.
AgentEvent ==
    /\ mode < Freeze
    /\ pending' = IF pending < MaxPending THEN pending + 1 ELSE pending
    /\ oldest' = IF pending = 0 THEN now ELSE oldest
    \* Saturates: only "at least BlindEvents" matters, and it keeps the model finite.
    /\ unscored' = IF restrictedAt # Never /\ unscored < BlindEvents THEN unscored + 1 ELSE unscored
    /\ UNCHANGED <<now, mode, deadline, freezeAt, lastAttempt, cls, clsBeat, restrictedAt, held, denied>>

\* A working classifier consumes the queue.
Consume ==
    /\ cls = "ok" /\ pending > 0
    /\ pending' = 0
    /\ UNCHANGED <<now, mode, deadline, freezeAt, lastAttempt, cls, clsBeat, oldest, restrictedAt, unscored, held, denied>>

\* The classifier can degrade or recover at any time.
Degrade ==
    /\ \E s \in {"ok", "slow", "stalled", "crashed"} : cls' = s
    /\ UNCHANGED <<now, mode, deadline, freezeAt, lastAttempt, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>

\* A classifier may ask for any level. It arrives as Event::Classifier.
Verdict ==
    /\ cls \in {"ok", "slow"}
    /\ \E level \in Modes :
         /\ mode' = Max(mode, CapClassifier(level))
         /\ freezeAt' = FreezeTime(mode, Max(mode, CapClassifier(level)), now)
    /\ UNCHANGED <<now, deadline, lastAttempt, cls, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>

Next == Tick \/ Renew \/ AgentEvent \/ Consume \/ Degrade \/ Verdict

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime /\ mode \in Modes
    /\ pending \in 0..MaxPending /\ unscored \in 0..BlindEvents /\ held \in BOOLEAN

\* C-MOD-1: classifier behaviour cannot bring the sandbox to Freeze or Kill.
ClassifierCannotForceStop == mode <= Hold

\* The health gate never refuses the monitor because of the classifier.
RenewalNeverDeniedForClassifier == denied = 0

\* Modes only rise (no resets in this model).
ModesOnlyRise == [][mode' >= mode]_vars
=============================================================================

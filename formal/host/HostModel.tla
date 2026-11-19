---------------------------- MODULE HostModel ----------------------------
(* Bounded model of the host wiring around the decision kernel for one sandbox:
   monitor renewals, the renewal health gate, the lease clock, System One
   (working, slow, stalled, crashed, or malicious), trace events from the agent,
   and the lag rules of design-spec section 5.

   The kernel itself is abstracted to what the Bend laws prove: modes only rise
   without a reset, a classifier signal is capped at Hold, Freeze escalates to
   Kill after its grace period, and an expired lease in Run or Restrict freezes.

   Claim C-MOD-1. The property is conditional, as in the claims table: the
   monitor stays alive and renews every tick, the enforcer stays healthy, no
   non-classifier hard rule at Freeze or above fires, and no actuator fails.
   Under those conditions the only way to reach Freeze is through classifier
   behaviour, so ClassifierCannotForceStop says the classifier has no such way.

   ClassifierInHealth = TRUE models the wiring before #1, where the renewal
   health gate also required a recent classifier heartbeat. TLC must find a
   counterexample there; otherwise the model could not see the bug. LagUncapped is
   a second known-bad variant, for the lag path itself. tools/tla_check.sh runs all
   three configurations and fails unless the good one passes and both bad ones
   violate ClassifierCannotForceStop. *)
EXTENDS Naturals

CONSTANTS
    ClassifierInHealth, \* TRUE: pre-#1 wiring (sabotage). FALSE: v3 wiring.
    LagUncapped,        \* TRUE: sabotage where check_lag raises a hard rule, not a classifier signal.
    MaxTime,            \* ticks explored
    Ttl,                \* lease length in ticks
    HealthLimit,        \* heartbeat age the health gate accepts
    LagLimit,           \* lag (ticks) that raises Classifier{Restrict}
    BlindLimit,         \* restricted ticks before a blind window may hold
    BlindEvents,        \* unscored events needed for a blind-window hold
    MaxPending,         \* bound on queued trace events
    Grace               \* Freeze grace in ticks

Run == 0  Restrict == 1  Hold == 2  Freeze == 3  Kill == 4
Modes == Run..Kill
Max(a, b) == IF a >= b THEN a ELSE b
CapClassifier(level) == IF level > Hold THEN Hold ELSE level   \* law classifier_stop_enters_hold

VARIABLES
    now, mode, deadline, freezeAt,
    cls,          \* "ok" | "slow" | "stalled" | "crashed"
    clsBeat,      \* last tick the classifier thread made progress
    pending,      \* unscored trace events
    oldest,       \* enqueue tick of the oldest unscored event
    restrictedAt, \* tick lag first restricted, or MaxTime + 1 if never
    unscored,     \* events enqueued while lag-restricted
    held,
    denied        \* 1 once any renewal was refused by the health gate

vars == <<now, mode, deadline, freezeAt, cls, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>
Never == MaxTime + 1

Init ==
    /\ now = 0 /\ mode = Run /\ deadline = Ttl /\ freezeAt = Never
    /\ cls = "ok" /\ clsBeat = 0
    /\ pending = 0 /\ oldest = 0
    /\ restrictedAt = Never /\ unscored = 0 /\ held = FALSE
    /\ denied = 0

\* Raise the mode, never lower it (laws tighten_only, no_sequence_lowers_containment).
Raise(level) ==
    /\ mode' = Max(mode, level)
    /\ freezeAt' = IF mode < Freeze /\ Max(mode, level) = Freeze THEN now ELSE freezeAt

Healthy(t) == ~ClassifierInHealth \/ t - clsBeat <= HealthLimit

(* One tick: the monitor attempts a renewal, the controller ticks the kernel and
   runs check_lag. The enforcer and tick heartbeats are fresh by assumption. *)
Tick ==
    /\ now < MaxTime
    /\ LET t == now + 1
           renewed == mode \in {Run, Restrict} /\ Healthy(t)
           dl == IF renewed THEN t + Ttl ELSE deadline
           \* Kernel step for the clock: expiry freezes Run/Restrict; Freeze escalates.
           m1 == IF mode \in {Run, Restrict} /\ t > dl THEN Freeze
                 ELSE IF mode = Freeze /\ t >= freezeAt + Grace THEN Kill
                 ELSE mode
           f1 == IF mode < Freeze /\ m1 = Freeze THEN t ELSE freezeAt
           lagging == pending > 0 /\ t - oldest > LagLimit
           startRestrict == lagging /\ restrictedAt = Never
           blind == /\ restrictedAt # Never /\ ~held /\ lagging
                    /\ t - restrictedAt > BlindLimit /\ unscored >= BlindEvents
           \* check_lag only ever emits Event::Classifier, so it is capped. The sabotage
           \* escalates a blind window one step further, as a hard rule would allow.
           LagSignal(level) == IF LagUncapped THEN level ELSE CapClassifier(level)
           m2 == IF startRestrict THEN Max(m1, LagSignal(Restrict))
                 ELSE IF blind THEN Max(m1, LagSignal(IF LagUncapped THEN Freeze ELSE Hold))
                 ELSE m1
       IN /\ now' = t
          /\ deadline' = dl
          /\ denied' = IF mode \in {Run, Restrict} /\ ~Healthy(t) THEN 1 ELSE denied
          /\ mode' = m2
          /\ freezeAt' = f1
          /\ restrictedAt' = IF startRestrict THEN t ELSE restrictedAt
          /\ unscored' = IF startRestrict THEN 0 ELSE unscored
          /\ held' = (held \/ blind)
          /\ clsBeat' = IF cls = "ok" THEN t ELSE clsBeat
          /\ UNCHANGED <<cls, pending, oldest>>

\* The agent produces a trace event or a gateway decision. Dropped events and
\* untraced decisions still count while an episode is open.
AgentEvent ==
    /\ mode < Freeze
    /\ pending' = IF pending < MaxPending THEN pending + 1 ELSE pending
    /\ oldest' = IF pending = 0 THEN now ELSE oldest
    \* Saturates at BlindEvents: only "at least BlindEvents" matters, and it keeps the model finite.
    /\ unscored' = IF restrictedAt # Never /\ unscored < BlindEvents THEN unscored + 1 ELSE unscored
    /\ UNCHANGED <<now, mode, deadline, freezeAt, cls, clsBeat, restrictedAt, held, denied>>

\* A working classifier consumes the queue.
Consume ==
    /\ cls = "ok" /\ pending > 0
    /\ pending' = 0
    /\ UNCHANGED <<now, mode, deadline, freezeAt, cls, clsBeat, oldest, restrictedAt, unscored, held, denied>>

\* The classifier can degrade or recover at any time.
Degrade ==
    /\ \E s \in {"ok", "slow", "stalled", "crashed"} : cls' = s
    /\ UNCHANGED <<now, mode, deadline, freezeAt, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>

\* A malicious classifier may ask for any level. It arrives as Event::Classifier.
Verdict ==
    /\ cls \in {"ok", "slow"}
    /\ \E level \in Modes : Raise(CapClassifier(level))
    /\ UNCHANGED <<now, deadline, cls, clsBeat, pending, oldest, restrictedAt, unscored, held, denied>>

Next == Tick \/ AgentEvent \/ Consume \/ Degrade \/ Verdict

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime /\ mode \in Modes
    /\ pending \in 0..MaxPending /\ held \in BOOLEAN

\* C-MOD-1: classifier behaviour cannot bring the sandbox to Freeze or Kill.
ClassifierCannotForceStop == mode <= Hold

\* The monitor's renewals are never refused because of the classifier.
RenewalNeverDeniedForClassifier == denied = 0

\* C-MOD-1, second part: modes only rise (temporal; checked as a PROPERTY).
ModesOnlyRise == [][mode' >= mode]_vars
=============================================================================

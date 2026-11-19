---- MODULE HostModel_TTrace_1795116688 ----
EXTENDS HostModel, Sequences, TLCExt, Toolbox, Naturals, TLC

_expression ==
    LET HostModel_TEExpression == INSTANCE HostModel_TEExpression
    IN HostModel_TEExpression!expression
----

_trace ==
    LET HostModel_TETrace == INSTANCE HostModel_TETrace
    IN HostModel_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        unscored = (0)
        /\
        mode = (3)
        /\
        restrictedAt = (13)
        /\
        freezeAt = (4)
        /\
        held = (FALSE)
        /\
        oldest = (0)
        /\
        pending = (0)
        /\
        now = (4)
        /\
        clsBeat = (0)
        /\
        cls = ("slow")
        /\
        denied = (1)
        /\
        deadline = (3)
    )
----

_init ==
    /\ pending = _TETrace[1].pending
    /\ now = _TETrace[1].now
    /\ freezeAt = _TETrace[1].freezeAt
    /\ cls = _TETrace[1].cls
    /\ restrictedAt = _TETrace[1].restrictedAt
    /\ unscored = _TETrace[1].unscored
    /\ clsBeat = _TETrace[1].clsBeat
    /\ mode = _TETrace[1].mode
    /\ held = _TETrace[1].held
    /\ denied = _TETrace[1].denied
    /\ oldest = _TETrace[1].oldest
    /\ deadline = _TETrace[1].deadline
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ pending  = _TETrace[i].pending
        /\ pending' = _TETrace[j].pending
        /\ now  = _TETrace[i].now
        /\ now' = _TETrace[j].now
        /\ freezeAt  = _TETrace[i].freezeAt
        /\ freezeAt' = _TETrace[j].freezeAt
        /\ cls  = _TETrace[i].cls
        /\ cls' = _TETrace[j].cls
        /\ restrictedAt  = _TETrace[i].restrictedAt
        /\ restrictedAt' = _TETrace[j].restrictedAt
        /\ unscored  = _TETrace[i].unscored
        /\ unscored' = _TETrace[j].unscored
        /\ clsBeat  = _TETrace[i].clsBeat
        /\ clsBeat' = _TETrace[j].clsBeat
        /\ mode  = _TETrace[i].mode
        /\ mode' = _TETrace[j].mode
        /\ held  = _TETrace[i].held
        /\ held' = _TETrace[j].held
        /\ denied  = _TETrace[i].denied
        /\ denied' = _TETrace[j].denied
        /\ oldest  = _TETrace[i].oldest
        /\ oldest' = _TETrace[j].oldest
        /\ deadline  = _TETrace[i].deadline
        /\ deadline' = _TETrace[j].deadline

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("HostModel_TTrace_1795116688.json", _TETrace)

=============================================================================

 Note that you can extract this module `HostModel_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `HostModel_TEExpression.tla` file takes precedence 
  over the module `HostModel_TEExpression` below).

---- MODULE HostModel_TEExpression ----
EXTENDS HostModel, Sequences, TLCExt, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `HostModel` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        pending |-> pending
        ,now |-> now
        ,freezeAt |-> freezeAt
        ,cls |-> cls
        ,restrictedAt |-> restrictedAt
        ,unscored |-> unscored
        ,clsBeat |-> clsBeat
        ,mode |-> mode
        ,held |-> held
        ,denied |-> denied
        ,oldest |-> oldest
        ,deadline |-> deadline
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_pendingUnchanged |-> pending = pending'
        
        \* Format the `pending` variable as Json value.
        \* ,_pendingJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(pending)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_pendingModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].pending # _TETrace[s-1].pending
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE HostModel_TETrace ----
\*EXTENDS HostModel, IOUtils, TLC
\*
\*trace == IODeserialize("HostModel_TTrace_1795116688.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE HostModel_TETrace ----
EXTENDS HostModel, TLC

trace == 
    <<
    ([unscored |-> 0,mode |-> 0,restrictedAt |-> 13,freezeAt |-> 13,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 0,clsBeat |-> 0,cls |-> "ok",denied |-> 0,deadline |-> 2]),
    ([unscored |-> 0,mode |-> 0,restrictedAt |-> 13,freezeAt |-> 13,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 0,clsBeat |-> 0,cls |-> "slow",denied |-> 0,deadline |-> 2]),
    ([unscored |-> 0,mode |-> 0,restrictedAt |-> 13,freezeAt |-> 13,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 1,clsBeat |-> 0,cls |-> "slow",denied |-> 0,deadline |-> 3]),
    ([unscored |-> 0,mode |-> 0,restrictedAt |-> 13,freezeAt |-> 13,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 2,clsBeat |-> 0,cls |-> "slow",denied |-> 1,deadline |-> 3]),
    ([unscored |-> 0,mode |-> 0,restrictedAt |-> 13,freezeAt |-> 13,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 3,clsBeat |-> 0,cls |-> "slow",denied |-> 1,deadline |-> 3]),
    ([unscored |-> 0,mode |-> 3,restrictedAt |-> 13,freezeAt |-> 4,held |-> FALSE,oldest |-> 0,pending |-> 0,now |-> 4,clsBeat |-> 0,cls |-> "slow",denied |-> 1,deadline |-> 3])
    >>
----


=============================================================================

---- CONFIG HostModel_TTrace_1795116688 ----
CONSTANTS
    ClassifierInHealth = TRUE
    LagUncapped = FALSE
    MaxTime = 12
    Ttl = 2
    HealthLimit = 1
    LagLimit = 1
    BlindLimit = 3
    BlindEvents = 2
    MaxPending = 3
    Grace = 2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Thu Nov 19 19:31:29 UTC 2026
# Containment only tightens (K-MONO-01)

One guarantee, the law that proves it, one way to break it, and how to watch the
proof catch the break.

## Guarantee

The guarantee is claim **K-MONO-01**. The block below is generated from
[`claims.toml`](../../claims.toml) by `tools/cookbook_check.py`, which fails
`scripts/check.sh` if it drifts. Its status and full evidence list are in the
rendered table, [`docs/claims.md`](../claims.md).

<!-- cookbook:begin claim K-MONO-01 -->
> **K-MONO-01** · layer `bend-kernel` · Generated from [`claims.toml`](../../claims.toml); claims.toml wins. Status and evidence: [`docs/claims.md`](../claims.md).
>
> **Statement:** Without an accepted reset, no event or sequence lowers containment, changes the counter, or emits a recovery action.
>
> **Falsifier:** An unsigned sequence that ends in a lower mode, a changed counter, or a thaw/rebuild/restore action
<!-- cookbook:end claim K-MONO-01 -->

In brief: the kernel has a ladder of modes, and without an accepted signed reset
nothing moves it down that ladder.

## The law

Two of the claim's laws carry the core of it. They are quoted exactly from
`formal/LAWS.bend`:

<!-- cookbook:begin law tighten_only no_sequence_lowers_containment -->
Quoted from [`formal/LAWS.bend`, lines 264–281](../../formal/LAWS.bend#L264-L281):

```
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
```
<!-- cookbook:end law tighten_only no_sequence_lowers_containment -->

How to read them:

- `tighten_only` covers one step. Take any configuration, mode, deadline,
  clock, counter and event. If the event is not an accepted reset (`r`), the
  mode after `K.step` ranks at least as high as the mode before it.
- `no_sequence_lowers_containment` covers any sequence of unsigned events. It
  lifts the one-step law to `replay`, so no ordering of events, however long,
  ends lower than it started.

The proofs are terms in [`formal/PROOF.bend`](../../formal/PROOF.bend), for
example `Laws.tighten_only`. `bend PROOF.bend --check-only` type-checks them.

## Break it

[`tools/kernel_mutants.py`](../../tools/kernel_mutants.py) holds deliberately
unsafe edits to the kernel. One of the mutants listed under K-MONO-01 is
`restrict_can_lower`. It changes what the kernel does when it is already in
Restrict and is told to restrict again:

<!-- cookbook:begin mutant restrict_can_lower -->
Mutant `restrict_can_lower` from [`tools/kernel_mutants.py`](../../tools/kernel_mutants.py), applied to [`formal/kernel.bend`, lines 96–97](../../formal/kernel.bend#L96-L97):

```diff
     case ModeRestrict{} ToRestrict{}:
-      StepResult{core_state(ModeRestrict{}, d), NoMore{}}
+      StepResult{core_state(ModeRun{}, d), NoMore{}}
```
<!-- cookbook:end mutant restrict_can_lower -->

That one-word edit makes a repeated restrict drop the agent back to Run with its
authority restored. The mutated kernel still type-checks, but the proofs no
longer do. This is the failure from running `bend PROOF.bend --check-only` on
the mutant in a scratch copy of `formal/`, recorded once by hand while this page
was written, for #97:

```
SOME PROOFS FAIL
Error:
- expected : False{}
- observed : True{}
...
Location: tight_classifier
456 |             case K.ToRestrict{}:
457>|               {==}
```

`tight_classifier` is the helper lemma that `Laws.tighten_only` uses for
classifier events. It is the first proof to fail.

The mutation check runs every mutant on each run of `scripts/check.sh` and
writes the results to
[`results/mutation-check.json`](../../results/mutation-check.json). That file
is regenerated output, not a lab artifact. For this mutant, the committed copy
records `"rejected": true`, `"first_failure": "tight_classifier"` and
`"laws_violated": ["hard_rule_reaches_level", "tighten_only"]`. Read the file
at the commit you are looking at rather than trusting these quoted values.

## Run it

A snippet is a short event sequence with the results the guarantee requires.
`tools/cookbook_check.py` runs it on every `scripts/check.sh` run on three
kernels:

- the Bend kernel compiled to JavaScript, the model the proofs are about;
- the Rust kernel compiled to WebAssembly, the one that ships;
- the Bend kernel with `restrict_can_lower` applied.

It must pass on the first two, with identical results on every step, and fail
on the mutant at the step and field it names in `teeth`. This snippet is an
example that shows the law in action, not evidence: no claim cites it, and the
proof is still `formal/PROOF.bend`.

<!-- cookbook:begin snippet k-mono-01-repeat-restrict -->
Snippet [`snippets/k-mono-01-repeat-restrict.json`](snippets/k-mono-01-repeat-restrict.json), checked by [`tools/cookbook_check.py`](../../tools/cookbook_check.py) on every `scripts/check.sh` run.

```json
{
  "id": "k-mono-01-repeat-restrict",
  "claim": "K-MONO-01",
  "recipe": "k-mono-01",
  "title": "A second restrict does not lower containment",
  "note": "Restrict twice, then try a renewal. No step may move the mode below Restrict or hand back the secret.",
  "breaks": "mutant:restrict_can_lower",
  "teeth": {"step": 2, "field": "mode"},
  "config": {"max_lease": 2500, "freeze_grace": 4000},
  "start": {"mode": "run", "deadline": 2000, "clock": 0, "counter": 0},
  "steps": [
    {
      "note": "The classifier asks for Restrict: secrets are revoked and egress narrowed.",
      "event": {"type": "classifier", "now": 100, "level": "restrict"},
      "expect": {"mode": "restrict", "actions": ["revoke_secrets", "narrow_egress"]},
      "access": [{"kind": "secret", "granted": true, "baseline": true, "allowed": false}]
    },
    {
      "note": "It asks again. Already in Restrict, nothing changes and nothing is restored.",
      "event": {"type": "classifier", "now": 200, "level": "restrict"},
      "expect": {"mode": "restrict", "actions": []},
      "access": [{"kind": "secret", "granted": true, "baseline": true, "allowed": false}]
    },
    {
      "note": "A renewal extends the lease but is not a reset: the mode stays Restrict.",
      "event": {"type": "renew", "now": 300, "ttl": 2000},
      "expect": {"mode": "restrict", "actions": []},
      "access": [{"kind": "secret", "granted": true, "baseline": true, "allowed": false}]
    }
  ]
}
```
<!-- cookbook:transcript -->
Output of the Bend kernel (`target/generated/kernel.mjs`), recorded by `cookbook_check.py --write`. `scripts/check.sh` reruns the snippet and fails if this output, the Rust kernel's, or the mutant's result changes.

```text
step 1: classifier restrict at 100 -> restrict, deadline 2000, clock 100, counter 0, actions: revoke_secrets, narrow_egress; secret denied
step 2: classifier restrict at 200 -> restrict, deadline 2000, clock 200, counter 0, actions: none; secret denied
step 3: renew ttl 2000 at 300 -> restrict, deadline 2300, clock 300, counter 0, actions: none; secret denied
on mutant restrict_can_lower:
  step 2: mode expected "restrict", observed "run"
  step 2: access.0 expected false, observed true
  step 3: mode expected "restrict", observed "run"
  step 3: access.0 expected false, observed true
```
<!-- cookbook:end snippet k-mono-01-repeat-restrict -->

## Reproduce

These commands need no root. They are the same ones `scripts/check.sh` runs
(see [`docs/verification.md`](../verification.md) for the Bend setup).

```bash
# 1. The proofs hold on the real kernel.
(cd formal && bend PROOF.bend --check-only)      # ALL PROOFS CHECK

# 2. Break it in a scratch copy, never in your working tree.
tmp=$(mktemp -d) && cp -r formal "$tmp/" && cd "$tmp/formal"
python3 - <<'EOF'
p = "kernel.bend"; s = open(p).read()
old = "case ModeRestrict{} ToRestrict{}:\n      StepResult{core_state(ModeRestrict{}, d), NoMore{}}"
assert s.count(old) == 1, "kernel changed; this recipe is out of date"
open(p, "w").write(s.replace(old, old.replace("core_state(ModeRestrict{}, d)", "core_state(ModeRun{}, d)")))
EOF
bend kernel.bend --check-only                    # the mutant is still a valid kernel
bend PROOF.bend --check-only                     # SOME PROOFS FAIL ... Location: tight_classifier

# 3. Every mutant at once, as CI does it.
scripts/check.sh                                 # includes tools/mutation_check.py
```

## What this does not prove

- **Only the Bend model.** K-MONO-01 is a `bend-kernel` claim. Whether the Rust
  kernel that ships behaves the same way is claim R-DIFF-01 (the differential
  check). Whether the Linux host actually enforces a mode is a set of host
  claims (H-*, C-*) with their own lab evidence.
- **Not the reset path.** The law assumes the event is *not* an accepted reset.
  What makes a reset acceptable (signature, counter, expiry, mode binding) is
  claim K-RST-01.
- **Mutants show the laws have teeth, not that they are complete.** A rejected
  mutant shows the proof catches that particular defect. It says nothing about
  defects nobody wrote a mutant for.
- **The generated blocks are checked; the prose is not.** `tools/cookbook_check.py`
  regenerates the claim block, the law quote, the mutant diff and the snippet
  output and fails `scripts/check.sh` if any differs. The explanations around
  them are checked by review only. If they disagree with the sources, the
  sources win; please open an issue.
- **A snippet shows one run, not all runs.** It passes on the real kernels and
  fails on one mutant. The law covers every configuration and every sequence;
  the snippet covers three steps.

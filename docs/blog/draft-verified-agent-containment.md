---
title: "A kill switch the classifier can't pull: verified containment for local agents"
status: DRAFT — not for publication until Jon signs off
date: 2026-11
---

> **Draft.** Facts and numbers are from the repository at the commit in the footer. Check them before publishing.

I wanted to give an agent backed by a local model real tools: a workspace, HTTP, a credential. I also wanted to know exactly what happens when something goes wrong. Most agent sandboxes answer that with one big switch, either "the agent can do things" or "it can't". When a classifier decides something looks bad, it flips that switch.

That design puts a lot of trust in the classifier. A classifier that is wrong, fooled or simply slow can kill your agent. A classifier that is quiet keeps it running. **Verified agent containment** is a research prototype that takes that trust apart.

## The idea in one paragraph

An agent's authority is a **lease**. A separate monitor keeps renewing it (the lease lasts about 200 ms) only while enforcement is confirmed healthy. If the lease isn't renewed, the agent loses its authority: no secrets, no network, then frozen, then killed. Containment has five levels, Run, Restrict, Hold, Freeze and Kill, and only a signed reset can bring the agent back down. A small **pure decision kernel** decides every move between levels. Its laws are machine-proved for the kernel's formal model (written in Bend and rechecked in Lean). The Rust kernel that actually runs is differential-tested against that model, not proved: 77,364 generated transitions, 0 mismatches.

## What the classifier is allowed to do

The local classifier, called System One, watches what the agent does: denied-request bursts, probes for secrets, prompt-injection markers, odd write volumes. It can only **tighten**:
- **Hold is its ceiling.** At most, a classifier verdict moves the agent to Hold. Hold stops the agent and waits for a person; the kernel gives it no timer. A live run still tears itself down after its configured maximum (900 s by default), failing closed.
- **It cannot reach Freeze or Kill.** A verdict cannot renew a lease, grant access, start the kill timer or cause Kill. A fooled classifier can pause your agent but never destroy it.
- **Verdicts based only on agent text stop at Restrict.** If a verdict rests only on text the agent produced (an injection marker, for instance), it can only restrict. This cap relies on System One labelling its own reasons honestly. A fooled classifier that calls an injection a denied-request burst can still reach Hold, but never Freeze.
- **Liveness can't stall the lease.** A slow classifier restricts and a blind one holds, but neither can block lease renewal. An earlier version got this wrong: a stalled classifier blocked renewals and the agent was killed. A TLA+ model now has to find that bug in the old wiring before its passing result counts.
- **System One is confined.** It runs as a separate process with its own uid and cgroup, an empty network namespace, no sockets, no fork and no signals. It reaches the controller only through a pipe and a socket it inherits.

## How I know it works (and where I don't)

Every guarantee is a row in a claims table. Each row lists its evidence, the observation that would falsify it, and the platforms it was checked on. A checker fails the build if a row's evidence goes stale. Highlights:

| Evidence | Result |
|---|---|
| Kernel laws (Bend model, rechecked in Lean) | 36 proved |
| Deliberately broken kernels | 46/46 rejected, each with a counterexample input |
| Linux attack suite (2-core VM) | 176/176 runs; 29/29 sabotaged controllers caught. Cgroup limits were waived on this VM; the same build passed on WSL2 with limits in force |
| Bytes admitted after a stop committed | 0 |
| TLA+ host model (bounded: one sandbox, 12 ticks, no resets) | the property holds, and the model finds the bugs it is meant to find |
| Live agent suite (real harness, scripted model) | 11/11; 8/8 sabotaged controllers caught |
| Red team, real local model (Qwen3.5-9B on llama.cpp, WSL2) | 0 leaks in 6 tasks; clean task completed; 3 injections resisted, 2 ended restricted |

"Sabotaged controllers" is the part I care about most. For every protection, there's a build with that protection removed, and the test suite **must fail** against it. A test that can't fail proves nothing.

The things it doesn't do yet are listed just as plainly:
- **Resets** are signed with a key file that only root can read, not a hardware key. Any root process on the host counts as the operator. A reset signed before a controller restart could be replayed after it.
- **The model server** runs outside the sandbox.
- **Allowed writes:** an agent talked into writing to a host you allowed, within budget, will succeed.
- **One real model so far:** a red team of Qwen3.5-9B on WSL2 had no leaks in six tasks, and its first run found a real false-alarm bug (slow local inference looked like classifier lag), now fixed. System One's false-alarm rate on clean work is still unmeasured beyond that.
- **Untested paths:** the CONNECT proxy path is untested. The HUD's access checks were tested by hand only.

## Try to break it

The prototype runs a real agent backed by a model you serve locally (Ollama, llama.cpp, LM Studio, vLLM):
- **A live HUD** shows each decision as it happens.
- **A red-team kit** runs injection tasks against your model and scores each one by what reached the servers, not by what the model claims it did.

![The HUD after a scripted agent kept trying to send notes to a host outside its policy. Denied requests restricted it, and System One's DENIED_BURST rule then moved it to Hold, where it waits for a person.](hud-hold.png)

*Scripted model, not a real one: the agent is told to POST notes to 203.0.113.7, a host outside its policy. Every attempt is denied. System One escalates from Restrict to Hold, and the controller revokes secrets, blocks egress and freezes the processes.*

[Scorecard from a real local model, to add after the first run]

The quickstart for WSL2 with Ollama is in the repository: `docs/quickstart-local-model.md`.

## What's next

- **Reset v3:** a hardware-backed key, and signatures bound to the instance and the boot.
- **A sandboxed model server.**
- **More edges:** larger models, nastier injection packs, and the false-positive rate on clean work.

---

*Repository: [link to add if made public]. Numbers as of commit [hash to add].*

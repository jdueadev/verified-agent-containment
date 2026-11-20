# Quickstart: a local model in the containment (WSL2 + Ollama)

> **On native Linux?** Skip Step 1 and run the commands directly inside a disposable Linux VM or container.

This runs a real agent, backed by a model you serve on your own machine, inside the containment. You watch it on the HUD and red-team it. It takes about 20 minutes. Everything runs as root in a **disposable** WSL2 distribution: the controller needs namespaces, cgroups and seccomp.

The model server runs **outside** the sandbox (v1). The agent never talks to it directly. Every inference call goes through the gateway, which counts tokens per lease and refuses calls that carry the workspace canary.

**Shortcut on Windows:** [`scripts/lab/`](../scripts/lab/README.md) automates this whole guide with one double-click: a throwaway distro, both suites, llama.cpp and the red team.

## 1. A disposable WSL2 distribution

In PowerShell on Windows:

```powershell
wsl --install -d Ubuntu-24.04 --name containment-lab   # or import any recent distro
wsl -d containment-lab
```

Inside it:

```bash
sudo apt-get update && sudo apt-get install -y build-essential git curl python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
git clone https://github.com/jdueadev/verified-agent-containment.git
cd verified-agent-containment
cargo build --release -p containment-host
```

## 2. Check the sandbox works (30 seconds)

Before downloading a model, run the red-team kit with a scripted model that obeys every injection. It runs six tasks, each in a real sandbox, and writes a scorecard:

```bash
sudo target/release/containment-lab redteam --scripted
```

Every task should end without `LEAK`, and the command exits 0. If it fails because the host has no delegated cgroup controllers, see the troubleshooting notes at the bottom. Before trusting this host with a real model, run the full gate in [Optional: verify your host](#optional-verify-your-host-full-gate).

## 3. Serve a model

Use a model that supports tool calls through Ollama's OpenAI-compatible endpoint, such as `qwen2.5:7b-instruct` or `llama3.1:8b`. The harness has been red-teamed with one real model so far (Qwen3.5-9B Q6_K on llama.cpp, `results/wsl2/lab-9ffd69a/` and `results/wsl2/lab-f88aeef/`). Turn thinking off for thinking models: the red-team policy caps each call at 1024 tokens.

**Option A: Ollama inside the same WSL2 distribution** (simplest):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct
# The endpoint is http://127.0.0.1:11434/v1/chat/completions
```

**Option B: Ollama on Windows** (uses the Windows GPU directly):
- With mirrored networking (`networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`, then `wsl --shutdown`), `127.0.0.1:11434` inside WSL2 reaches Windows. Use the same endpoint as option A.
- Without mirrored networking, Ollama has to listen on an address WSL2 can reach. Ollama's API has no authentication, so never leave it on `0.0.0.0` with your firewall open:
  1. Set `OLLAMA_HOST` to the Windows address on the WSL virtual adapter. That is the gateway in `ip route show default` inside WSL2, for example `OLLAMA_HOST=172.20.80.1`.
  2. Or, if you must bind `0.0.0.0`, add an inbound Windows Firewall rule for port 11434 that allows only the WSL subnet.
  3. Put that IP literal in the policy. The gateway refuses host *names* that resolve to private addresses, but accepts private IP literals you list.

  Mirrored mode is simpler and keeps Ollama on loopback.

## 4. Watch a live run on the HUD

Set the model endpoint and name in the `[model]` section of `examples/live/policy.toml`. For Ollama with `qwen2.5:7b-instruct` (option A, or option B with mirrored networking), it reads:

```toml
[model]
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
name = "qwen2.5:7b-instruct"
max_tokens_per_call = 1024
token_budget = 200000
```

For option B without mirrored networking, replace `127.0.0.1` with the Windows IP literal from step 3. Then:

```bash
sudo FIXTURE_TOKEN=dummy target/release/containment-lab live \
  --policy examples/live/policy.toml \
  --task "Read notes.txt and write a one-line summary to summary.md" \
  --hud 8787
```

The terminal prints a private link such as `http://127.0.0.1:8787/<random>/`. Open it in a Windows browser; WSL2 forwards localhost.
- The HUD shows the mode ladder, counters and every gateway decision, System One verdict and mode change.
- It is read-only. Anyone who has the link can read the run's events, including any Windows process once WSL2 forwards the port, so keep the link to yourself.

To steer the run from another terminal:

```bash
R=/run/verified-agent-containment/live-...          # printed when the run starts
sudo target/release/containment-lab ctl --run $R status
sudo target/release/containment-lab ctl --run $R reset hold    # sign a reset out of Hold
sudo target/release/containment-lab ctl --run $R stop
```

Each run saves `report.json` and `transcript.jsonl` under `results/live/`.

## 5. Red-team the model

```bash
sudo target/release/containment-lab redteam \
  --model-endpoint http://127.0.0.1:11434/v1/chat/completions --model qwen2.5:7b-instruct
```

This runs six tasks, one clean and five with hidden instructions, each in a fresh sandbox. It writes `results/redteam/<model>-<time>/scorecard.md`. `LEAK` must never appear, and if it does the command exits non-zero. Every other outcome tells you what the model tried and how far it got. To try your own attacks, add tasks to `redteam/pack.toml`.

Good edges to poke at:
- **Policy-allowed writes:** the containment does not stop writes to allowed hosts within budget (claim L-OPS-01). Try tightening budgets and watch the outcome change.
- **System One's rules:** look at what DENIED_BURST, SECRET_PROBE and INJECTION_MARKER catch, and what slips under them.
- **Larger or more obedient models:** compare their scorecards against the clean task's false-positive rate.

## What this does not protect yet

- **Resets:** they are signed with a per-run key file that only root can read, not a hardware key, because reset v3 is not built. A reset proves that root on this host approved it, nothing more.
- **The model server:** it is not sandboxed (v1). A compromised model server is outside this design's boundary.
- **Data the policy allows out:** data the agent sends to an allowed write host within budget leaves.
- **The VM boundary:** the sandbox is a Linux namespace and seccomp sandbox inside a VM you control. It is not a VM boundary of its own.

Every guarantee and its evidence is a row in [`claims.toml`](../claims.toml), rendered as [`claims.md`](claims.md). Gateway rules, HUD access checks and every red-team outcome are in [`reference.md`](reference.md).

## Optional: verify your host (full gate)

The controller is trusted only if both suites pass on this machine **without** `--allow-missing-limits`. Run them before attaching a model you care about. `scripts/run-wsl2.sh` checks the kernel and cgroup setup first.

```bash
sudo target/release/containment-lab attack-suite --repeat 30 --out results/wsl2/attack-suite-$(hostname)-$(git rev-parse --short HEAD).json
sudo target/release/containment-lab live-suite --out results/wsl2/live-suite-$(hostname)-$(git rev-parse --short HEAD).json
```

The expected results:
- attack suite: every run passes and every sabotaged controller is caught (verified on WSL2 at f88aeef: 176/176, 29/29);
- live suite: 11/11 runs and 8/8 sabotaged controllers (verified on a Linux VM and on WSL2 at f88aeef).

Please keep the JSON either way. If either suite fails, stop there and keep its JSON and log. A failure on WSL2 is a finding: the first WSL2 run found the memfd interop escape that way.

## Troubleshooting

- **Result files owned by root:** the commands run under sudo, so files they write in your checkout end up owned by root. Run `sudo chown -R $USER results` afterwards.
- **Missing cgroup limits:** on hosts without delegated cgroup v2 pids, memory and CPU controllers, the commands refuse to run System One without its limits. `--allow-missing-limits` runs anyway and records the waiver in the results; don't use it for the full gate.

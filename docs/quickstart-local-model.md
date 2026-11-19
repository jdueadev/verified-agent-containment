# Quickstart: a local model in the containment (WSL2 + Ollama)

This runs a real agent, backed by a model you serve on your own machine, inside the containment. You watch it on the HUD and red-team it. It takes about 20 minutes. Everything runs as root in a **disposable** WSL2 distribution: the controller needs namespaces, cgroups and seccomp.

The model server runs **outside** the sandbox (v1). The agent never talks to it directly. Every inference call goes through the gateway, which counts tokens per lease and refuses calls that carry the workspace canary.

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
git clone git@github.com:jdueadev/verified-agent-containment.git   # or https with a token
cd verified-agent-containment
cargo build --release -p containment-host
```

## 2. Pass the gate before attaching a model

The controller is trusted only if both suites pass on this machine **without** `--allow-missing-limits`:

```bash
sudo target/release/containment-lab attack-suite --repeat 30 --out results/wsl2/attack-suite-$(hostname)-$(git rev-parse --short HEAD).json
sudo target/release/containment-lab live-suite --out results/wsl2/live-suite-$(hostname)-$(git rev-parse --short HEAD).json
```

The expected results:
- attack suite: every run passes and every sabotaged controller is caught;
- live suite: 10/10 runs and 7/7 sabotaged controllers.

If either suite fails, stop there and keep its JSON and log. A failure on WSL2 is a finding: the first WSL2 run found the memfd interop escape that way.

## 3. Serve a model

Use a model that supports tool calls. `qwen2.5:7b-instruct` and `llama3.1:8b` both work with Ollama's OpenAI-compatible endpoint.

**Option A: Ollama inside the same WSL2 distribution** (simplest):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct
# The endpoint is http://127.0.0.1:11434/v1/chat/completions
```

**Option B: Ollama on Windows** (uses the Windows GPU directly):
- With mirrored networking (`networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`, then `wsl --shutdown`), `127.0.0.1:11434` inside WSL2 reaches Windows. Use the same endpoint as option A.
- Without mirrored networking, use the Windows host's IP literal, which is the gateway in `ip route show default`, and set `OLLAMA_HOST=0.0.0.0` on Windows. That exposes Ollama to your LAN, so restrict it with Windows Firewall. Put the IP literal in the policy. The gateway refuses host *names* that resolve to private addresses, but accepts private IP literals you list.

## 4. Watch a live run on the HUD

Edit `examples/live/policy.toml` to set the model endpoint and name, then:

```bash
sudo FIXTURE_TOKEN=dummy target/release/containment-lab live \
  --policy examples/live/policy.toml \
  --task "Read notes.txt and write a one-line summary to summary.md" \
  --hud 8787
```

The terminal prints a private link such as `http://127.0.0.1:8787/<random>/`. Open it in a Windows browser; WSL2 forwards localhost.
- The HUD shows the mode ladder, counters and every gateway decision, System One verdict and mode change.
- It is read-only. Anyone who has the link can read the run's events, so keep the link to yourself.

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

Every guarantee and its evidence is a row in `claims.toml`, rendered as `docs/claims.md`.

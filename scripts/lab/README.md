# Containment lab for Windows (WSL2)

One double-click does the following:
- runs both test suites without waivers in a **throwaway WSL2 distro**;
- serves a local model with **llama.cpp**;
- **red-teams** that model inside the containment.

No admin rights are needed, and the PC is kept awake while the lab runs.

## Set up the lab folder

Make a folder, for example `H:\containment-lab`, containing:

| file | from |
|---|---|
| `run-lab.cmd`, `lab.ps1`, `lab-inside.sh` | this directory |
| `repo.bundle` | `git bundle create repo.bundle --all` in a checkout, or pass `-Repo <path>` |

Then double-click `run-lab.cmd`, or run it from a terminal with options:

```powershell
.\run-lab.cmd                     # everything; the distro is removed at the end
.\run-lab.cmd -Keep               # keep the distro: wsl -d containment-lab-<date>
.\run-lab.cmd -Only suites        # suites only, no model (a model is never attached without passing suites)
.\run-lab.cmd -Model unsloth/Qwen3.5-9B-GGUF:Qwen3.5-9B-Q6_K.gguf   # any GGUF on Hugging Face, as repo:file
```

## What it does

| step | where | what |
|---|---|---|
| 1 | Windows | Checks WSL 2, and records GPU, RAM and free disk space. |
| 2 | Windows | Gets an Ubuntu 24.04 WSL root filesystem. It uses one cached in `images\`, then downloads from cloud-images.ubuntu.com, then falls back to `wsl --install Ubuntu-24.04`. |
| 3 | Windows | Imports `containment-lab-<date>` into `distros\` and enables systemd. Root is the default user. **Windows interop is disabled**, so a process in the distro cannot start Windows programs (the first WSL2 run found that escape). |
| 4 | distro | Installs build tools, Rust and, when an NVIDIA GPU is visible, the CUDA toolkit from NVIDIA's WSL repository. RTX 50-series cards need 12.8 or newer. Builds the project. |
| 5 | distro | Runs the attack suite (repeat 30) and the live suite **with cgroup limits enforced**. If either fails, no model is attached (claim C-SYS-1). |
| 6 | distro | Builds `llama-server` with CUDA (falling back to CPU), downloads the model into `models\` and checks its SHA-256 against Hugging Face. Serves it on 127.0.0.1 with `--jinja` and thinking off, checks that it returns native tool calls, and runs `containment-lab redteam` against it. |

## Where things go

- `logs\status.txt`: one line per step, appended by each run. Read it to see where a run is.
- `logs\lab-<stamp>.log` and `logs\inside-<stamp>.log`: full logs.
- `results\<stamp>\`:
  - `environment.txt`
  - `attack-suite.json`
  - `live-suite.json`
  - `llama-server.log`
  - `tool-call-check.json`
  - `redteam\scorecard.md`

The exit code is 0 only if every step passed and no red-team task leaked.

## Notes

- **The model server runs outside the sandbox** (v1). The sandboxed agent reaches it only through the gateway, which counts tokens per lease and refuses calls that carry the workspace canary.
- **Downloads are cached.** Models stay in `models\` and the root filesystem in `images\`, so a rerun downloads nothing.
- **Hardening inside the distro:**
  - drives are mounted root-only (umask 077);
  - Windows interop is checked again before a model is attached;
  - llama-server needs a per-run API key, because WSL forwards localhost to Windows. The gateway sends the key and the agent never sees it.
- **Pins in `pins.env`:**
  - The llama.cpp commit and the model's SHA-256 are pinned there.
  - A value that is still empty is trusted once and written to `results\<stamp>\pins.env` for review and commit.
  - Rust comes from Ubuntu's `rustup` package.
- **Thinking is off.** The red-team policy caps each model call at 1024 tokens, and a thinking model would spend them reasoning instead of calling tools.

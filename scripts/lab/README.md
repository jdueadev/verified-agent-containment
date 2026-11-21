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
| 4 | distro | Installs build tools, rustup and, when an NVIDIA GPU is visible, the CUDA toolkit from NVIDIA's WSL repository. RTX 50-series cards need 12.8 or newer. Installs the Rust toolchain that `rust-toolchain.toml` pins, refuses to build on anything else (see Notes), records the toolchain, then builds the project. |
| 5 | distro | Runs the attack suite (repeat 30) and the live suite **with cgroup limits enforced**. If either fails, no model is attached (claim C-SYS-1). |
| 6 | distro | Builds `llama-server` with CUDA (falling back to CPU), downloads the model into `models\` and checks its SHA-256 against the pin in `pins.env` (the Hub's value must agree; an unpinned model is trusted once). Serves it on 127.0.0.1 with `--jinja` and thinking off, checks that it returns native tool calls, and runs `containment-lab redteam` against it. |

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
  - Windows interop is checked again before a model is attached, by running `whoami.exe`; the check fails closed if there is nothing to probe or the probe hangs, and its result goes to `environment.txt`. With `-Only suites` it is skipped, since no model is attached;
  - llama-server needs a per-run API key, because WSL forwards localhost to Windows. It is passed in a 0600 file, not on the command line. The gateway sends the key and the agent never sees it. `/health` and `/v1/models` stay unauthenticated in llama.cpp, so Windows processes can see which model is loaded.
- **Pins in `pins.env`:**
  - The llama.cpp commit and the model's SHA-256 are pinned there. Model pins are keyed by repository and file. A kept llama.cpp build is reused only at the pinned commit.
  - A value that is still empty is trusted once and written to `results\<stamp>\pins.env` for review and commit.
  - rustup comes from Ubuntu's `rustup` package. The Rust version is not in `pins.env`: it is the `channel` in `rust-toolchain.toml`, the same pin CI uses.
- **The toolchain is checked before the build (#68).** If any of these checks fails, the run stops and nothing is built:
  - there is no legacy `rust-toolchain` or `.cargo/config` file in the clone;
  - `HOME` is `/root`, and no build override is set, even to an empty value. An override is any variable matching `BUILD_OVERRIDES` in `lab-inside.sh`: `RUSTC*`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_ENCODED_*`, `RUSTUP_*`, `CARGO_HOME`, `CARGO_INCREMENTAL`, `CARGO_BUILD_*`, `CARGO_TARGET_*`, `CARGO_PROFILE_*`, `CARGO_UNSTABLE_*`, `CARGO_SOURCE_*`, `CARGO_REGISTRIES_*`, `CARGO_REGISTRY_*`, the `cc` crate's `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `ARFLAGS` and `LDFLAGS` (bare, `HOST_`/`TARGET_` prefixed, or with a target suffix), `RANLIB`, `RANLIBFLAGS`, `CXXSTDLIB`, `CRATE_CC_NO_DEFAULTS`, gcc's `COMPILER_PATH`, `GCC_EXEC_PREFIX`, `LIBRARY_PATH`, `CPATH`, `C_INCLUDE_PATH` and `CPLUS_INCLUDE_PATH`, and every dynamic-loader `LD_*` variable (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`: rustc loads its compiler driver at run time). Names are read from the process environment, so a name bash cannot hold as a variable (`CFLAGS_x86_64-unknown-linux-gnu`) is still seen. Only names are reported;
  - no cargo config exists above the clone. With `CARGO_HOME` refused and `HOME=/root`, cargo looks only in `/root/.cargo` and `/.cargo`, and both are checked;
  - `rustc` and `cargo` on `PATH` are rustup's proxies;
  - `tools/pins_check.py drift --rustc --cargo` passes: both tools exit 0, and the first line of each `--version` is exactly `rustc <channel> (...)` and `cargo <channel> (...)`;
  - `rustup which` places both in the installed `/root/.rustup/toolchains/<channel>-<host>` toolchain. That rules out a linked toolchain, because rustup refuses to link one under a release name.

  `environment.txt` then records, before the binary hashes:
  - the full commit id and the channel;
  - rustup's version and its active toolchain;
  - the `rustc` path and every line of `rustc -vV`;
  - `cargo -V`;
  - the SHA-256 of `Cargo.lock` and of `.cargo/config.toml`;
  - the C compiler, the linker, and the `gcc`, `binutils` and `libc6-dev` packages.

  After the build, `rustc -vV`, `cargo -V` and both paths must still succeed and must not have changed. That is a tripwire, not proof: code that runs during the build could fake them. The record is written by the same script that builds the binaries, so whether it is authentic is review-only (INV-1). The binary SHA-256s remain the strongest link to the evidence.
- **Thinking is off.** The red-team policy caps each model call at 1024 tokens, and a thinking model would spend them reasoning instead of calling tools.

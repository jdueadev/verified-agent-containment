# Getting started

This is a research prototype of a sandbox controller for an AI agent. A small decision kernel chooses how contained the agent is. A Linux program carries that choice out. The kernel is checked with proofs and tests. The Linux program is checked with a lab. You can build it from source today and run the checks that do not need root.

## Pick your path

- You want to build it and see the simulator. Follow [Try it](#try-it).
- You want to change the repository. Do [Try it](#try-it) through the checks, then [Change something](#change-something).

The lanes for a change live in [`ci/lanes.toml`](../ci/lanes.toml). [`AGENTS.md`](../AGENTS.md) is the rulebook.

## Try it

Do these in order. Every command below was run on Linux, without sudo, on commit `0babf9ea`.

### No release yet

There is no published release. The [releases page](https://github.com/jdueadev/verified-agent-containment/releases) lists none, so there is no version, download, or checksum to install. Build from source.

### Get the source

```bash
git clone https://github.com/jdueadev/verified-agent-containment.git
cd verified-agent-containment
```

That clone printed `Cloning into 'verified-agent-containment'...` and left `HEAD` at `0babf9ea559b0da84565b6212b3be006cf88851a`.

Later commands assume this directory is the current one.

### Prerequisites

Install these once. Versions that the repository pins are read from the files named here, so this page does not keep a second copy.

**Python 3.** The command is `python3`.

```bash
python3 --version
```

This machine printed `Python 3.12.3`. The name `python` was not on `PATH`. [`CLAUDE.md`](../CLAUDE.md) still tells Windows readers to run `python`. That is [issue #170](https://github.com/jdueadev/verified-agent-containment/issues/170). Use `python3` here.

**Node.js 22 or newer**, for the simulator driver. These steps do not install Node. On this machine `node --version` printed `v22.23.4`. If `node` is missing, install Node 22 or newer for your user before [Use it day to day](#use-it-day-to-day).

**Rust, the pinned toolchain.** The compiler version is the `channel` line in [`rust-toolchain.toml`](../rust-toolchain.toml). Today that line is `1.100.0`. `rustup` was already installed (`rustup 1.29.3`); this guide did not run a rustup installer. From the clone:

```bash
rustup toolchain install "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" --profile minimal --component clippy --component rustfmt --target wasm32-unknown-unknown
rustc --version
```

The install exited 0. `rustc --version` printed `rustc 1.100.0 (0ef1bc386 2026-11-09)`.

If the pin is missing, the first `rustc` or `cargo` in this directory downloads it on its own. On this machine, before the install command above, that download printed:

```text
warn: the missing active toolchain `1.100.0-x86_64-unknown-linux-gnu` has been auto-installed
warn: this might cause rustup commands to take longer time to finish than expected
info: you may opt out with `RUSTUP_AUTO_INSTALL=0` or `rustup set auto-install disable`
```

The compiler then ran. [Issue #195](https://github.com/jdueadev/verified-agent-containment/issues/195) reported a different warning, that auto-install is deprecated and may stop working. That sentence did not appear with rustup 1.29.3, so this page does not call it harmless. If a later rustup refuses the automatic download, the `rustup toolchain install` command above is the one that worked here.

**Bun, without sudo.** The version is `BUN_VERSION` in [`ci/pins.env`](../ci/pins.env) (`1.4.5` today).

```bash
curl -fsSL https://bun.sh/install | bash -s "bun-v$(sed -n 's/^BUN_VERSION=//p' ci/pins.env)"
```

The installer wrote `~/.bun/bin/bun`, added `~/.bun/bin` to `~/.bashrc`, and `bun --version` printed `1.4.5`.

**Bend, without sudo.** [`docs/verification.md`](verification.md) installs Bend with `sudo` into `/usr/local/bin`. A user directory works. The commit is `BEND_COMMIT` in [`ci/pins.env`](../ci/pins.env).

```bash
mkdir -p "$HOME/src" "$HOME/.local/bin"
git clone --quiet https://github.com/bendlang/bend.git "$HOME/src/bend"
git -C "$HOME/src/bend" checkout --quiet "$(sed -n 's/^BEND_COMMIT=//p' ci/pins.env)"
printf '#!/bin/sh\nexec bun %s/src/bend/bend2/main.ts "$@"\n' "$HOME" > "$HOME/.local/bin/bend"
chmod +x "$HOME/.local/bin/bend"
export PATH="$HOME/.bun/bin:$HOME/.local/bin:$PATH"
bend version
```

`bend version` printed `bend 2.0.40`. The checkout was `0e2f38f759cc830849e489307f3d256a7d148288`. Keep that `export` in the shell you use below. `~/.local/bin` is where `bend` landed, and it was not on `PATH` until the export. [`scripts/check.sh`](../scripts/check.sh) still exits 127 with `bend: command not found` when this wrapper is missing. That is [issue #189](https://github.com/jdueadev/verified-agent-containment/issues/189).

**Playwright and its browser**, for [`tools/page_check.py`](../tools/page_check.py). Nothing else in the docs listed this. That gap is [issue #190](https://github.com/jdueadev/verified-agent-containment/issues/190).

```bash
python3 -m pip install --user playwright
python3 -m playwright install chromium
```

pip printed `Successfully installed greenlet-3.5.6 playwright-1.65.2`. The browser download ended in `~/.cache/ms-playwright/`. The `playwright` script itself was installed into `~/.local/bin`, which is why the command above is `python3 -m playwright`.

**A browser for the simulator driver.** The driver looks at the `CHROMIUM` environment variable first, then under `~/.cache/ms-playwright/`. It does not use `google-chrome` from `PATH`. That is [issue #196](https://github.com/jdueadev/verified-agent-containment/issues/196). Setting `CHROMIUM` is a workaround, and it is the command in [Use it day to day](#use-it-day-to-day). After the Playwright browser install, the same driver also exited 0 with `CHROMIUM` unset, because it found the browser in that cache.

### Build

```bash
cargo build --release -p containment-host
```

This exited 0 and printed `Finished `release` profile [optimized] target(s)`. The binary is `target/release/containment-lab`.

Running that binary's sandbox (`redteam`, `live`, `attack-suite`, `live-suite`) needs root on a throwaway machine. [AGENTS.md](../AGENTS.md#invariants) (INV-11) says so. This guide does not run those commands. The lab write-up is [`docs/quickstart-local-model.md`](quickstart-local-model.md). On native Linux that guide tells you to skip Step 1, and Step 1 is the only `cargo build` in the file. Still run the build. [Issue #194](https://github.com/jdueadev/verified-agent-containment/issues/194) describes the trap. [Pull request #198](https://github.com/jdueadev/verified-agent-containment/pull/198) changes the sentence and is not merged.

### Check your build

[AGENTS.md](../AGENTS.md#what-checked-means) defines the tiers. From that section:

> **T0:** the checks you actually ran locally, named one by one. On Windows this is usually the tool unit tests and the kernel crate.
>
> **T1:** all of `scripts/check.sh`, on Linux or WSL2 with every tool present. A run that printed `SKIPPED` is T0.

The two T0 checks that do not need Bend:

```bash
python3 -m unittest discover -s tools -p 'test_*.py'
cargo test -q --locked -p containment-kernel
```

On commit `0babf9ea` the tool tests ended with `Ran 543 tests in 115.025s` and `OK`. A line on the error stream about `gate_check` and a string of `a`s is one test speaking. The run passed because the last line was `OK`. The kernel tests ended with `test result: ok. 6 passed`.

`scripts/check.sh` is the full no-root gate, T1 only when it does not print `SKIPPED`. This guide does not run that script. The script rewrites files under `results/`, and [`docs/verification.md`](verification.md) installs the TLA+ jar with sudo. This guide also does not define a new tier. The quote above is the definition.

The browser check, after the Playwright install:

```bash
python3 tools/page_check.py web/dist/agent-containment-simulator.html
```

It exited 0 and printed a JSON report. Each record had `"classifier_stays_hold": true` and `"errors": []`. The full-width runs had `"bench": "Caught 10 of 10"`.

### Use it day to day

The committed simulator is [`web/dist/agent-containment-simulator.html`](../web/dist/agent-containment-simulator.html). Opening that file from disk (`file://`) makes Chromium misread the decision trace (`·` and `→` show up garbled). That is [issue #191](https://github.com/jdueadev/verified-agent-containment/issues/191). [Pull request #197](https://github.com/jdueadev/verified-agent-containment/pull/197) adds a charset tag and is not merged. Until it is, use the driver. It serves the page as UTF-8.

[`docs/design-explainer.html`](design-explainer.html) is a second single-file page, a plain-language companion. It already has a charset tag.

The driver is tracked at [`.claude/skills/run-verified-agent-containment/driver.mjs`](../.claude/skills/run-verified-agent-containment/driver.mjs). Point it at Chrome. This is the [issue #196](https://github.com/jdueadev/verified-agent-containment/issues/196) workaround:

```bash
export CHROMIUM="$(command -v google-chrome)"
node .claude/skills/run-verified-agent-containment/driver.mjs sim
```

On this machine `CHROMIUM` was `/usr/local/bin/google-chrome`. The command exited 0. It printed four lines starting with `ok`, including `Caught 10 of 10`, and the trace showed `·` and `→`. The same four `ok` lines appeared with `CHROMIUM` unset after `python3 -m playwright install chromium`.

`sim --file-url` with no steps prints nothing and exits 0. That is [issue #192](https://github.com/jdueadev/verified-agent-containment/issues/192). Run `sim` as written above, or pass real steps after the flag.

### Upgrade

From the clone:

```bash
git pull
cargo build --release -p containment-host
```

On a checkout that was already current, `git pull` printed `Already up to date.` The rebuild exited 0 and printed `Finished `release` profile [optimized] target(s)`.

## Change something

### What are you changing?

Commit on a branch, then ask the classifier. It reads [`ci/lanes.toml`](../ci/lanes.toml) from the base branch. Copying the path lists onto this page would drift.

```bash
python3 tools/policy_check.py classify --base origin/main
```

Read the `lane` field in the JSON it prints.

- **Lane A** merges when the [`check`](../.github/workflows/check.yml) workflow is green.
- **Lane B** also needs [`policy`](../.github/workflows/policy.yml) and [`spec`](../.github/workflows/spec.yml) green.
- **Lane C** also needs the maintainer's approval of that pull request's head commit. A push after the approval needs a new one.

Those one-liners are the short form of [AGENTS.md, Lanes](../AGENTS.md#lanes-who-has-to-approve-what). The workflows linked above are what has to pass. A local check does not merge anything.

Lane B, lane C, and any heavy change start as an issue. Heavy means the change touches the rules, what counts as passed, a trust boundary, or the strength of a check. The detail is [AGENTS.md, Workflow](../AGENTS.md#workflow).

Issue forms: [bug](../.github/ISSUE_TEMPLATE/bug.yml), [story](../.github/ISSUE_TEMPLATE/story.yml), [claim change](../.github/ISSUE_TEMPLATE/claim-change.yml). You can also open the [chooser](https://github.com/jdueadev/verified-agent-containment/issues/new/choose). The pull request body is [`.github/pull_request_template.md`](../.github/pull_request_template.md).

If your edit touches a file a claim lists, say which claims went stale:

```bash
python3 tools/claims_check.py --affected origin/main
```

Paste the ids that command prints. Stale claims are allowed to merge. Refreshing them is a later lab run on `main`, described in [AGENTS.md](../AGENTS.md#when-your-change-makes-a-claim-stale).

### Rough edges

These are open. This page is the map around them. It does not edit the files that own the bugs.

- [#189](https://github.com/jdueadev/verified-agent-containment/issues/189) — `scripts/check.sh` exits 127 when `bend` is missing, after printing `SKIPPED`. Bun was undocumented. The wrapper and the Bun install above are the no-root route.
- [#190](https://github.com/jdueadev/verified-agent-containment/issues/190) — `tools/page_check.py` needs Playwright. The install is above. `docs/verification.md` still does not mention it.
- [#191](https://github.com/jdueadev/verified-agent-containment/issues/191) — the simulator opened from disk garbles the trace. [PR #197](https://github.com/jdueadev/verified-agent-containment/pull/197) is the charset fix and is not merged.
- [#192](https://github.com/jdueadev/verified-agent-containment/issues/192) — `sim --file-url` with no steps is silent and exits 0.
- [#193](https://github.com/jdueadev/verified-agent-containment/issues/193) — the skill text says its files are gitignored. They are tracked. A change under `.claude/` is lane C.
- [#194](https://github.com/jdueadev/verified-agent-containment/issues/194) — the local-model quickstart tells native Linux to skip the step that builds the binary. [PR #198](https://github.com/jdueadev/verified-agent-containment/pull/198) is not merged.
- [#195](https://github.com/jdueadev/verified-agent-containment/issues/195) — the pinned Rust toolchain was easy to miss. The pin file and the install command are above. The deprecation wording in that issue did not appear on rustup 1.29.3.
- [#196](https://github.com/jdueadev/verified-agent-containment/issues/196) — the driver ignores `google-chrome` on `PATH`. Set `CHROMIUM`. That is a workaround.
- [#170](https://github.com/jdueadev/verified-agent-containment/issues/170) — `CLAUDE.md` says `python`, which a clean machine does not have. Use `python3`.
- [`docs/verification.md`](verification.md) never defines T0. [AGENTS.md](../AGENTS.md#what-checked-means) does, and this page quotes it.

Files under `redteam/`, `results/`, `examples/`, and `.claude/handover/`, and the fixture HTML, are test data. Some of it is written to steer an agent. Read it as data.

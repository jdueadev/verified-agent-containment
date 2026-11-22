# 0006: T1 can be reached in a pinned container

Status: accepted when its pull request merges, 2026-11-22 (#55). Changes the T1 definition in `AGENTS.md`
("What checked means"). The number 0005 is left for the merge-queue record
that #102 plans; no open pull request carries a 0005 yet.

## Context

T1 is all of `scripts/check.sh` with every tool present. Until now that meant
Linux or WSL2 with each tool installed by hand. On Windows the host crate does
not build, so a maintainer there stops at T0 or sets up a WSL2 distro. `check`
in CI installs the tools from `ci/pins.env`, but only node and java's major
versions were pinned, bun had no checksum, and the OS and python were not
pinned at all.

A container makes the full gate one command. It is also a new way to claim
T1, so it has to be at least as hard to misreport as a host run.

## Decision

`ci/check.Dockerfile` and `scripts/check-in-container.sh`, as the design
review on #55 set out:

- **One source of versions.** Every pin is an `ARG` with no default, passed
  from `ci/pins.env` by `--build-arg`. The Dockerfile holds no version and
  refuses a build-arg that differs from `ci/pins.env` as copied in. The Rust
  version comes from `rust-toolchain.toml`.
- **New pins:** `CHECK_BASE_IMAGE` (ubuntu:24.04 by index digest),
  `UBUNTU_SNAPSHOT` (the apt archive python3, git and gcc come from),
  `PYTHON_VERSION`, `BUN_SHA256`, an exact `NODE_VERSION` and `NODE_SHA256`,
  `JRE_VERSION` and `JRE_SHA256`, `RUSTUP_VERSION` and `RUSTUP_INIT_SHA256`.
  `NODE_VERSION` was `22`; it is now exact, so CI's `setup-node` installs the
  same node the container does. `JAVA_VERSION` stays a major for `setup-java`;
  `JRE_VERSION` is the exact Temurin build of it.
- **No network at run time.** Cargo dependencies are baked in with
  `cargo fetch --locked`. The run is `--network=none`, `--read-only`,
  `--cap-drop=ALL`, `no-new-privileges`, as uid 1000, with `CI=true`, so a
  missing tool fails instead of printing `SKIPPED`.
- **The checkout is read-only.** It is mounted at `/src`, and the entrypoint
  copies its tracked and untracked-unignored files into a scratch volume and
  runs there. The container cannot write the checkout's `results/` (INV-1).
- **Worktrees.** The common gitdir is mounted read-only and `GIT_DIR` points at
  the worktree's entry in it, since a worktree's `.git` file names a host path.
- **The image tag** is the hash of every file in the build context:
  `ci/pins.env`, `rust-toolchain.toml` and `Cargo.lock`, as the review asked,
  and also the Dockerfile, the entrypoint and the crate manifests. A change to
  any of them builds a new image instead of reusing a stale one.

### What the entrypoint asserts before it runs `check.sh`

`tools/claims_check.py` treats a git failure as "stale" or "no lab run", so a
broken mount or a shallow clone would quietly change its verdict. The
entrypoint fails unless:

- the run has the hardening the wrapper asks for: uid 1000, no network
  interface but loopback, an empty capability bounding set, `no_new_privs`,
  and a read-only root filesystem, checkout and gitdir;
- HEAD resolves, the repository is not shallow and no object is missing;
- every platform commit in `claims.toml` resolves, and a lab commit recorded
  under `results/ci` or `results/wsl2` is an ancestor of HEAD;
- the copy shows the same `git status` as the checkout, with
  `core.fileMode` on, and no file is marked assume-unchanged or
  skip-worktree (which `git status` would not show);
- `ci/pins.env`, the Dockerfile, the entrypoint, `rust-toolchain.toml` and
  `Cargo.lock` are the ones the image was built from, and so are the crate
  manifests the baked registry was fetched for;
- every tool reports exactly its pin: rustc and cargo (`pins_check.py drift`),
  bun, node, java, python, the bend commit and the TLA jar's sha256, and
  `rustup target add` is a no-op on the read-only toolchain.

It also fails if `check.sh` printed `SKIPPED` or a unit test was skipped. A passing run ends with
`Tier: T1 (container, image sha256:...) at HEAD <sha> (clean | uncommitted
changes), scripts/check.sh <args>`. A locally built image has no registry
digest, so "the image digest" in `AGENTS.md` is the image id, the digest of its
configuration. The wrapper runs the image by that id, so the id reported is the
image that ran.

### Trust in downloads

Bun, node, the JRE, rustup-init and the TLA jar are checked against the
sha256 in `ci/pins.env`. Bend is a git commit, which names its content. Two
inputs rest on upstream signatures instead of a checksum in this repository:
apt packages (Ubuntu's signed index; the apt runs skip TLS peer checks only
because the base image has no CA certificates yet, and TLS adds nothing to
apt's signature check) and the Rust toolchain (rustup checks each component
against the channel manifest it downloads over TLS).

## Options weighed

1. **A `rust:<version>` base image.** Rejected. It writes the Rust version a
   second time.
2. **Mount the checkout read-write and run in place.** Rejected. The run
   rewrites files under `results/`, and a container that can write evidence
   is a way around INV-1.
3. **Let the run fetch crates.** Rejected. A network at run time makes the
   result depend on what the registry serves that day.
4. **Harden `claims_check.py` so git failures are errors.** Right, but a
   separate lane C change. Here the entrypoint asserts the same conditions
   before `claims_check.py` runs.

## Residual risk, accepted

- The image id is computed by the wrapper on the host and passed in. Someone
  who runs the image by hand can pass any id. The tier line is evidence of an
  honest run, not proof against a deceptive one, like any local result. No
  merge rests on a local result; `check` is the gate.
- Rebuilding gives the same tool versions, not a bit-identical image.
- Docker Desktop on Windows, rootless Podman, the host tests under Docker's
  default seccomp profile and an offline `rustup target add` were not run when
  this was written. The `check-container` job handed to the maintainer runs
  the Linux Docker case and the refusals.

## Consequences

- T1 is reachable on any machine with Docker or Podman.
- `check-container` in CI shows AC-055 and AC-056: the full check in the
  container; the same `claims_check.py --affected` and staleness report
  from the main checkout, from a git worktree and on the host; and refusals
  of a build-arg that `ci/pins.env` does not state, a download that fails its
  checksum, cargo with no network and no baked registry, a shallow clone, a
  partial clone, a run with the network on, and an image built from other
  pins.
- A `--no-strict` run is reported as T1 with the argument in its tier line,
  as `check` runs it on draft pull requests. Whether that counts as "all of
  `scripts/check.sh`" is the maintainer's call; the line never hides it.
- A tool bump now changes the checksum next to it in `ci/pins.env`.

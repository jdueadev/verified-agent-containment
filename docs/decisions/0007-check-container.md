# 0007: T1 can be reached in a pinned container

Status: accepted when its pull request merges, 2026-11-22 (#55). Changes the T1 definition in `AGENTS.md`
("What checked means"). Proposed as 0006; renumbered when 0006 went to the
shared Claude Code configuration record (#169).

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
  `CHECK_UBUNTU_SNAPSHOT` (the apt archive python3, git and gcc come from),
  the `CHECK_INRELEASE_*` sha256 of each suite's signed index in it,
  `CHECK_PYTHON_VERSION`, `CHECK_BUN_SHA256`, an exact `NODE_VERSION` and
  `CHECK_NODE_SHA256`, `CHECK_JRE_VERSION` and `CHECK_JRE_SHA256`,
  `CHECK_RUSTUP_VERSION` and `CHECK_RUSTUP_INIT_SHA256`. The container-only
  keys start with `CHECK_` because the workflows load the whole file into
  their environment, where a name such as `RUSTUP_VERSION` would steer
  rustup. `NODE_VERSION` was `22`; it is now exact, so CI's `setup-node`
  installs the same node the container does. `JAVA_VERSION` stays a major for
  `setup-java`; `CHECK_JRE_VERSION` is the exact Temurin build of it.
- **No network at run time.** Cargo dependencies are baked in with
  `cargo fetch --locked`. The run is `--network=none`, `--read-only`,
  `--cap-drop=ALL`, `no-new-privileges`, as uid 1000, with `CI=true`, so a
  missing tool fails instead of printing `SKIPPED`.
- **The checkout is read-only.** It is mounted at `/src`, and the entrypoint
  copies its tracked and untracked-unignored files into a scratch volume and
  runs there. The container cannot write the checkout's `results/` (INV-1).
- **Worktrees.** The common gitdir is mounted read-only and `GIT_DIR` points at
  the worktree's entry in it, since a worktree's `.git` file names a host path.
- **The context hash** is the hash of every file in the build context:
  `ci/pins.env`, `rust-toolchain.toml` and `Cargo.lock`, as the review asked,
  and also the Dockerfile, the entrypoint, `Cargo.toml` and the crate
  manifests. It names the image (`vac-check:<first 16 hex>`), so a change to
  any of them builds a new image instead of reusing a stale one. Unlike the
  image id, a reviewer can recompute it from a commit: the sha256 of the
  sorted `sha256sum ./<path>` lines of those files.

### What the entrypoint asserts before it runs `check.sh`

`tools/claims_check.py` treats a git failure as "stale" or "no lab run", so a
broken mount or a shallow clone would quietly change its verdict. The
entrypoint fails unless:

- the run has the hardening the wrapper asks for: uid 1000, no network
  interface but loopback, an empty capability bounding set, `no_new_privs`,
  and a read-only root filesystem, checkout and gitdir, read from
  `/proc/self/mountinfo` (a write probe would prove nothing, since uid 1000
  cannot write a root-owned directory anyway, and would leave a file in a
  writable checkout);
- HEAD resolves, the repository is not shallow and no object is missing;
- every platform commit in `claims.toml` resolves, and a lab commit recorded
  under `results/ci` or `results/wsl2` is an ancestor of HEAD;
- the copy shows the same `git status` as the checkout, with
  `core.fileMode` on, and no file is marked assume-unchanged or
  skip-worktree (which `git status` would not show);
- the image's inputs (the context files and `scripts/check-in-container.sh`)
  are committed, and the image was built from exactly those files: the build
  context baked into it matches them file by file, and its hash is the one
  the wrapper built;
- every tool reports exactly its pin: rustc and cargo (`pins_check.py drift`),
  bun, node, java, python, the bend commit and the TLA jar's sha256, and
  `rustup target add` is a no-op on the read-only toolchain.

It also fails if `check.sh` printed `SKIPPED` or a unit test was skipped. A
passing run on a clean tree ends with `Tier: T1 (container, image
sha256:..., context <hash>) at HEAD <sha> (clean), scripts/check.sh <args>`.
On a tree with uncommitted changes it says that `check.sh` passed and prints
no tier line: the result is not one for HEAD. A locally built image has no
registry digest, so `AGENTS.md` asks for the image id and the context hash
that line prints. The image id is the digest of the image's configuration
(`sha256:...`), and the wrapper runs the image by that id.

These checks catch accidents and honest mistakes: a stale image, a broken
mount, a missing flag. They are not a defence against a hostile image, which
can print any line it likes, or against a hand-made `docker run` that passes
a false `CHECK_IMAGE_ID`.

### Trust in downloads

Bun, node, the JRE, rustup-init and the TLA jar are checked against the
sha256 in `ci/pins.env`. Bend is a git commit, which names its content. Two
inputs rest on upstream signatures instead of a checksum in this repository:
apt packages (Ubuntu's signed index) and the Rust toolchain (rustup checks each component
against the channel manifest it downloads over TLS).

The apt runs skip TLS peer checks, because the base image has no CA
certificates yet. A signature alone would then accept an older signed
snapshot replayed in place of the pinned one: noble's InRelease carries no
`Valid-Until`. So the sha256 of each suite's InRelease in the snapshot is
pinned too (`CHECK_INRELEASE_*`), and the build refuses any other index.
That pins every package, dependencies included. Pinning package versions
instead would pin only the packages the Dockerfile names.

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
  this was written. On Docker Desktop, bind mounts show files as 0755 or 0777,
  so with `core.fileMode` forced on the tree never reads as clean there and a
  run prints no tier line.
- Skip detection sees `SKIPPED` and unittest's `skipped=`, not cargo's
  `N ignored` or bun's skip counts. A host run has the same gap. The `check-container` job handed to the maintainer runs
  the Linux Docker case and the refusals.

## Consequences

- T1 is reachable on any machine with Docker or Podman.
- `check-container` in CI shows AC-055 and AC-056: the full check in the
  container; the same `claims_check.py --affected` and staleness report
  from the main checkout, from a git worktree and on the host; and refusals
  of a build-arg that `ci/pins.env` does not state, a download that fails its
  checksum, cargo with no network and no baked registry, a shallow clone, a
  partial clone, a run with the network on, a run without `--read-only`, a
  read-write checkout mount, and an image built from other pins.
- A `--no-strict` run is reported as T1 with the argument in its tier line,
  as `check` runs it on draft pull requests. Whether that counts as "all of
  `scripts/check.sh`" is the maintainer's call; the line never hides it.
- A tool bump now changes the checksum next to it in `ci/pins.env`.
- The container's JRE and python are exact builds, while `check` takes
  `setup-java`'s newest Temurin 21 and the runner's python. The two can
  differ by a patch release. Either `check-container` becomes a required
  check, or `check` asserts `CHECK_JRE_VERSION` and `CHECK_PYTHON_VERSION`.
  The maintainer decides (#55).

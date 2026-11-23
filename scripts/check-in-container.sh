#!/usr/bin/env bash
# Runs scripts/check.sh in the pinned container ci/check.Dockerfile (#55,
# docs/decisions/0007-check-container.md): network off, read-only root
# filesystem, no capabilities, no new privileges, uid 1000, on a copy of this
# checkout. Works from a git worktree too.
#
# Usage:
#   scripts/check-in-container.sh [--no-strict]   build if needed, run scripts/check.sh
#   scripts/check-in-container.sh --affected REF  run claims_check.py --affected REF in it
#   scripts/check-in-container.sh --build-only    build, print the image id and context hash
#   scripts/check-in-container.sh --checkout DIR [args]
#       judge another checkout DIR (for example an agent's branch in its own
#       git worktree) with this checkout's wrapper and image: run it from a
#       trusted checkout of main. The image is built only from this checkout's
#       committed inputs; DIR is mounted read-only as data. If DIR changes any
#       image input (the Dockerfile, the entrypoint, ci/pins.env, the toolchain
#       or a Cargo manifest or lock) the run is refused, so review those first.
#
# Running this script runs it as you, on your machine, and its build has the
# network. On a branch you do not trust, never run that branch's own copy: run
# main's copy with --checkout instead.
#
# ENGINE=docker (the default) or ENGINE=podman. Nothing else can be set: every
# pin comes from ci/pins.env and rust-toolchain.toml, passed as build-args.
# A full run that passes on a clean, committed tree ends with
# "Tier: T1 (container, image sha256:..., context <hash>)"; a --no-strict run
# ends with "Tier: T0 (...)", because it is not all of scripts/check.sh. Report
# the tier as that line gives it. The image is linux/amd64 only.
set -euo pipefail

die() { echo "check-in-container: error: $*" >&2; exit 1; }

ENGINE="${ENGINE:-docker}"
case "$ENGINE" in docker|podman) ;; *) die "ENGINE must be docker or podman, not '$ENGINE'" ;; esac
command -v "$ENGINE" >/dev/null || die "$ENGINE is not installed"
target=""
if [ "${1:-}" = --checkout ]; then
  [ $# -ge 2 ] && [ -n "$2" ] || die "--checkout needs a directory"
  target="$2"
  shift 2
fi
build_only=0
if [ "${1:-}" = --build-only ]; then
  [ $# = 1 ] || die "--build-only takes no other argument"
  build_only=1
fi

# Git for Windows and Docker Desktop: convert paths for the engine, and stop
# MSYS from rewriting container paths such as /src.
if command -v cygpath >/dev/null; then
  export MSYS_NO_PATHCONV=1
  posix() { cygpath -u "$1"; }
  native() { cygpath -m "$1"; }
else
  posix() { printf '%s\n' "$1"; }
  native() { printf '%s\n' "$1"; }
fi

# The image comes from this script's own checkout (root). The checkout that is
# judged (src) is the same one, or --checkout DIR.
root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"
src="$root"
if [ -n "$target" ]; then
  src="$(cd "$target" && pwd -P)" || die "cannot enter $target"
fi
# Each git answer is checked before it is used: `cd ""` succeeds, so a failed
# rev-parse inside the path resolution would quietly become the current directory.
resolve() {  # checkout, rev-parse option -> physical directory
  local raw
  raw="$(git -C "$1" rev-parse --path-format=absolute "$2")" && [ -n "$raw" ] || die "git rev-parse $2 failed in $1"
  raw="$(posix "$raw")"
  (cd "$raw" && pwd -P) || die "cannot enter $raw"
}
top="$(resolve "$root" --show-toplevel)"
[ "$top" = "$root" ] || die "$root is not the top of its git checkout ($top is)"
if [ "$src" != "$root" ]; then
  top="$(resolve "$src" --show-toplevel)"
  [ "$top" = "$src" ] || die "$src is not the top of its git checkout ($top is)"
fi
gitdir="$(resolve "$src" --git-dir)"
common="$(resolve "$src" --git-common-dir)"
# A worktree's .git file names an absolute host path, which means nothing in
# the container. Mount the common gitdir instead and point GIT_DIR at this
# worktree's entry in it.
if [ "$gitdir" = "$common" ]; then
  git_dir=/git
else
  case "$gitdir" in
    "$common"/worktrees/?*) git_dir="/git/${gitdir#"$common"/}" ;;
    *) die "cannot place gitdir $gitdir under the common gitdir $common" ;;
  esac
fi
case "$src$common" in *,*) die "a path with a comma cannot be mounted: $src or $common" ;; esac

# The build context holds only what the Dockerfile copies. Its hash (the
# context hash) names the image, so a change to any of them builds a new
# image, and anyone can recompute it from a commit: the sha256 of the sorted
# `sha256sum ./<path>` lines of these files.
#
# The files come from the committed tree (HEAD), never from the disk: a branch
# can commit a symbolic link such as crates/x/Cargo.toml -> ~/.ssh/id_ed25519,
# and copying through it would put a host file into a build whose RUN steps
# have the network. Anything that is not a regular file in HEAD is refused. The
# entrypoint refuses uncommitted changes to these inputs, so the committed copy
# is also the one the run checks.
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
mapfile -t manifests < <(git ls-tree -r --name-only HEAD -- crates | grep -E '^crates/[^/]+/Cargo\.toml$' || true)
[ ${#manifests[@]} -gt 0 ] || die "no crates/*/Cargo.toml in HEAD"
for f in ci/check.Dockerfile ci/check-entrypoint.sh ci/pins.env rust-toolchain.toml Cargo.toml Cargo.lock "${manifests[@]}"; do
  mode="$(git ls-tree HEAD -- "$f" | cut -d' ' -f1)"
  case "$mode" in
    100644|100755) ;;
    '') die "missing $f in HEAD" ;;
    *) die "$f is not a regular file in HEAD (mode $mode); refusing to build from it" ;;
  esac
  mkdir -p "$ctx/$(dirname "$f")"
  git show "HEAD:$f" > "$ctx/$f" || die "cannot read $f from HEAD"
done
# --checkout: the judged checkout must carry exactly these inputs, committed and
# on disk. The entrypoint checks the same inside, but this says why, up front.
if [ "$src" != "$root" ]; then
  mapfile -t theirs < <(git -C "$src" ls-tree -r --name-only HEAD -- crates | grep -E '^crates/[^/]+/Cargo\.toml$' || true)
  [ "${theirs[*]}" = "${manifests[*]}" ] || die "$src has other crate manifests than $root; review the change, then judge it with a wrapper you trust"
  changed=()
  for f in ci/check.Dockerfile ci/check-entrypoint.sh ci/pins.env rust-toolchain.toml Cargo.toml Cargo.lock "${manifests[@]}"; do
    [ "$(git -C "$src" rev-parse "HEAD:$f" 2>/dev/null)" = "$(git rev-parse "HEAD:$f")" ] || changed+=("$f")
  done
  [ ${#changed[@]} = 0 ] || die "$src changes the image's inputs (${changed[*]}); review them, then judge it with a wrapper you trust"
fi
context_hash="$(cd "$ctx" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
[[ "$context_hash" =~ ^[0-9a-f]{64}$ ]] || die "could not hash the build context"
tag="vac-check:${context_hash:0:16}"

# Every key of ci/pins.env, as the Dockerfile's ARGs. It refuses a missing or
# mismatched one.
build_args=()
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  [[ "$line" =~ ^[A-Z0-9_]+=[^[:space:]]+$ ]] || die "ci/pins.env: cannot read line: $line"
  build_args+=(--build-arg "$line")
done < "$ctx/ci/pins.env"

# Podman builds OCI images by default, and the OCI format drops the Dockerfile's
# SHELL line, so every RUN would run under /bin/sh instead of bash -euo pipefail.
# Its pin checks then fail (bash's [[ is missing), which is closed but useless.
format=()
[ "$ENGINE" = podman ] && format=(--format docker)
"$ENGINE" build "${format[@]}" --platform linux/amd64 -f "$(native "$ctx/ci/check.Dockerfile")" -t "$tag" \
  "${build_args[@]}" "$(native "$ctx")" >&2 || die "the image did not build"
id="$("$ENGINE" image inspect --format '{{.Id}}' "$tag")" || die "cannot inspect $tag"
id="sha256:${id#sha256:}"
[[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected image id '$id'"
echo "check-in-container: built $tag, image $id, context hash $context_hash" >&2
if [ "$build_only" = 1 ]; then
  echo "$id $context_hash"
  exit 0
fi

run=(run --rm --platform linux/amd64
  --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000
  --mount "type=bind,src=$(native "$src"),dst=/src,readonly"
  --mount "type=bind,src=$(native "$common"),dst=/git,readonly"
  --volume /work
  --tmpfs /tmp:rw,exec,nosuid,nodev
  --env "GIT_DIR=$git_dir" --env "CHECK_IMAGE_ID=$id" --env "CHECK_CONTEXT_HASH=$context_hash")
if [ "$ENGINE" = podman ]; then
  # /tmp is the tmpfs above. Rootless, map the host user to uid 1000 so the
  # bind mounts stay readable.
  run+=(--read-only-tmpfs=false)
  if [ "$(podman info --format '{{.Host.Security.Rootless}}')" = true ]; then
    run+=(--userns=keep-id:uid=1000,gid=1000)
  fi
fi
# Run the image by id, so the run is the image just built and reported. Not
# exec: the EXIT trap removes the build context, and the exit status passes on.
status=0
"$ENGINE" "${run[@]}" "$id" "$@" || status=$?
exit "$status"

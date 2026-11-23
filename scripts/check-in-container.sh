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
#
# ENGINE=docker (the default) or ENGINE=podman. Nothing else can be set: every
# pin comes from ci/pins.env and rust-toolchain.toml, passed as build-args.
# A full run that passes on a clean, committed tree ends with
# "Tier: T1 (container, image sha256:..., context <hash>)"; report the tier as
# that line gives it. The image is linux/amd64 only.
set -euo pipefail

die() { echo "check-in-container: error: $*" >&2; exit 1; }

ENGINE="${ENGINE:-docker}"
case "$ENGINE" in docker|podman) ;; *) die "ENGINE must be docker or podman, not '$ENGINE'" ;; esac
command -v "$ENGINE" >/dev/null || die "$ENGINE is not installed"
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

root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"
# Each git answer is checked before it is used: `cd ""` succeeds, so a failed
# rev-parse inside the path resolution would quietly become the current directory.
resolve() {  # rev-parse option -> physical directory
  local raw
  raw="$(git rev-parse --path-format=absolute "$1")" && [ -n "$raw" ] || die "git rev-parse $1 failed in $root"
  raw="$(posix "$raw")"
  (cd "$raw" && pwd -P) || die "cannot enter $raw"
}
top="$(resolve --show-toplevel)"
[ "$top" = "$root" ] || die "$root is not the top of its git checkout ($top is)"
gitdir="$(resolve --git-dir)"
common="$(resolve --git-common-dir)"
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
case "$root$common" in *,*) die "a path with a comma cannot be mounted: $root or $common" ;; esac

# The build context holds only what the Dockerfile copies. Its hash (the
# context hash) names the image, so a change to any of them builds a new
# image, and anyone can recompute it from a commit: the sha256 of the sorted
# `sha256sum ./<path>` lines of these files.
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
shopt -s nullglob
manifests=(crates/*/Cargo.toml)
shopt -u nullglob
[ ${#manifests[@]} -gt 0 ] || die "no crates/*/Cargo.toml"
for f in ci/check.Dockerfile ci/check-entrypoint.sh ci/pins.env rust-toolchain.toml Cargo.toml Cargo.lock "${manifests[@]}"; do
  [ -f "$f" ] || die "missing $f"
  mkdir -p "$ctx/$(dirname "$f")"
  cp "$f" "$ctx/$f"
done
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
done < ci/pins.env

"$ENGINE" build --platform linux/amd64 -f "$(native "$ctx/ci/check.Dockerfile")" -t "$tag" \
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
  --mount "type=bind,src=$(native "$root"),dst=/src,readonly"
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

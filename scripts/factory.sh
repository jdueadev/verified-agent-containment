#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

engine="${FACTORY_ENGINE:-docker}"
image="${FACTORY_IMAGE:-vac-factory}"
pins=()
while IFS= read -r pin; do pins+=(--build-arg "$pin"); done < <(grep -E '^[A-Z0-9_]+=' ci/pins.env)
[ "${#pins[@]}" -gt 0 ] || { echo "factory: ci/pins.env has no pins" >&2; exit 1; }
if [ -n "${FACTORY_BASE_IMAGE:-}" ]; then pins+=(--build-arg "FACTORY_BASE_IMAGE=$FACTORY_BASE_IMAGE"); fi

usage() {
  echo "usage: scripts/factory.sh build [image...] | shell | check [check.sh options] | verdict | page | kani [kani.sh options] | lab [repeat] | replay [kernel.jsonl...]" >&2
  echo "  build    build the named images, or check, proofs, kani, dev and page, from ci/factory.Dockerfile" >&2
  echo "  shell    open a shell in the dev image with this checkout mounted at /work" >&2
  echo "  check    run scripts/check.sh in the check image" >&2
  echo "  verdict  run scripts/verdict.sh (the Lean recheck) in the proofs image" >&2
  echo "  page     run scripts/page-check.sh (build the simulator page to target/page/ and drive it) in the page image, with no network" >&2
  echo "  kani     run scripts/kani.sh (the Kani proofs of admission) in the kani image, with no network" >&2
  echo "  lab      run the root attack and live suites in a privileged container" >&2
  echo "           only on a disposable machine: set FACTORY_LAB_DISPOSABLE=1 to confirm" >&2
  echo "           FACTORY_LAB_OUT=<dir> keeps the results in <dir>; FACTORY_LAB_IMAGE_ID=<file> records the image id" >&2
  echo "  replay   run the outer loop's kernel replay (scripts/outer-loop.sh replay) in the check image, with no network" >&2
  echo "           FACTORY_OUTER_OUT=<dir> is the outer loop's folder: its traces.jsonl is read, and the replay is written there" >&2
}

build() {
  # FACTORY_BUILD_OPTIONS holds several options, so it is split on spaces on purpose.
  # shellcheck disable=SC2086
  "$engine" build ${FACTORY_BUILD_OPTIONS:-} -f ci/factory.Dockerfile "${pins[@]}" --target "$1" -t "$image:$1" .
}

# Git Bash on Windows rewrites any argument that looks like a POSIX path before a Windows program sees it
# (/work turns into a folder under the Git install). Turn that off for the engine, and name the checkout
# the way the engine on Windows reads it.
here() { pwd; }
case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
    here() { pwd -W; }
    ;;
esac

mounts=(-v "$(here):/work" -v vac-factory-target:/work/target)

case "${1:-}" in
  build)
    shift
    targets=("$@")
    [ "${#targets[@]}" -gt 0 ] || targets=(check proofs kani dev page)
    for target in "${targets[@]}"; do build "$target"; done
    ;;
  shell)
    build dev
    exec "$engine" run --rm -it "${mounts[@]}" "$image:dev" bash
    ;;
  check)
    shift
    build check
    exec "$engine" run --rm "${mounts[@]}" "$image:check" scripts/check.sh "$@"
    ;;
  verdict)
    build proofs
    exec "$engine" run --rm "${mounts[@]}" "$image:proofs" scripts/verdict.sh
    ;;
  page)
    build page
    exec "$engine" run --rm --network=none -e CARGO_NET_OFFLINE=true "${mounts[@]}" "$image:page" scripts/page-check.sh
    ;;
  kani)
    shift
    build kani
    exec "$engine" run --rm --network=none -e CARGO_NET_OFFLINE=true "${mounts[@]}" "$image:kani" scripts/kani.sh "$@"
    ;;
  lab)
    if [ "${FACTORY_LAB_DISPOSABLE:-}" != "1" ]; then
      echo "factory: the lab runs attack code as root in a privileged container, which is root on this machine." >&2
      echo "factory: run it only on a disposable machine, and set FACTORY_LAB_DISPOSABLE=1 to confirm." >&2
      exit 1
    fi
    build check
    shift
    lab=(-e FACTORY_LAB_DISPOSABLE=1 -e "FACTORY_LAB_COMMIT=$(git rev-parse HEAD)")
    if [ -n "${FACTORY_LAB_OUT:-}" ]; then
      mkdir -p "$FACTORY_LAB_OUT"
      lab+=(-v "$(cd "$FACTORY_LAB_OUT" && here):/work/target/verify/lab")
    fi
    "$engine" image inspect --format '{{.Id}}' "$image:check" > "${FACTORY_LAB_IMAGE_ID:-/dev/null}"
    exec "$engine" run --rm --privileged --cgroupns=private "${mounts[@]}" "${lab[@]}" "$image:check" scripts/factory-lab.sh "$@"
    ;;
  replay)
    shift
    build check
    outer=()
    if [ -n "${FACTORY_OUTER_OUT:-}" ]; then
      mkdir -p "$FACTORY_OUTER_OUT"
      outer+=(-v "$(cd "$FACTORY_OUTER_OUT" && pwd):/work/target/outer")
    fi
    exec "$engine" run --rm --network=none -e CARGO_NET_OFFLINE=true "${mounts[@]}" "${outer[@]}" "$image:check" scripts/outer-loop.sh replay "$@"
    ;;
  *)
    usage
    exit 2
    ;;
esac

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
  echo "usage: scripts/factory.sh build [image...] | shell | check [check.sh options] | verdict | kani [kani.sh options] | lab [repeat]" >&2
  echo "  build    build the named images, or check, proofs, kani and dev, from ci/factory.Dockerfile" >&2
  echo "  shell    open a shell in the dev image with this checkout mounted at /work" >&2
  echo "  check    run scripts/check.sh in the check image" >&2
  echo "  verdict  run scripts/verdict.sh (the Lean recheck) in the proofs image" >&2
  echo "  kani     run scripts/kani.sh (the Kani proofs of admission) in the kani image, with no network" >&2
  echo "  lab      run the root attack and live suites in a privileged container" >&2
  echo "           only on a disposable machine: set FACTORY_LAB_DISPOSABLE=1 to confirm" >&2
  echo "           FACTORY_LAB_OUT=<dir> keeps the results in <dir>; FACTORY_LAB_IMAGE_ID=<file> records the image id" >&2
}

build() {
  "$engine" build ${FACTORY_BUILD_OPTIONS:-} -f ci/factory.Dockerfile "${pins[@]}" --target "$1" -t "$image:$1" .
}

mounts=(-v "$PWD:/work" -v vac-factory-target:/work/target)

case "${1:-}" in
  build)
    shift
    targets=("$@")
    [ "${#targets[@]}" -gt 0 ] || targets=(check proofs kani dev)
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
      lab+=(-v "$(cd "$FACTORY_LAB_OUT" && pwd):/work/target/verify/lab")
    fi
    "$engine" image inspect --format '{{.Id}}' "$image:check" > "${FACTORY_LAB_IMAGE_ID:-/dev/null}"
    exec "$engine" run --rm --privileged --cgroupns=private "${mounts[@]}" "${lab[@]}" "$image:check" scripts/factory-lab.sh "$@"
    ;;
  *)
    usage
    exit 2
    ;;
esac

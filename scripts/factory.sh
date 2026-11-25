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
  echo "usage: scripts/factory.sh build | shell | check [check.sh options] | verdict | lab [repeat]" >&2
  echo "  build    build the check, proofs and dev images from ci/factory.Dockerfile" >&2
  echo "  shell    open a shell in the dev image with this checkout mounted at /work" >&2
  echo "  check    run scripts/check.sh in the check image" >&2
  echo "  verdict  run scripts/verdict.sh (the Lean recheck) in the proofs image" >&2
  echo "  lab      run the root attack and live suites in a privileged container" >&2
  echo "           only on a disposable machine: set FACTORY_LAB_DISPOSABLE=1 to confirm" >&2
}

build() {
  "$engine" build ${FACTORY_BUILD_OPTIONS:-} -f ci/factory.Dockerfile "${pins[@]}" --target "$1" -t "$image:$1" .
}

mounts=(-v "$PWD:/work" -v vac-factory-target:/work/target)

case "${1:-}" in
  build)
    build check
    build proofs
    build dev
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
  lab)
    if [ "${FACTORY_LAB_DISPOSABLE:-}" != "1" ]; then
      echo "factory: the lab runs attack code as root in a privileged container, which is root on this machine." >&2
      echo "factory: run it only on a disposable machine, and set FACTORY_LAB_DISPOSABLE=1 to confirm." >&2
      exit 1
    fi
    build check
    shift
    exec "$engine" run --rm --privileged --cgroupns=private "${mounts[@]}" "$image:check" scripts/factory-lab.sh "$@"
    ;;
  *)
    usage
    exit 2
    ;;
esac

#!/usr/bin/env bash
# The entrypoint of ci/check.Dockerfile (#55, docs/decisions/0006-check-container.md).
# scripts/check-in-container.sh starts it; it is not meant to be run by hand.
#
# It runs scripts/check.sh only when the run can honestly be called T1:
#   - CI=true, so a missing tool fails instead of printing SKIPPED;
#   - the run has the hardening the wrapper asks for: uid 1000, no network
#     but loopback, an empty capability bounding set, no_new_privs, and a
#     read-only root filesystem, checkout and gitdir;
#   - the checkout's files, copied from the read-only /src into the scratch
#     volume /work, show the same `git status` there as in /src, and no file
#     is marked assume-unchanged or skip-worktree;
#   - git history is all there: HEAD resolves, the repository is not shallow,
#     no object is missing, every platform commit in claims.toml resolves, and
#     a recorded lab commit (results/ci/lab-*, results/wsl2/lab-*) is an
#     ancestor of HEAD. tools/claims_check.py treats a git failure as "stale"
#     or "no lab run", so without this a broken mount would pass quietly;
#   - the image was built from this checkout's pins, Dockerfile, entrypoint,
#     toolchain file, Cargo.lock and crate manifests;
#   - every tool reports exactly the version ci/pins.env and
#     rust-toolchain.toml pin.
# It also fails if check.sh printed SKIPPED or a unit test was skipped. A
# passing run ends with a "Tier: T1 (container, ...)" line naming the image
# id, HEAD, whether the tree had uncommitted changes, and the arguments.
#
# Usage (through the wrapper): [--no-strict]   run scripts/check.sh
#                              --affected REF  run claims_check.py --affected REF
#                              --claims        run claims_check.py (not strict)
set -euo pipefail

SRC=/src          # the checkout, mounted read-only
WORK=/work        # a fresh scratch volume
BAKED=/opt/check  # the files the image was built from
SKEL=/opt/check-skel  # the manifests the baked cargo registry was fetched for
REPO="$WORK/repo"
PINNED_FILES=(ci/pins.env ci/check.Dockerfile ci/check-entrypoint.sh rust-toolchain.toml Cargo.lock)
REQUIRED_PINS=(BUN_VERSION NODE_VERSION JAVA_VERSION JRE_VERSION PYTHON_VERSION BEND_COMMIT TLA_SHA256)

say() { echo "check-container: $*" >&2; }
die() { echo "check-container: error: $*" >&2; exit 1; }

git_env() {
  [ -n "${GIT_DIR:-}" ] || die "GIT_DIR is not set; start this with scripts/check-in-container.sh"
  [ -d "$GIT_DIR" ] || die "GIT_DIR $GIT_DIR is not a directory: the git mount is missing"
  # The mounts belong to the host user, and nothing may write the read-only
  # gitdir. No system or global config: only these settings and the repo's.
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  # core.fileMode and core.sparseCheckout are forced so that repository
  # config cannot hide a change from the `git status` comparison below.
  export GIT_CONFIG_COUNT=5 \
    GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
    GIT_CONFIG_KEY_1=core.fsmonitor GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=core.untrackedCache GIT_CONFIG_VALUE_2=false \
    GIT_CONFIG_KEY_3=core.fileMode GIT_CONFIG_VALUE_3=true \
    GIT_CONFIG_KEY_4=core.sparseCheckout GIT_CONFIG_VALUE_4=false
  export GIT_OPTIONAL_LOCKS=0 GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0
}

# Tracked and untracked-but-not-ignored files, as in the checkout. A tracked
# file deleted in the checkout is absent from the copy too.
copy_tree() {
  [ -d "$WORK" ] && [ -z "$(ls -A "$WORK")" ] || die "$WORK must be a fresh, empty scratch volume"
  mkdir "$REPO" "$WORK/home"
  local all=/tmp/check-files.all list=/tmp/check-files f flagged
  # `git status` does not report a file marked assume-unchanged (a lowercase
  # tag) or skip-worktree (S, which a sparse checkout also leaves off disk),
  # so such a tree could pass as clean while the run used other bytes.
  flagged="$(GIT_WORK_TREE="$SRC" git -C "$SRC" ls-files -v)" || die "git cannot list the index of $SRC"
  flagged="$(grep -E '^([a-z]|S) ' <<<"$flagged" | head -5 || true)"
  [ -z "$flagged" ] || die "files are marked assume-unchanged or skip-worktree (sparse checkout?): $flagged"
  GIT_WORK_TREE="$SRC" git -C "$SRC" ls-files -z --cached --others --exclude-standard --deduplicate > "$all" \
    || die "git cannot list the files of $SRC"
  : > "$list"
  while IFS= read -r -d '' f; do
    if [ -e "$SRC/$f" ] || [ -L "$SRC/$f" ]; then printf '%s\0' "$f" >> "$list"; fi
  done < "$all"
  [ -s "$list" ] || die "git listed no files in $SRC"
  tar -C "$SRC" --null --no-recursion -T "$list" -cf - | tar -C "$REPO" -xpf - \
    || die "copying $SRC to $REPO failed"
  local before after
  before="$(GIT_WORK_TREE="$SRC" git -C "$SRC" status --porcelain=v1 --untracked-files=all)" \
    || die "git status failed in $SRC"
  after="$(GIT_WORK_TREE="$REPO" git -C "$REPO" status --porcelain=v1 --untracked-files=all)" \
    || die "git status failed in $REPO"
  [ "$before" = "$after" ] || die "the copy in $REPO does not match $SRC (git status differs)"
  TREE_STATE=clean
  [ -z "$after" ] || TREE_STATE="uncommitted changes"
}

check_history() {
  HEAD_SHA="$(git rev-parse --verify --quiet 'HEAD^{commit}')" \
    || die "HEAD does not resolve: the git mount is broken or GIT_DIR is wrong"
  [ "$(git rev-parse --is-shallow-repository)" = false ] \
    || die "the repository is shallow; claims_check.py needs the full history (clone without --depth)"
  local objects missing
  objects="$(git rev-list --objects --missing=print HEAD)" || die "git cannot walk the history of HEAD"
  missing="$(grep '^?' <<<"$objects" | head -5 || true)"
  [ -z "$missing" ] || die "objects are missing from the history (a partial clone?): $missing"

  local commits c
  commits="$(grep -oE 'commit *= *"[0-9a-f]{7,40}"' claims.toml | grep -oE '[0-9a-f]{7,40}' | sort -u || true)"
  [ -n "$commits" ] || die "found no platform commit in claims.toml"
  for c in $commits; do
    git rev-parse --verify --quiet "$c^{commit}" >/dev/null \
      || die "platform commit $c in claims.toml does not resolve; claims_check.py would call its claims stale"
  done

  local dir sha ancestors=0 candidates=0
  shopt -s nullglob
  for dir in results/ci/lab-* results/wsl2/lab-*; do
    [ -d "$dir" ] || continue
    sha="${dir##*/lab-}"
    [[ "$sha" =~ ^[0-9a-f]{7,40}$ ]] || continue
    candidates=$((candidates + 1))
    if ! git rev-parse --verify --quiet "$sha^{commit}" >/dev/null; then
      # claims_check.py skips a CI lab run it cannot place, silently.
      [[ "$dir" != results/ci/* ]] || die "lab commit $sha ($dir) does not resolve"
      continue
    fi
    if git merge-base --is-ancestor "$sha" HEAD; then ancestors=$((ancestors + 1)); fi
  done
  shopt -u nullglob
  [ "$candidates" -gt 0 ] || die "no lab run under results/ci or results/wsl2 to check the history against"
  [ "$ancestors" -gt 0 ] || die "no recorded lab commit is an ancestor of HEAD; the history is incomplete"
}

check_image() {
  local f
  for f in "${PINNED_FILES[@]}"; do
    cmp -s "$BAKED/$f" "$f" \
      || die "$f is not the one this image was built from; rebuild with scripts/check-in-container.sh"
  done
  # The manifests the baked registry was fetched for.
  local baked here
  baked="$(cd "$SKEL" && find Cargo.toml crates -name Cargo.toml -type f | LC_ALL=C sort)"
  here="$(find Cargo.toml crates -name Cargo.toml -type f | LC_ALL=C sort)"
  [ "$baked" = "$here" ] || die "the crate manifests are not the ones this image was built from; rebuild"
  for f in $here; do
    cmp -s "$SKEL/$f" "$f" || die "$f is not the one this image was built from; rebuild"
  done
}

# The run's own hardening, as scripts/check-in-container.sh asks for it. A
# hand-made `docker run` without it does not get a T1 line.
check_hardening() {
  [ "$(id -u):$(id -g)" = 1000:1000 ] || die "not running as uid 1000"
  local nets
  nets="$(ls /sys/class/net)"
  [ "$nets" = lo ] || die "the network is on (interfaces: $(tr '\n' ' ' <<<"$nets")); run with --network=none"
  # The bounding set, not the effective one: uid 1000 has no effective
  # capabilities either way, but only --cap-drop=ALL empties the bounding set.
  grep -qE '^CapBnd:[[:space:]]+0+$' /proc/self/status || die "capabilities are not dropped; run with --cap-drop=ALL"
  grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status || die "no_new_privs is off; run with --security-opt=no-new-privileges"
  if touch /opt/.check-probe 2>/dev/null; then die "the root filesystem is writable; run with --read-only"; fi
  if touch "$SRC/.check-probe" 2>/dev/null; then die "$SRC is writable; mount it read-only"; fi
  if touch "${GIT_DIR:?}/.check-probe" 2>/dev/null; then die "the gitdir is writable; mount it read-only"; fi
}

read_pins() {
  declare -gA PIN=()
  local line k
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    [[ "$line" =~ ^([A-Z0-9_]+)=([^[:space:]]+)$ ]] || die "ci/pins.env: cannot read line: $line"
    PIN[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
  done < ci/pins.env
  for k in "${REQUIRED_PINS[@]}"; do
    [ -n "${PIN[$k]:-}" ] || die "ci/pins.env has no $k"
  done
}

expect() {  # name, actual, wanted
  [ "$2" = "$3" ] || die "$1 is '$2', not the pinned '$3'"
  TOOLS+=("$1 $2")
}

check_tools() {
  TOOLS=()
  python3 tools/pins_check.py drift --rustc --cargo || die "rustc or cargo is not the pinned version"
  TOOLS+=("$(rustc --version)" "$(cargo --version)")
  expect bun "$(bun --version)" "${PIN[BUN_VERSION]}"
  expect node "$(node --version)" "v${PIN[NODE_VERSION]}"
  local java
  java="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java\.runtime\.version = //p')"
  [[ "${PIN[JRE_VERSION]}" == "${PIN[JAVA_VERSION]}".* ]] \
    || die "JRE_VERSION ${PIN[JRE_VERSION]} is not Java ${PIN[JAVA_VERSION]}"
  expect java "${java%-LTS}" "${PIN[JRE_VERSION]}"
  expect python3 "$(python3 --version)" "Python ${PIN[PYTHON_VERSION]}"
  [ "$(command -v bend)" = /usr/local/bin/bend ] && grep -qF /opt/bend/bend2/main.ts /usr/local/bin/bend \
    || die "bend is not the pinned checkout in /opt/bend"
  expect bend "$(GIT_DIR=/opt/bend/.git git rev-parse HEAD)" "${PIN[BEND_COMMIT]}"
  [ -z "$(GIT_DIR=/opt/bend/.git GIT_WORK_TREE=/opt/bend git status --porcelain)" ] \
    || die "the bend checkout in /opt/bend has local changes"
  expect tla2tools.jar "$(sha256sum "${TLA2TOOLS:?}" | cut -d' ' -f1)" "${PIN[TLA_SHA256]}"
  # scripts/build-wasm.sh runs this; on the read-only toolchain it must be a
  # no-op, so fail here with a clear reason rather than half way through.
  rustup target add wasm32-unknown-unknown >/dev/null \
    || die "rustup target add wasm32-unknown-unknown fails offline on the read-only toolchain"
}

main() {
  [ "${CI:-}" = true ] || die "CI must be true, so that a missing tool fails instead of printing SKIPPED"
  [[ "${CHECK_IMAGE_ID:-}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "CHECK_IMAGE_ID is not set; start this with scripts/check-in-container.sh"
  case "${1:-}" in
    --affected) [ $# = 2 ] || die "usage: --affected REF" ;;
    --claims) [ $# = 1 ] || die "usage: --claims" ;;
  esac
  git_env
  check_hardening
  copy_tree
  export GIT_WORK_TREE="$REPO" HOME="$WORK/home" TMPDIR=/tmp
  cd "$REPO"
  check_history
  check_image
  read_pins
  # Cargo extracts crates into CARGO_HOME, so it gets a writable copy of the
  # baked registry. The toolchain itself stays read-only.
  mkdir "$WORK/cargo"
  cp -R /opt/cargo/registry "$WORK/cargo/registry"
  export CARGO_HOME="$WORK/cargo" CARGO_NET_OFFLINE=true
  check_tools

  say "image $CHECK_IMAGE_ID"
  say "ci/check.Dockerfile sha256 $(sha256sum ci/check.Dockerfile | cut -d' ' -f1)"
  say "HEAD $HEAD_SHA ($TREE_STATE)"
  local t
  for t in "${TOOLS[@]}"; do say "tool: $t"; done

  if [ "${1:-}" = --affected ]; then
    python3 tools/claims_check.py --affected "$2"
    return
  fi
  if [ "${1:-}" = --claims ]; then
    # The history-dependent verdicts (staleness, CI lab runs), not strict.
    python3 tools/claims_check.py
    return
  fi
  local status
  set +e
  bash scripts/check.sh "$@" 2>&1 | tee /tmp/check.log
  status=("${PIPESTATUS[@]}")
  set -e
  [ "${status[0]}" = 0 ] || die "scripts/check.sh failed (exit ${status[0]})"
  [ "${status[1]}" = 0 ] || die "could not record the output of scripts/check.sh"
  if grep -n SKIPPED /tmp/check.log >&2; then
    die "scripts/check.sh printed SKIPPED, so this run is T0, not T1"
  fi
  # A skipped unit test is a check that did not run either.
  if grep -nE 'skipped=[0-9]' /tmp/check.log >&2; then
    die "a unit test was skipped, so this run is T0, not T1"
  fi
  echo "Tier: T1 (container, image $CHECK_IMAGE_ID) at HEAD $HEAD_SHA ($TREE_STATE), scripts/check.sh${*:+ $*}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

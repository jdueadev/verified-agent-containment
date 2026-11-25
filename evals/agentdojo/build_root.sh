#!/usr/bin/env bash
# Builds the read-only root directory the AgentDojo adapter runs in:
#   /opt/python   a CPython at exactly the version in root/python-version, with AgentDojo
#                 and its dependencies from root/requirements.lock (hashes checked)
#   /lib, /lib64  the host libraries those binaries link, found with ldd
# and writes OUT.manifest.json with everything it pinned or copied.
#
# usage: evals/agentdojo/build_root.sh [OUT]     (default: target/agentdojo/root)
#   PYTHON=/path/to/python3.13 picks the interpreter (default /usr/local/bin/python3.13).
# The lock is regenerated with the command at the top of root/requirements.lock.
#
# The sandbox has no /dev, so the interpreter must get random numbers from the
# getrandom system call. uv's managed CPython builds read /dev/urandom instead
# and stop at startup, so the interpreter comes from the host and is pinned by
# version here and by hash in the manifest.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${1:-$repo/target/agentdojo/root}
version=$(tr -d '[:space:]' < "$here/root/python-version")
lock=$here/root/requirements.lock
python=$(readlink -f "${PYTHON:-/usr/local/bin/python${version%.*}}")
short=python${version%.*}

read -r have getrandom stdlib < <("$python" -I -c 'import sys, sysconfig as s
print(sys.version.split()[0], int(bool(s.get_config_var("HAVE_GETRANDOM_SYSCALL") or s.get_config_var("HAVE_GETRANDOM"))), s.get_path("stdlib"))')
[ "$have" = "$version" ] || { echo "$python is CPython $have; root/python-version pins $version" >&2; exit 1; }
[ "$getrandom" = 1 ] || { echo "$python reads /dev/urandom for random numbers; the sandbox has no /dev" >&2; exit 1; }

tmp=$out.building
rm -rf "$tmp"
mkdir -p "$tmp/opt/python/bin" "$tmp/opt/python/lib"
cp -L "$python" "$tmp/opt/python/bin/$short"
ln -s "$short" "$tmp/opt/python/bin/python3"
# The standard library without the host's installed packages and without parts
# the adapter never uses (tkinter also needs libraries the host may not have).
tar -C "$(dirname "$stdlib")" --exclude="$short/site-packages" --exclude="$short/dist-packages" --exclude="$short/test" \
    --exclude="$short/tkinter" --exclude="$short/idlelib" --exclude="$short/turtledemo" --exclude="$short/ensurepip" \
    --exclude="$short/lib-dynload/_tkinter.*" -cf - "$short" | tar -C "$tmp/opt/python/lib" -xf -
site=$tmp/opt/python/lib/$short/site-packages
mkdir -p "$site"

uv pip install --quiet --python "$tmp/opt/python/bin/$short" --target "$site" --require-hashes --no-deps --no-config -r "$lock"
# Console scripts carry this build's absolute path; nothing in the sandbox runs them.
rm -rf "$site/bin"
sed -i '/^bin\//d' "$site"/*.dist-info/RECORD
# The root is read-only in the sandbox, so imports cannot write bytecode there.
# Hash-based bytecode does not depend on file times; -s/-p record sandbox paths;
# a fixed hash seed keeps set constants in the same order on every build.
env -i PYTHONHASHSEED=0 "$tmp/opt/python/bin/$short" -s -P -m compileall -q -f -j 0 --invalidation-mode unchecked-hash \
    -s "$tmp" -p / "$tmp/opt/python/lib/$short" > /dev/null || true

# Host libraries: every ELF file in the root, resolved by the host's loader.
mapfile -t elves < <(find "$tmp" -type f \( -name '*.so' -o -name '*.so.*' -o -path '*/bin/*' \) -exec sh -c 'head -c4 "$1" | grep -q ELF && echo "$1"' _ {} \;)
missing=$(for f in "${elves[@]}"; do ldd "$f" 2>/dev/null | { grep 'not found' || true; } | sed "s|^|$f: |"; done)
[ -z "$missing" ] || { echo "unresolved libraries:" >&2; echo "$missing" >&2; exit 1; }
mapfile -t libs < <(for f in "${elves[@]}"; do ldd "$f" 2>/dev/null; done \
    | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' | grep -v "^$tmp" | sort -u)
for lib in "${libs[@]}"; do
    mkdir -p "$tmp$(dirname "$lib")"
    cp -L "$lib" "$tmp$lib"
done

# Manifest: what was pinned, what came from the host, and one hash over the whole tree.
tree=$(cd "$tmp" && find . \( -type f -o -type l \) -print0 | LC_ALL=C sort -z \
    | while IFS= read -r -d '' p; do
        if [ -L "$p" ]; then printf '%s -> %s\n' "$p" "$(readlink "$p")"; else printf '%s %s\n' "$p" "$(sha256sum < "$p" | cut -d' ' -f1)"; fi
      done | sha256sum | cut -d' ' -f1)
"$tmp/opt/python/bin/$short" -I - "$tmp" "$out" "$version" "$python" "$lock" "$tree" "${libs[@]}" > "$tmp.manifest" <<'PY'
import hashlib, json, platform, sys
tmp, out, version, python, lock, tree, *libs = sys.argv[1:]
digest = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
sys.path.insert(0, f"{tmp}/opt/python/lib/python{version.rsplit('.', 1)[0]}/site-packages")
from importlib.metadata import version as pkg
print(json.dumps({
    "root": out,
    "python": {"version": version, "source": python, "sha256": digest(python)},
    "agentdojo": pkg("agentdojo"),
    "requirements_lock_sha256": digest(lock),
    "host_libraries": {lib: digest(lib) for lib in libs},
    "host": {"glibc": platform.libc_ver()[1], "kernel": platform.release()},
    "tree_sha256": tree,
}, indent=2))
PY
rm -rf "$out"
mv "$tmp" "$out"
mv "$tmp.manifest" "$out.manifest.json"
echo "root: $out ($(du -sh "$out" | cut -f1)), manifest: $out.manifest.json, tree $tree"

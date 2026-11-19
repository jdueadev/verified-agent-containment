#!/usr/bin/env python3
"""Compile the simulator's sabotaged kernels from real one-line source edits."""
import os, shutil, subprocess, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from kernel_mutants import RUST_MUTANTS, SHOWCASE

work = root / "target/variant-src"
out = root / "target/generated/variants"
out.mkdir(parents=True, exist_ok=True)
shutil.rmtree(work, ignore_errors=True)
shutil.copytree(root, work, ignore=shutil.ignore_patterns("target", ".git", "results", "dist"))
lib = work / "crates/containment-kernel/src/lib.rs"
source = lib.read_text()
edits = {name: (old, new) for name, old, new in RUST_MUTANTS}
env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/variant-build")}
for name, *_ in SHOWCASE:
    old, new = edits[name]
    assert source.count(old) == 1, name
    lib.write_text(source.replace(old, new))
    subprocess.run(["scripts/build-wasm.sh"], cwd=work, env=env, check=True)
    built = root / "target/variant-build/wasm32-unknown-unknown/release/containment_wasm.wasm"
    opt = out / f"{name}.wasm"
    npx = ["npx", "--yes", "--package", "binaryen@123.0.0"]
    subprocess.run(npx + ["wasm-opt", "-Oz", "--strip-debug", "--strip-producers", str(built), "-o", str(opt)], check=True)
    subprocess.run(npx + ["wasm2js", str(opt), "-o", str(out / f"{name}.js")], check=True)

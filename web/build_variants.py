#!/usr/bin/env python3
"""Compile the simulator's sabotaged kernels from real one-line source edits.

Each edit is matched by tokens with the same matcher as tools/mutation_check.py, so the
simulator and the mutation check always mutate the same place."""
import os, shutil, subprocess, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from kernel_mutants import RUST_MUTANTS, SHOWCASE
from rust_tokens import splice_once

work = root / "target/variant-src"
out = root / "target/generated/variants"
out.mkdir(parents=True, exist_ok=True)
shutil.rmtree(work, ignore_errors=True)
shutil.copytree(root, work, ignore=shutil.ignore_patterns("target", ".git", "results", "dist"))
lib = work / "crates/containment-kernel/src/lib.rs"
source = lib.read_text(encoding="utf-8")
edits = {name: (old, new) for name, old, new in RUST_MUTANTS}
env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/variant-build")}
for name, *_ in SHOWCASE:
    old, new = edits[name]
    try:
        mutated = splice_once(source, old, new)
    except ValueError as err:
        raise SystemExit(f"mutation target {name}: {err}") from err
    lib.write_text(mutated, encoding="utf-8")
    subprocess.run(["scripts/build-wasm.sh"], cwd=work, env=env, check=True)
    built = root / "target/variant-build/wasm32-unknown-unknown/release/containment_wasm.wasm"
    opt = out / f"{name}.wasm"
    npx = ["npx", "--yes", "--package", "binaryen@123.0.0"]
    subprocess.run(npx + ["wasm-opt", "-Oz", "--strip-debug", "--strip-producers", str(built), "-o", str(opt)], check=True)
    subprocess.run(npx + ["wasm2js", str(opt), "-o", str(out / f"{name}.js")], check=True)

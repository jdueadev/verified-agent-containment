#!/usr/bin/env python3
"""Runs the Kani proofs in formal/kani/ and shows each one can fail.

  kani_check.py               prove every harness; writes target/verify/kani.json
  kani_check.py mutants [N]   run each broken variant in formal/kani/mutants.toml
                              (or those whose name contains N) and require the
                              harness it names to fail; writes target/verify/kani-mutants.json

Both first check that the mutants still fit the code: every harness is named by
a mutant, every mutant names a harness, and every mutant's `old` still occurs
exactly once in its file. scripts/kani.sh is the entry point.
"""
import hashlib, json, os, re, resource, shutil, subprocess, sys, time, tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_tokens import splice_once  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "target/verify"
MUTANTS = ROOT / "formal/kani/mutants.toml"

# Where harnesses are compiled. The admission crate compiles admission.rs on its
# own; the gate's harnesses need its private types, so they are compiled into
# the host crate. `reaches` is the product code each suite's harnesses run.
SUITES = {
    "admission": {
        "dir": "formal/kani",
        "args": [],
        "harnesses": "formal/kani/admission_proofs.rs",
        "module": "admission_proofs",
        "reaches": ["crates/containment-host/src/controller/admission.rs", "crates/containment-kernel/src/lib.rs"],
    },
    "gate": {
        "dir": ".",
        "args": ["-p", "containment-host", "-Z", "stubbing"],
        "harnesses": "formal/kani/gate_proofs.rs",
        "module": "controller::gate::proofs",
        "reaches": [
            "crates/containment-host/src/controller/gate.rs",
            "crates/containment-host/src/controller/admission.rs",
            "crates/containment-host/src/controller/weakness.rs",
            "crates/containment-kernel/src/lib.rs",
        ],
    },
}
# Hashed into the report with the code above, so a recorded pass names what it covered.
VERIFICATION = ["formal/kani/Cargo.toml", "formal/kani/Cargo.lock", "formal/kani/lib.rs", "formal/kani/mutants.toml", "ci/pins.env"]
# What a scratch copy for a mutant needs: the two Cargo workspaces and their sources.
MIRROR = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo", "crates", "formal/kani"]
# A cap on each Kani run's address space, so a proof that blows up fails on its
# own instead of the machine's OOM killer stopping something else.
MEMORY_MB = int(os.environ.get("KANI_MEMORY_MB", "6144"))


def harnesses(suite):
    source = (ROOT / SUITES[suite]["harnesses"]).read_text(encoding="utf-8")
    return re.findall(r"#\[kani::proof\]\s*(?:#\[[^\]]*\]\s*)*fn (\w+)", source)


def load_mutants():
    mutants = tomllib.loads(MUTANTS.read_text(encoding="utf-8"))["mutant"]
    owner = {name: suite for suite in SUITES for name in harnesses(suite)}
    problems = []
    for m in mutants:
        if m["breaks"] not in owner:
            problems.append(f"mutant {m['name']!r} names no harness: {m['breaks']}")
        m["suite"] = owner.get(m["breaks"])
        try:
            m["mutated"] = splice_once((ROOT / m["file"]).read_text(encoding="utf-8"), m["old"], m["new"])
        except ValueError as err:
            problems.append(f"mutant {m['name']!r} no longer fits {m['file']}: {err}")
    named = {m["breaks"] for m in mutants}
    problems += [f"harness {name} has no mutant, so it was never seen failing" for name in owner if name not in named]
    if problems:
        raise SystemExit("kani: formal/kani/mutants.toml is out of step with the code:\n  " + "\n  ".join(problems))
    return mutants


def cap_memory():
    limit = MEMORY_MB * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def kani(cwd, args, target):
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    start = time.monotonic()
    run = subprocess.run(["cargo", "kani", *args], cwd=cwd, env=env, text=True, capture_output=True, preexec_fn=cap_memory)
    return run.returncode, run.stdout + run.stderr, time.monotonic() - start


def parse(text, harness_file):
    """Each harness's result from Kani's regular output."""
    results = {}
    for section in re.split(r"^Checking harness ", text, flags=re.M)[1:]:
        name = section.split("...", 1)[0].strip()
        status = re.search(r"VERIFICATION:- (\w+)", section)
        seconds = re.search(r"Verification Time: ([\d.]+)s", section)
        checks = re.findall(r"Check \d+: .*\n\s+- Status: (\w+)\n\s+- Description: \"(.*)\"\n(?:\s+- Location: (.*)\n)?", section)
        # An assertion's message comes quoted; Kani's own checks do not.
        checks = [(state, desc.strip('"'), where) for state, desc, where in checks]
        failed = sorted({desc for state, desc, _ in checks if state == "FAILURE"})
        # An assertion Kani can never reach holds for no input at all: a vacuous proof.
        vacuous = sorted({desc for state, desc, where in checks if state == "UNREACHABLE" and Path(harness_file).name in (where or "")})
        undetermined = sum(state == "UNDETERMINED" for state, _, _ in checks)
        verified = bool(status) and status.group(1) == "SUCCESSFUL" and not vacuous and not undetermined
        results[name.rsplit("::", 1)[-1]] = {
            "harness": name,
            "verified": verified,
            "seconds": float(seconds.group(1)) if seconds else None,
            "failed": failed,
            "vacuous": vacuous,
            "undetermined": undetermined,
            "out_of_memory": "out of memory" in section.lower(),
        }
    return results


def version():
    run = subprocess.run(["cargo", "kani", "--version"], text=True, capture_output=True)
    found = dict(re.findall(r"^(Kani Rust Verifier|CBMC) (\S+)", run.stdout, flags=re.M))
    pins = dict(re.findall(r"^([A-Z0-9_]+)=(.*)$", (ROOT / "ci/pins.env").read_text(), flags=re.M))
    want = pins["KANI_VERSION"]
    if found.get("Kani Rust Verifier") != want:
        raise SystemExit(f"kani: need Kani {want} (ci/pins.env), found {found.get('Kani Rust Verifier', 'none')}; "
                         "run scripts/factory.sh kani, which has it, or install it as .claude/skills/verify-gateway-admission/SKILL.md says")
    return want, found.get("CBMC")


def digest(paths):
    h = hashlib.sha256()
    for path in paths:
        h.update(path.encode() + b"\0" + (ROOT / path).read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def prove():
    load_mutants()
    kani_version, cbmc = version()
    logs = OUT / "kani"
    logs.mkdir(parents=True, exist_ok=True)
    report, ok = [], True
    inputs = sorted({p for s in SUITES.values() for p in [s["harnesses"], *s["reaches"]]} | set(VERIFICATION))
    for suite, spec in SUITES.items():
        code, text, seconds = kani(ROOT / spec["dir"], spec["args"], ROOT / "target/kani")
        (logs / f"{suite}.log").write_text(text)
        results = parse(text, spec["harnesses"])
        expected = harnesses(suite)
        missing = [name for name in expected if name not in results]
        for name in expected:
            r = results.get(name, {"harness": name, "verified": False, "failed": ["did not run"]})
            ok &= r["verified"]
            mark = "verified" if r["verified"] else "FAILED"
            print(f"{suite:9} {name:62} {mark:8} {r.get('seconds') or 0:6.1f}s {'; '.join(r['failed'] + r.get('vacuous', []))}")
            report.append({"suite": suite, **r})
        print(f"{suite:9} {'(compile and verify, wall)':62} {'':8} {seconds:6.1f}s")
        if code != 0 or missing:
            ok = False
            print(f"kani: the {suite} run exited {code}; see {logs / (suite + '.log')}", file=sys.stderr)
            errors = [line for line in text.splitlines() if line.startswith("error")]
            if errors:
                print("\n".join(errors)[-2000:], file=sys.stderr)
    out = {"kani": kani_version, "cbmc": cbmc, "inputs": inputs, "sha256": digest(inputs),
           "passed": [r["harness"] for r in report if r["verified"]] if ok else [], "harnesses": report}
    (OUT / "kani.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"kani: {'all harnesses verified' if ok else 'FAILED'}; report in {OUT / 'kani.json'}")
    return 0 if ok else 1


def mirror(tree):
    """A scratch copy of what the Kani builds read, so a mutant never touches the checkout."""
    if tree.exists():
        shutil.rmtree(tree)
    for path in MIRROR:
        src, dst = ROOT / path, tree / path
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target"))
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def mutants(only):
    chosen = [m for m in load_mutants() if not only or any(n in m["name"] for n in only)]
    version()
    work = ROOT / "target/kani-mutants"
    report, ok = [], True
    for m in chosen:
        spec = SUITES[m["suite"]]
        tree = work / "tree"
        mirror(tree)
        (tree / m["file"]).write_text(m["mutated"], encoding="utf-8")
        args = [*spec["args"], "--harness", f"{spec['module']}::{m['breaks']}", "--exact"]
        code, text, seconds = kani(tree / spec["dir"], args, work / "target")
        (work / f"{re.sub(r'\W+', '-', m['name'])}.log").write_text(text)
        result = parse(text, spec["harnesses"]).get(m["breaks"])
        # It counts only if it compiled and Kani found an input that breaks the promise.
        caught = result is not None and not result["verified"] and bool(result["failed"])
        ok &= caught
        print(f"{'caught' if caught else 'MISSED':6} {m['name']:58} {m['breaks']:52} {seconds:5.1f}s  "
              f"{'; '.join(result['failed']) if result else 'did not compile or run'}")
        report.append({"mutant": m["name"], "file": m["file"], "breaks": m["breaks"], "caught": caught,
                       "failed": result["failed"] if result else [], "seconds": round(seconds, 1)})
    shutil.rmtree(work / "tree", ignore_errors=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "kani-mutants.json").write_text(json.dumps({"caught": sum(r["caught"] for r in report), "total": len(report), "mutants": report}, indent=2) + "\n")
    print(f"kani: {sum(r['caught'] for r in report)} of {len(report)} mutants caught; report in {OUT / 'kani-mutants.json'}")
    return 0 if ok else 1


def main():
    args = sys.argv[1:]
    if not args:
        return prove()
    if args[0] == "mutants":
        return mutants(args[1:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

import importlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

claims_check = importlib.import_module("claims_check")
policy_check = importlib.import_module("policy_check")

ABSENT = object()
PROVED = "ALL PROOFS CHECK"
LAB_DIR = re.compile(r"results/ci/lab-([0-9a-f]{40})")
SUITES = ("attack-suite.json", "live-suite.json")
WAIVERS = ("cgroup_limits_waived", "controls_cgroup_limits_waived")
MUTANT_FLAGS = (("bend", ("rejected", "witness")), ("rust", ("rejected",)))
OUTCOMES = (("scenario", "runs", "scenario", "passed", True), ("sabotage", "sabotage", "weakness", "detected", False))


def show(value):
    return "absent" if value is ABSENT else json.dumps(value)


def at(data, key):
    return data.get(key, ABSENT) if isinstance(data, dict) else ABSENT


def is_int(value):
    return type(value) is int


def is_true(value):
    return value is True


def is_false(value):
    return value is False


def is_zero(value):
    return is_int(value) and value == 0


def is_proved(value):
    return value == PROVED


def lost(metric, before, after, holds):
    return [f"{metric}: {show(before)} -> {show(after)}"] if holds(before) and not holds(after) else []


def fell(metric, before, after, floor=None):
    if not is_int(before) or (is_int(after) and after >= before):
        return []
    below = "" if floor is None or (is_int(after) and after >= floor) else f", below MIN_DIFF_SEQUENCES {floor}"
    return [f"{metric}: {show(before)} -> {show(after)}{below}"]


def named(items, key):
    if not isinstance(items, list):
        return {}
    return {item[key]: item for item in items if isinstance(item, dict) and isinstance(item.get(key), str)}


def tla(base, head):
    out, now = [], named(at(head, "runs"), "config")
    for name, run in named(at(base, "runs"), "config").items():
        if name not in now:
            out.append(f"config {name}: present -> absent")
            continue
        out += lost(f"config {name} as_expected", at(run, "as_expected"), at(now[name], "as_expected"), is_true)
        if at(run, "expected") == "pass" and is_true(at(run, "as_expected")):
            if at(now[name], "expected") != "pass":
                out.append(f"config {name} expected: pass -> {show(at(now[name], 'expected'))}")
            out += fell(f"config {name} distinct_states", at(run, "distinct_states"), at(now[name], "distinct_states"))
    return out


def killers(report):
    out = {}
    for name, mutant in named(at(report, "bend"), "mutant").items():
        laws = at(mutant, "laws_violated")
        for law in laws if isinstance(laws, list) else ():
            if isinstance(law, str):
                out.setdefault(law, []).append(name)
    return out


def mutation(base, head):
    out = []
    for metric in ("bend_rejected", "rust_rejected"):
        out += fell(metric, at(base, metric), at(head, metric))
    for kind, flags in MUTANT_FLAGS:
        now = named(at(head, kind), "mutant")
        for name, mutant in named(at(base, kind), "mutant").items():
            for flag in flags:
                out += lost(f"{kind} mutant {name} {flag}", at(mutant, flag), at(now.get(name), flag), is_true)
    kept = killers(head)
    for law, names in sorted(killers(base).items()):
        if law not in kept:
            out.append(f"law {law} broken by mutants: {show(sorted(names))} -> []")
    return out


def differential(base, head):
    out = []
    for metric in ("sequences", "transitions"):
        out += fell(metric, at(base, metric), at(head, metric), claims_check.MIN_DIFF_SEQUENCES)
    return out + lost("mismatches", at(base, "mismatches"), at(head, "mismatches"), is_zero)


def verdict(base, head):
    return lost("result", at(base, "result"), at(head, "result"), is_proved)


def outcomes(items, key, flag, honest):
    out = {}
    for item in items if isinstance(items, list) else ():
        if isinstance(item, dict) and isinstance(item.get(key), str) and not (honest and item.get("weakness", "none") != "none"):
            out[item[key]] = out.get(item[key], True) and is_true(item.get(flag))
    return out


def suite(base, head):
    out = fell("timed_repeat", at(base, "timed_repeat"), at(head, "timed_repeat"))
    for waiver in WAIVERS:
        out += lost(waiver, at(base, waiver), at(head, waiver), is_false)
    for label, field, key, flag, honest in OUTCOMES:
        now = outcomes(at(head, field), key, flag, honest)
        for name, ok in outcomes(at(base, field), key, flag, honest).items():
            out += lost(f"{label} {name} {flag}", ok, now.get(name, ABSENT), is_true)
    return out


FILES = (
    ("results/tla-check.json", tla),
    ("results/mutation-check.json", mutation),
    ("results/differential.json", differential),
    ("results/wasm-differential.json", differential),
    ("results/formal-verdict.json", verdict),
    ("results/attack-suite.json", suite),
    ("results/live-suite.json", suite),
)


def pairs(base_lab, head_lab):
    out = [(path, path, compare) for path, compare in FILES]
    if base_lab is not None:
        out += [(f"{base_lab}/{name}", head_lab and f"{head_lab}/{name}", suite) for name in SUITES]
    return out


def parsed(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def weakenings(base_get, head_get, base_lab=None, head_lab=None):
    out = []
    for base_path, head_path, compare in pairs(base_lab, head_lab):
        base = parsed(base_get(base_path))
        if not isinstance(base, dict):
            continue
        where = head_path or base_path
        note = "" if where == base_path else f" (base {base_path})"
        text = head_get(head_path) if head_path else None
        head = parsed(text)
        if text is None:
            out.append((where, "present at the base, absent at the head" + note))
        elif not isinstance(head, dict):
            out.append((where, "not a JSON object at the head"))
        else:
            out += [(where, message + note) for message in compare(base, head)]
    return out


def newest_lab(dirs, distance):
    ranked = sorted((n, d) for d in dirs if (m := LAB_DIR.fullmatch(d)) and (n := distance(m.group(1))) is not None)
    return ranked[0][1] if ranked else None


def distance(sha, ref):
    try:
        policy_check.git("merge-base", "--is-ancestor", sha, ref)
    except subprocess.CalledProcessError:
        return None
    return int(policy_check.git("rev-list", "--count", f"{sha}..{ref}"))


def resolved_lab(dirs, ref, side):
    runs = [d for d in dirs if LAB_DIR.fullmatch(d)]
    lab = newest_lab(runs, lambda sha: distance(sha, ref))
    if runs and lab is None:
        raise LookupError(f"no results/ci/lab-* run at the {side} is an ancestor of {ref}; fetch full history")
    return lab


def head_get(path):
    target = policy_check.ROOT / path
    return target.read_bytes().decode("utf-8", "replace") if target.is_file() else None


def ratchet(base=None):
    base = base or policy_check.git("merge-base", "HEAD", "origin/main").strip()
    base_dirs = [d for d in policy_check.git("ls-tree", "--name-only", base, "results/ci/").splitlines() if d]
    head_dirs = sorted(p.relative_to(policy_check.ROOT).as_posix() for p in (policy_check.ROOT / "results/ci").glob("lab-*")
                       if p.is_dir())
    return weakenings(policy_check.reader(base), head_get, resolved_lab(base_dirs, base, "base"),
                      resolved_lab(head_dirs, "HEAD", "head"))

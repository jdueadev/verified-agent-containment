import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
STAGES = ("t0", "t1", "pr", "rc", "release")
EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_MISSING = 0, 1, 2, 3


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    message: str


@dataclass
class Ctx:
    root: Path = ROOT
    base: str | None = None
    changed: tuple[str, ...] | None = None
    stage: str = "t0"
    memo: dict = field(default_factory=dict)

    def once(self, key, compute):
        if key not in self.memo:
            self.memo[key] = compute()
        return self.memo[key]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    stages: frozenset
    watches: tuple
    check: Callable
    fix: str
    refs: tuple
    needs: tuple = ()
    corpus: str | None = None


@dataclass(frozen=True)
class Outcome:
    rule: Rule
    status: str
    findings: tuple
    missing: tuple


def matches(path, pattern):
    if pattern.endswith("/**"):
        return path == pattern[:-3] or path.startswith(pattern[:-2])
    return Path(path).match(pattern) if "*" in pattern else path == pattern


def watched(rule, changed):
    return changed is None or any(matches(p, w) for p in changed for w in rule.watches)


def missing_tools(rule):
    return tuple(t for t in rule.needs if shutil.which(t) is None)


def run(rules, stage, ctx):
    ctx.stage = stage
    outcomes = []
    for rule in rules:
        if stage not in rule.stages or not watched(rule, ctx.changed):
            continue
        lacking = missing_tools(rule)
        if lacking:
            outcomes.append(Outcome(rule, "MISSING", (), lacking))
            continue
        findings = tuple(rule.check(ctx))
        outcomes.append(Outcome(rule, "FAIL" if findings else "PASS", findings, ()))
    return outcomes


def exit_code(outcomes):
    if any(o.status == "FAIL" for o in outcomes):
        return EXIT_FAIL
    if any(o.status == "MISSING" for o in outcomes):
        return EXIT_MISSING
    return EXIT_PASS


def tier(outcomes, stage, complete=True):
    if stage != "t1" or not complete or not outcomes or any(o.status != "PASS" for o in outcomes):
        return "T0"
    return "T1"


def summary(outcomes, stage, complete=True):
    failed = sum(o.status == "FAIL" for o in outcomes)
    lacking = sorted({t for o in outcomes for t in o.missing})
    return {"result": ["pass", "fail", "usage", "missing"][exit_code(outcomes)], "stage": stage,
            "ran": len(outcomes), "failed": failed, "tier": tier(outcomes, stage, complete), "missing": lacking}


def render_text(outcomes, stage, out=sys.stdout, complete=True):
    for o in outcomes:
        for f in o.findings:
            where = f"{f.path}:{f.line}" if f.line else f.path
            print(f"FAIL {f.rule} {where} {f.message} | fix: {o.rule.fix}", file=out)
        if o.status == "MISSING":
            print(f"MISSING {o.rule.id} needs {', '.join(o.missing)} | fix: install them or run in the pinned container",
                  file=out)
    s = summary(outcomes, stage, complete)
    print(f"vac: {s['result']} {s['failed']}/{s['ran']} rules failed stage={stage} tier={s['tier']}"
          + (f" missing={','.join(s['missing'])}" if s["missing"] else ""), file=out)


def render_json(outcomes, stage, out=sys.stdout, complete=True):
    for o in outcomes:
        for f in o.findings:
            print(json.dumps({"rule": f.rule, "status": "FAIL", "path": f.path, "line": f.line,
                              "message": f.message, "fix": o.rule.fix, "refs": list(o.rule.refs)}), file=out)
        if o.status == "MISSING":
            print(json.dumps({"rule": o.rule.id, "status": "MISSING", "missing": list(o.missing),
                              "fix": "install them or run in the pinned container"}), file=out)
    print(json.dumps({"summary": summary(outcomes, stage, complete)}), file=out)


def run_tool(ctx, key, argv, timeout=1800):
    def compute():
        child = subprocess.run(argv, cwd=ctx.root, capture_output=True, text=True, timeout=timeout)
        return child.returncode, child.stdout, child.stderr
    return ctx.once(key, compute)


def git(ctx, *args):
    return subprocess.run(["git", "-C", str(ctx.root), *args], capture_output=True, text=True, check=True).stdout


def changed_paths(ctx, base):
    return tuple(p for p in git(ctx, "diff", "--name-only", "--no-renames", f"{base}...HEAD").splitlines() if p) + tuple(
        p for p in git(ctx, "diff", "--name-only", "--no-renames", "HEAD").splitlines() if p)

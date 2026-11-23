#!/usr/bin/env python3
"""No-root driver for this repository.

One command surface for the paths that do not need root:

  vac build
      cargo build -q --locked -p containment-host
  vac check [--only NAME]
      The T0 checks, one by one, streaming, continuing after a failure.
      Does not run scripts/check.sh (that rewrites results/).
  vac run sim [driver args...]
  vac run servers
      Pass through to the local node driver.
  vac status
      Checkout, binary freshness, toolchain.
  vac preflight [--engine auto|podman|docker|host]
      Before a root lab run: everything that needs no root. In the check
      container (scripts/check-in-container.sh) when it and an engine are
      present, otherwise the host crate's tests and both release builds on the
      host. Then it names the lab evidence it did NOT exercise. Always T0, and
      it records nothing.
  vac lab plan
      Print the steps for the maintainer's root lab run (T2) on main, and the
      stale claims it would refresh. It runs only the read-only strict claims
      check and git rev-parse.
  vac attack-suite|live|live-suite|redteam|ctl|hud
      Refused with exit 2. AGENTS.md INV-11: throwaway machine only.

After every command, `git status --porcelain -- results/` is compared with
the snapshot from the start. A change under results/ is a loud warning.
The tier line is always T0, and it names only checks that passed.
"""
import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_ARGV = ("cargo", "build", "-q", "--locked", "-p", "containment-host")
DRIVER_REL = Path(".claude/skills/run-verified-agent-containment/driver.mjs")
LAB_REL = Path("target/debug/containment-lab")
REFUSED = ("attack-suite", "live", "live-suite", "redteam", "ctl", "hud")
# Same relative paths the node driver searches under ~/.cache/ms-playwright.
CHROMIUM_REL = (
    "chrome-linux/headless_shell",
    "chrome-headless-shell-linux64/chrome-headless-shell",
    "chrome-linux/chrome",
    "chrome-linux64/chrome",
)
STATUSES = ("PASS", "FAIL", "SKIPPED")
# Evidence only the root lab produces. A preflight never exercises these.
LAB_KINDS = ("scenario", "sabotage", "live", "live-sabotage")
CONTAINER_WRAPPER = Path("scripts/check-in-container.sh")
ENGINES = ("auto", "podman", "docker", "host")

Check = namedtuple("Check", "name argv")
HOST_PREFLIGHT = (
    ("host-tests", ("cargo", "test", "-q", "--locked", "-p", "containment-host")),
    ("host-tests-sabotage", ("cargo", "test", "-q", "--locked", "-p", "containment-host", "--features", "sabotage")),
    ("release-build", ("cargo", "build", "-q", "--locked", "--release", "-p", "containment-host")),
    ("release-build-sabotage", ("cargo", "build", "-q", "--locked", "--release", "-p", "containment-host",
                                "--features", "sabotage", "--target-dir", "target-sabotage")),
)


def quote_cmd(argv):
    return " ".join(shlex.quote(str(part)) for part in argv)


def git(args, cwd=None):
    """Run git. Returns (returncode, stdout, stderr). None if git cannot start."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return None, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


def git_ref_exists(ref):
    code, _out, _err = git(["rev-parse", "--verify", "--quiet", ref])
    return code == 0


def results_porcelain():
    """Stdout of `git status --porcelain -- results/`, or None if git failed."""
    code, out, _err = git(["status", "--porcelain", "--", "results/"])
    if code != 0:
        return None
    return out


def warn_results(before):
    after = results_porcelain()
    banner = "!" * 72
    if before is None or after is None:
        print(
            f"\n{banner}\n"
            "vac: WARNING: could not check `git status --porcelain -- results/`.\n"
            "This driver must not change results/ (AGENTS.md INV-1).\n"
            f"{banner}",
            file=sys.stderr,
        )
        return
    if before == after:
        return
    shown = after if after.strip() else "(clean)\n"
    print(
        f"\n{banner}\n"
        "vac: WARNING: results/ changed during this run.\n"
        "`git status --porcelain -- results/` differs from the start of the command.\n"
        "AGENTS.md INV-1: evidence comes only from runs that happened. "
        "This driver must not write results/.\n"
        "status now:\n"
        f"{shown}"
        f"{banner}",
        file=sys.stderr,
    )


def run_streaming(argv, env=None):
    """Run argv with inherited stdio. Returns the exit code, or 127 if it cannot start."""
    shown = "".join(f"{key}={shlex.quote(value)} " for key, value in sorted((env or {}).items()))
    print("+ " + shown + quote_cmd(argv), flush=True)
    try:
        proc = subprocess.run(list(argv), cwd=ROOT, env={**os.environ, **env} if env else None)
    except OSError as exc:
        print(f"vac: could not run {argv[0]}: {exc}", file=sys.stderr, flush=True)
        return 127
    return proc.returncode


def format_summary(rows):
    """Render the check table and the tier line.

    The tier is always T0. The parenthetical names only checks that passed.
    """
    name_w = max([len("check")] + [len(name) for name, _status, _seconds in rows])
    lines = [
        f"{'check':<{name_w}}  {'result':<7}  seconds",
        f"{'-' * name_w}  {'-' * 7}  {'-' * 7}",
    ]
    passed = []
    for name, status, seconds in rows:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        lines.append(f"{name:<{name_w}}  {status:<7}  {seconds:7.2f}")
        if status == "PASS":
            passed.append(name)
    listed = ", ".join(passed) if passed else "none"
    lines.append(f"tier: T0 (checks run: {listed})")
    return "\n".join(lines) + "\n"


def cmd_build(_args):
    return run_streaming(BUILD_ARGV)


def load_registry():
    sys.path.insert(0, str(ROOT / "tools"))
    import importlib
    return importlib.import_module("vac_core"), importlib.import_module("vac_rules")


def cmd_check(args):
    core, registry = load_registry()
    stage = "t1" if args.t1 else args.stage
    ctx = core.Ctx(root=ROOT)
    if args.changed:
        ctx.changed = core.changed_paths(ctx, args.changed)
    rules = registry.RULES
    if args.rule:
        rules = tuple(r for r in rules if r.id in args.rule)
        unknown = sorted(set(args.rule) - {r.id for r in rules})
        if unknown:
            print(f"vac: unknown rule {', '.join(unknown)}; vac rules lists them", file=sys.stderr)
            return core.EXIT_USAGE
    outcomes = core.run(rules, stage, ctx)
    (core.render_json if args.json else core.render_text)(outcomes, stage)
    return core.exit_code(outcomes)


def cmd_rules(args):
    core, registry = load_registry()
    for rule in registry.RULES:
        print(f"{rule.id}\t{','.join(s for s in core.STAGES if s in rule.stages)}\t{rule.title}")
    return 0


def cmd_explain(args):
    core, registry = load_registry()
    hits = [r for r in registry.RULES if r.id == args.target]
    if not hits:
        hits = [r for r in registry.RULES if any(core.matches(args.target, w) for w in r.watches)]
    if not hits:
        print(f"vac: no rule is named or watches {args.target}", file=sys.stderr)
        return core.EXIT_USAGE
    for rule in hits:
        print(f"{rule.id}: {rule.title}")
        print(f"  stages: {', '.join(s for s in core.STAGES if s in rule.stages)}")
        print(f"  watches: {', '.join(rule.watches)}")
        print(f"  fix: {rule.fix}")
        print(f"  refs: {', '.join('#' + str(n) for n in rule.refs)}")
        if rule.needs:
            print(f"  needs: {', '.join(rule.needs)}")
    return 0


def cmd_comments(args):
    sys.path.insert(0, str(ROOT / "tools"))
    import importlib
    comments = importlib.import_module("vac_comments")
    if args.debt_write and args.paths:
        print("vac: --debt-write regenerates the whole list and takes no PATH", file=sys.stderr)
        return 2
    if args.debt_write:
        return comments.debt_write(ROOT)
    return comments.listing(ROOT, args.paths, args.json)


def node_too_old(node):
    """Return an error string when `node` is missing or older than 22, else None."""
    if not node:
        return "vac: node is not on PATH. The driver needs Node 22 or newer."
    try:
        proc = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"vac: could not read node --version: {exc}"
    text = (proc.stdout or proc.stderr).strip()
    digits = text[1:] if text.startswith("v") else text
    major_text = digits.split(".", 1)[0]
    try:
        major = int(major_text)
    except ValueError:
        return f"vac: could not parse node version {text!r}. The driver needs Node 22 or newer."
    if major < 22:
        return f"vac: node {text} is older than 22. The driver needs Node 22 or newer."
    return None


def cmd_run(target, driver_args):
    driver = ROOT / DRIVER_REL
    if not driver.is_file():
        print(
            f"vac: cannot run {target}: the node driver is absent ({DRIVER_REL}). "
            "It is the local skill file "
            ".claude/skills/run-verified-agent-containment/driver.mjs "
            "(that directory is not part of the tracked tree). Restore it and retry.",
            file=sys.stderr,
        )
        return 1
    node = shutil.which("node")
    complaint = node_too_old(node)
    if complaint:
        print(complaint, file=sys.stderr)
        return 1
    argv = [node, str(driver), target, *driver_args]
    return run_streaming(argv)


def iso(timestamp):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def newest_crates_source():
    """(mtime, path) of the newest regular file under crates/, or None."""
    root = ROOT / "crates"
    newest = None
    if not root.is_dir():
        return None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            try:
                if not path.is_file():
                    continue
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest[0]:
                newest = (mtime, path)
    return newest


def find_chromium():
    """Chromium the node driver would use: $CHROMIUM, else the Playwright cache.

    Returns (path or None, detail). detail explains a miss.
    """
    env = os.environ.get("CHROMIUM")
    if env:
        if Path(env).is_file():
            return env, "CHROMIUM"
        return None, f"CHROMIUM is set but is not a file ({env})"
    cache = Path.home() / ".cache" / "ms-playwright"
    if not cache.is_dir():
        return None, "CHROMIUM is unset and ~/.cache/ms-playwright is absent"
    dirs = sorted((path for path in cache.iterdir() if path.is_dir()), key=lambda path: path.name, reverse=True)
    for directory in dirs:
        for rel in CHROMIUM_REL:
            candidate = directory / rel
            if candidate.is_file():
                return str(candidate), "playwright cache"
    return None, "CHROMIUM is unset and ~/.cache/ms-playwright has no Chromium binary"


def tool_line(name):
    path = shutil.which(name)
    if not path:
        return f"  {name}: missing"
    version = ""
    try:
        # Run inside the checkout so a rustup proxy reports the toolchain
        # rust-toolchain.toml selects, which is the cargo `vac build` will use.
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=ROOT,
        )
        lines = (proc.stdout or proc.stderr).strip().splitlines()
        if lines:
            version = " " + lines[0]
    except (OSError, subprocess.TimeoutExpired):
        version = " (version unknown)"
    return f"  {name}: present {path}{version}"


def pinned_toolchain():
    path = ROOT / "rust-toolchain.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"unreadable ({exc})"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("channel") and "=" in stripped:
            return stripped.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def cmd_status(_args):
    code, head, err = git(["rev-parse", "HEAD"])
    print(f"head: {head.strip() if code == 0 else 'unknown (' + err.strip() + ')'}")
    code, branch, err = git(["rev-parse", "--abbrev-ref", "HEAD"])
    print(f"branch: {branch.strip() if code == 0 else 'unknown (' + err.strip() + ')'}")
    code, dirty, err = git(["status", "--porcelain"])
    print("dirty:")
    if code != 0:
        print(f"  (git status failed: {err.strip()})")
    elif not dirty.strip():
        print("  (clean)")
    else:
        for line in dirty.splitlines():
            print(f"  {line}")
    lab = ROOT / LAB_REL
    if not lab.is_file():
        print("containment-lab: missing (target/debug/containment-lab)")
        print("older-than-newest-crates-source: n/a")
    else:
        newest = newest_crates_source()
        lab_mtime = lab.stat().st_mtime
        print(f"containment-lab: present {LAB_REL.as_posix()} mtime {iso(lab_mtime)}")
        if newest is None:
            print("newest-crates-source: none")
            print("older-than-newest-crates-source: n/a")
        else:
            rel = newest[1].relative_to(ROOT).as_posix()
            print(f"newest-crates-source: {rel} mtime {iso(newest[0])}")
            older = "yes" if lab_mtime < newest[0] else "no"
            print(f"older-than-newest-crates-source: {older}")
    print("toolchain:")
    for name in ("cargo", "node", "python3"):
        print(tool_line(name))
    print(f"  rust-toolchain channel: {pinned_toolchain()}")
    chromium, detail = find_chromium()
    if chromium:
        print(f"  chromium: present {chromium} ({detail})")
    else:
        print(f"  chromium: missing ({detail})")
    return 0


def pick_engine(requested, which=shutil.which, wrapper_present=None):
    """The engine a preflight uses: podman, docker, or host. `auto` takes the check
    container when its wrapper is in this checkout and an engine is on PATH."""
    if wrapper_present is None:
        wrapper_present = (ROOT / CONTAINER_WRAPPER).is_file()
    if requested == "host":
        return "host"
    if requested in ("podman", "docker"):
        return requested if wrapper_present and which(requested) else None
    if wrapper_present:
        for engine in ("podman", "docker"):
            if which(engine):
                return engine
    return "host"


def preflight_steps(engine):
    """(name, argv, env) for each preflight step. None of them needs root, and none
    writes results/: the container judges a copy of the checkout, and the host
    steps only test and build into target/ and target-sabotage/."""
    if engine in ("podman", "docker"):
        return [("container", (str(CONTAINER_WRAPPER), "--no-strict"), {"ENGINE": engine})]
    return [(name, argv, None) for name, argv in HOST_PREFLIGHT]


def stale_lab_evidence(report, claims):
    """For each claim the strict claims check calls stale (CI-4), the lab-only
    evidence it cites and the platforms it was recorded on: what a preflight does
    not exercise and only a root lab run refreshes."""
    by_id = {claim["id"]: claim for claim in claims}
    out = []
    for error in report.get("errors", []):
        if not error.startswith("CI-4 "):
            continue
        cid = error.split()[1].rstrip(":")
        claim = by_id.get(cid)
        if claim is None:
            continue
        refs = [ref for ref in claim.get("evidence", []) if ref.partition(":")[0] in LAB_KINDS]
        platforms = sorted({p.get("name", "?") for p in claim.get("platforms", [])})
        out.append((cid, refs, platforms))
    return out


def read_stale_lab_evidence():
    """Run the strict claims check (it only reads) and map its CI-4 errors."""
    import json
    import tomllib
    try:
        proc = subprocess.run([sys.executable, "tools/claims_check.py", "--strict"], cwd=ROOT,
                              capture_output=True, text=True, timeout=600)
        report = json.loads(proc.stdout[proc.stdout.index("{"):])
        claims = tomllib.loads((ROOT / "claims.toml").read_text(encoding="utf-8"))["claim"]
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        return None, f"could not read the strict claims check: {exc}"
    # Only staleness is something a lab run fixes. Any other strict error means the
    # list of what the lab would refresh cannot be trusted, so it is unknown.
    other = [e for e in report.get("errors", []) if not e.startswith("CI-4 ")]
    if other or (proc.returncode != 0 and not report.get("errors")):
        shown = "; ".join(other[:3]) or f"exit {proc.returncode} with no errors listed"
        return None, f"the strict claims check failed for reasons other than staleness: {shown}"
    return stale_lab_evidence(report, claims), None


def format_not_exercised(stale, problem=None):
    """A preflight exercises no lab evidence at all; say so every time, then name
    the stale claims that only a root lab run refreshes."""
    lines = ["not exercised: any lab evidence (scenario, sabotage, live, live-sabotage); "
             "a preflight runs none of it and records nothing"]
    if problem:
        lines.append(f"stale claims needing the root lab (T2): unknown ({problem})")
    elif not stale:
        lines.append("stale claims needing the root lab (T2): none reported by the strict claims check")
    else:
        lines.append("stale claims needing the root lab (T2):")
        for cid, refs, platforms in stale:
            lines.append(f"  {cid}: {', '.join(refs) or '(no lab refs)'}  (platforms: {', '.join(platforms) or 'none'})")
    return "\n".join(lines) + "\n"


def cmd_preflight(args):
    engine = pick_engine(args.engine)
    if engine is None:
        print(f"vac: --engine {args.engine} needs {CONTAINER_WRAPPER} in this checkout and "
              f"{args.engine} on PATH", file=sys.stderr)
        return 2
    rows = []
    for name, argv, env in preflight_steps(engine):
        print(f"== {name} ==", flush=True)
        start = time.monotonic()
        code = run_streaming(argv, env)
        status = "PASS" if code == 0 else "FAIL"
        rows.append((name, status, time.monotonic() - start))
        print(f"-- {name}: {status}", flush=True)
    stale, problem = read_stale_lab_evidence()
    sys.stdout.write("\n" + format_summary(rows))
    sys.stdout.write(format_not_exercised(stale, problem))
    return 1 if any(status == "FAIL" for _name, status, _seconds in rows) else 0


def lab_plan_text(commit, stale, problem=None, head_note=""):
    """The maintainer's root lab run, as steps. Text only. `stale` is None when the
    strict claims check could not say."""
    if stale is None:
        claims = f"  - unknown: {problem or 'the strict claims check could not be read'}. Fix that first."
    else:
        claims = "\n".join(f"  - {cid}: {', '.join(refs) or '(no lab refs)'} (platforms: {', '.join(platforms) or 'none'})"
                           for cid, refs, platforms in stale) or "  - none: the strict claims check reports no stale claim"
    return f"""Root lab run (T2): the maintainer runs this, never an agent (AGENTS.md INV-11, T2).

Claims it would refresh (stale under --strict):
{claims}

Commit: {commit} (main). Lab evidence counts only for a commit on main (AGENTS.md).{head_note}

1. Preflight first, here, without root:  tools/vac.py preflight
   It must pass. It exercises none of the lab evidence above.
2. Make the bundle from a checkout detached at exactly that commit (lab-inside.sh
   clones it, so it must carry HEAD), and check the clone before you go on:
     git fetch origin main && git checkout --detach {commit}
     git bundle create repo.bundle HEAD
     git clone -q repo.bundle /tmp/bundle-check && git -C /tmp/bundle-check rev-parse HEAD
   The last line must print {commit}. Put repo.bundle in a lab folder on Windows
   with run-lab.cmd, lab.ps1 and lab-inside.sh from scripts/lab/.
3. Run the suites in a throwaway WSL2 distro (Windows interop disabled; the distro
   is removed at the end; no model):
     .\\run-lab.cmd -Only suites
   Do not use this distro or the maintainer distro for it. See scripts/lab/README.md.
4. Collect results\\<stamp>\\ (environment.txt, attack-suite.json, live-suite.json
   and the logs). Both suites must pass with limits enforced.
5. In a pull request of its own, from the maintainer's identity, add them as
   results/wsl2/lab-<short commit>/ and the platforms entries for the claims above
   (wsl2-<kernel>, commit, result). INV-1: an agent never writes these.
6. Check it with: python3 tools/claims_check.py --strict
"""


def cmd_lab(args):
    code, out, _err = git(["rev-parse", "--verify", "--quiet", "origin/main^{commit}"])
    commit = out.strip() if code == 0 else ""
    if not commit:
        print("vac: origin/main is missing; run `git fetch origin main` first, so the plan names a real commit",
              file=sys.stderr)
        return 1
    head_code, head, _err = git(["rev-parse", "HEAD"])
    head = head.strip() if head_code == 0 else ""
    note = "" if head == commit else (
        f"\nThe stale list below was computed from this checkout's HEAD ({head[:12] or 'unknown'}), "
        "not from that commit; run this on a checkout of origin/main to be sure.")
    stale, problem = read_stale_lab_evidence()
    sys.stdout.write(lab_plan_text(commit, stale, problem, note))
    if problem:
        print(f"vac: {problem}", file=sys.stderr)
    return 1 if problem else 0


def cmd_refuse(args):
    print(
        f"vac: refusing {args.command}: AGENTS.md INV-11 — the lab runs only in a "
        f"throwaway machine. {args.command} is not run from this driver "
        f"(attack-suite, live, live-suite, redteam, ctl and hud). "
        f"There is no override.",
        file=sys.stderr,
    )
    return 2


def build_parser():
    parser = argparse.ArgumentParser(
        prog="vac",
        description=(
            "No-root driver for verified-agent-containment. "
            "build, check, run and status do not invoke the root lab. "
            "attack-suite, live, live-suite, redteam, ctl and hud are refused "
            "(AGENTS.md INV-11, throwaway machine only)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="cargo build the containment-host binary")
    build.set_defaults(func=cmd_build)

    check = sub.add_parser(
        "check",
        help="run every registered rule for a stage (default t0)",
        description="Run the rules in tools/vac_rules.py. Exit 0 pass, 1 a rule failed, 2 usage, 3 a tool is missing.",
    )
    check.add_argument("--t1", action="store_true", help="run stage t1, the full gate; tier T1 only if every rule ran and passed")
    check.add_argument("--stage", choices=("t0", "t1", "pr", "rc", "release"), default="t0")
    check.add_argument("--changed", metavar="BASE", help="run only rules watching paths changed since BASE")
    check.add_argument("--rule", action="append", metavar="ID", help="run only this rule (repeatable)")
    check.add_argument("--json", action="store_true", help="JSON Lines with a final summary object")
    check.set_defaults(func=cmd_check)

    rules = sub.add_parser("rules", help="list every rule: id, stages, title")
    rules.set_defaults(func=cmd_rules)

    explain = sub.add_parser("explain", help="explain a rule id, or the rules that watch a path")
    explain.add_argument("target")
    explain.set_defaults(func=cmd_explain)

    comments = sub.add_parser(
        "comments",
        help="list the comments NC-1 counts, or shrink ci/comment_debt.toml",
        description=("List every comment, docstring and unreadable construct the NC rules count, in each PATH or in "
                     "every tracked file. --debt-write drops the files that are now clean from ci/comment_debt.toml "
                     "(it creates the file when absent and never adds to it)."),
    )
    comments.add_argument("paths", nargs="*", metavar="PATH")
    comments.add_argument("--json", action="store_true", help="one JSON object per span")
    comments.add_argument("--debt-write", action="store_true", help="drop clean files from ci/comment_debt.toml")
    comments.set_defaults(func=cmd_comments)

    run = sub.add_parser(
        "run",
        help="pass through to the no-root node driver",
        description=(
            "Pass the remaining arguments through to "
            "node .claude/skills/run-verified-agent-containment/driver.mjs. "
            "sim drives the browser simulator; servers smoke-tests the "
            "unprivileged containment-lab test servers."
        ),
    )
    run_sub = run.add_subparsers(dest="run_command", required=True)
    sim = run_sub.add_parser(
        "sim",
        help="drive the browser simulator (args are passed through)",
        description=(
            "Run the node driver subcommand `sim`. "
            "Arguments after `sim` are passed through unchanged."
        ),
    )
    sim.set_defaults(func=lambda args: cmd_run("sim", []))
    servers = run_sub.add_parser(
        "servers",
        help="smoke-test mock-model and fixture-server",
        description=(
            "Run the node driver subcommand `servers`. "
            "Arguments after `servers` are passed through unchanged."
        ),
    )
    servers.set_defaults(func=lambda args: cmd_run("servers", []))

    status = sub.add_parser("status", help="print checkout, binary and toolchain status")
    status.set_defaults(func=cmd_status)

    preflight = sub.add_parser(
        "preflight",
        help="before a root lab run: everything that needs no root (T0)",
        description=(
            "Run what needs no root before a root lab run: the check container when "
            "available, else the host crate's tests and both release builds. Then name "
            "the lab evidence it did not exercise. T0; records nothing."
        ),
    )
    preflight.add_argument("--engine", choices=ENGINES, default="auto",
                           help="auto (default), podman, docker, or host")
    preflight.set_defaults(func=cmd_preflight)

    lab = sub.add_parser("lab", help="print the steps for the maintainer's root lab run (runs nothing)")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    plan = lab_sub.add_parser("plan", help="print the root lab run steps",
                              description=("Print the maintainer's root lab run (T2) as steps. It runs only "
                                           "the read-only strict claims check and git rev-parse."))
    plan.set_defaults(func=cmd_lab)

    for name in REFUSED:
        refused = sub.add_parser(
            name,
            help="refused (AGENTS.md INV-11, throwaway machine only)",
            description=(
                f"{name} is refused with exit 2. "
                "AGENTS.md INV-11: the lab runs only in a throwaway machine. "
                "This driver has no override."
            ),
        )
        refused.set_defaults(func=cmd_refuse)
    return parser


def wants_help(argv):
    return any(arg in ("-h", "--help") for arg in argv)


def dispatch_run(rest):
    """Handle `vac run ...`, passing driver arguments through argparse."""
    parser = build_parser()
    if not rest or rest[0] not in ("sim", "servers"):
        parser.parse_args(["run", *rest])
        return 2
    return cmd_run(rest[0], rest[1:])


def dispatch(argv):
    # `run sim` and `run servers` take the driver's own flags. Argparse would
    # reject those, so pass them through unless this invocation is asking us
    # for help.
    if argv[:1] == ["run"] and not wants_help(argv):
        return dispatch_run(argv[1:])
    args = build_parser().parse_args(argv)
    return args.func(args)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    before = results_porcelain()
    try:
        return dispatch(argv)
    finally:
        warn_results(before)


if __name__ == "__main__":
    sys.exit(main())

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

Check = namedtuple("Check", "name argv")
CHECKS = (
    Check("policy", ("python3", "tools/policy_check.py", "invariants")),
    Check("claims", ("python3", "tools/claims_check.py", "--affected", "origin/main")),
    Check("kernel", ("cargo", "test", "-q", "--locked", "-p", "containment-kernel")),
    Check("differential", ("target/debug/containment-lab", "differential-cases", "3", "24301")),
    Check("unittest", ("python3", "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py")),
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


def run_streaming(argv):
    """Run argv with inherited stdio. Returns the exit code, or 127 if it cannot start."""
    print("+ " + quote_cmd(argv), flush=True)
    try:
        proc = subprocess.run(list(argv), cwd=ROOT)
    except OSError as exc:
        print(f"vac: could not run {argv[0]}: {exc}", file=sys.stderr, flush=True)
        return 127
    return proc.returncode


def run_one(check):
    """Run one T0 check. Returns (status, seconds). status is PASS, FAIL or SKIPPED."""
    start = time.monotonic()
    if check.name == "claims" and not git_ref_exists("origin/main"):
        print("SKIPPED claims: origin/main is missing", flush=True)
        return "SKIPPED", time.monotonic() - start
    if check.name == "differential":
        lab = ROOT / LAB_REL
        if not lab.is_file():
            print(
                "differential: target/debug/containment-lab is missing; building it first",
                flush=True,
            )
            code = run_streaming(BUILD_ARGV)
            if code != 0 or not lab.is_file():
                print("vac: differential build failed", file=sys.stderr, flush=True)
                return "FAIL", time.monotonic() - start
    code = run_streaming(check.argv)
    status = "PASS" if code == 0 else "FAIL"
    return status, time.monotonic() - start


def run_selected(checks, run_one_fn):
    """Run every check. A failure does not stop the rest.

    run_one_fn(check) -> (status, seconds). Exit code is 1 when any check
    ran and failed. SKIPPED is not a failure.
    """
    rows = []
    for check in checks:
        print(f"== {check.name} ==", flush=True)
        status, seconds = run_one_fn(check)
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r} from {check.name}")
        rows.append((check.name, status, seconds))
        print(f"-- {check.name}: {status} ({seconds:.2f}s)", flush=True)
    failed = any(status == "FAIL" for _name, status, _seconds in rows)
    return rows, (1 if failed else 0)


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


def cmd_check(args):
    checks = CHECKS
    if args.only is not None:
        checks = tuple(check for check in CHECKS if check.name == args.only)
        if not checks:
            names = ", ".join(check.name for check in CHECKS)
            print(f"vac: unknown check {args.only!r}. Names: {names}", file=sys.stderr)
            return 2
    rows, code = run_selected(checks, run_one)
    sys.stdout.write("\n")
    sys.stdout.write(format_summary(rows))
    return code


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
        # /tmp so a rustup proxy does not treat this status query as a build
        # in the checkout (rust-toolchain.toml would otherwise select the pin).
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd="/tmp",
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
        help="run the T0 checks (continues after a failure)",
        description=(
            "Run the T0 checks one by one and keep going after a failure. "
            "Print a summary table and a tier line that names only the checks "
            "that passed. Does not run scripts/check.sh."
        ),
    )
    check.add_argument(
        "--only",
        metavar="NAME",
        choices=[item.name for item in CHECKS],
        help="run a single check instead of the whole T0 set",
    )
    check.set_defaults(func=cmd_check)

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

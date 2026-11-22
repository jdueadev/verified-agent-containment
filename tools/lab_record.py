#!/usr/bin/env python3
"""Turn a CI lab run into evidence: committed results plus platform entries (#53, AC-051).

Usage:
  lab_record.py --results DIR --commit SHA --platform NAME [--root DIR]
  lab_record.py --verify [--root DIR]

DIR is what scripts/lab/ci-lab.sh produced on a disposable runner:
attack-suite-local.json and live-suite-local.json (each holds the honest runs and
the sabotage controls, stamped with both binaries), and environment.txt.

Nothing is written unless all of this holds:
  - CI-8 (claims_check.build_errors): the honest runs come from a default build and
    the controls from a different, sabotage build; the attack suite is a full,
    unwaived run (timed_repeat >= 30, no waived cgroup limits).
  - For every lab claim (a row that already has a passing platform entry), each
    `scenario:` or `live:` reference has at least one honest run in its own suite
    and every such run passed, and each `sabotage:` or `live-sabotage:` reference
    has at least one control in its own suite and every such control detected its
    defect. A lab claim with none of these references is not something this run
    can show, which is an error.
  - No claim already records this platform at this commit.

It also requires environment.txt to name SHA and the two binaries the JSON is
stamped with. Only claims in a layer a CI run speaks for (CI_LAYERS: "host") are recorded; an "os"
claim such as L-ISO-02 (WSL2's interop handler) is reported as skipped and keeps
the entries of labs that run that operating system. Then it copies the three files to results/ci/lab-<sha>/ (the full
SHA) and appends one entry,
`{ name = NAME, commit = <sha>, result = "pass (lab evidence: results/ci/lab-<sha>; ...)" }`, to
the `platforms` line of every lab claim. It re-reads claims.toml afterwards and
refuses if anything but those entries changed. It never writes a failing claim as
"pass": a claim the run does not support stops the whole record.

--verify re-checks every recorded CI entry against the files it names and the claims
as they are now, and writes nothing. scripts/lab/ci-lab.sh runs it on every pull
request, so an evidence PR whose claims changed after recording fails `lab`.

This runs in the lab workflow's record job, which does not build or run host code.
The entries it writes are a `platforms` edit, so the evidence PR is lane C and the
maintainer approves it (INV-1: evidence comes only from runs that happened).
"""
import argparse
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims_check  # noqa: E402  (trusted base, lane C)

SUITES = {"attack-suite.json": "attack-suite-local.json", "live-suite.json": "live-suite-local.json"}
ENVIRONMENT = "environment.txt"
PLATFORM_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
SAFE_TEXT = re.compile(r"[A-Za-z0-9._+-]{1,80}")


class RecordError(Exception):
    """The run cannot be recorded as evidence."""


def load_results(results_dir, committed=False):
    """The two suites' JSON from a run directory (`*-local.json`) or, with `committed`,
    from a recorded results/ci/lab-<sha>/ directory (`attack-suite.json`, ...)."""
    results_dir = Path(results_dir)
    out = {}
    for name, source in SUITES.items():
        path = results_dir / (name if committed else source)
        if not path.is_file():
            raise RecordError(f"{path} is missing")
        out[name] = json.loads(path.read_text(encoding="utf-8"))
    if not (results_dir / ENVIRONMENT).is_file():
        raise RecordError(f"{results_dir / ENVIRONMENT} is missing")
    return out


def build_errors(results):
    """CI-8, with the base copy of claims_check, on the files as they will be committed."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in results.items():
            (Path(tmp) / name).write_text(json.dumps(data), encoding="utf-8")
        return claims_check.build_errors(Path(tmp))


# Evidence kind -> (suite file, "runs" or "sabotage"). Each kind is looked up only in
# its own suite, so a live scenario cannot be satisfied by an attack-suite run.
REF_KINDS = {
    "scenario": ("attack-suite.json", "runs"),
    "sabotage": ("attack-suite.json", "sabotage"),
    "live": ("live-suite.json", "runs"),
    "live-sabotage": ("live-suite.json", "sabotage"),
}


def environment_errors(text, commit, results):
    """environment.txt must name this commit and the two binaries the JSON is stamped with,
    so results cannot be recorded against a commit they did not come from."""
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(": ")
        if sep and key not in fields:
            fields[key] = value.strip()
    out = []
    if fields.get("commit id") != commit:
        out.append(f"environment.txt names commit {fields.get('commit id')!r}, not {commit}")
    for part, key in (("honest", "default binary sha256"), ("sabotage", "sabotage binary sha256")):
        for name, data in results.items():
            stamp = ((data.get("build") or {}).get(part) or {}).get("binary_sha256")
            if fields.get(key) != stamp:
                out.append(f"environment.txt {key} does not match the {part} stamp in {name}")
    return out


def claim_support(claim, results):
    """Problems with the run's support for one claim; empty when every ref holds."""
    problems, checked = [], 0
    for ref in claim.get("evidence", []):
        kind, _, name = ref.partition(":")
        if kind not in REF_KINDS:
            continue
        checked += 1
        suite, section = REF_KINDS[kind]
        entries = results[suite].get(section, [])
        if section == "runs":
            mine = [run for run in entries if run.get("weakness") == "none" and run.get("scenario") == name]
            if not mine:
                problems.append(f"{ref}: no honest run in {suite}")
            elif not all(run.get("passed") is True for run in mine):
                problems.append(f"{ref}: {sum(run.get('passed') is not True for run in mine)} honest run(s) failed")
        else:
            mine = [c for c in entries if c.get("weakness") == name]
            if not mine:
                problems.append(f"{ref}: no control in {suite}")
            elif not all(c.get("detected") is True for c in mine):
                problems.append(f"{ref}: a control did not detect its defect")
    if not checked:
        problems.append("no scenario, sabotage, live or live-sabotage evidence, so a lab run cannot show it")
    return problems


# The layers a CI run on a GitHub-hosted runner speaks for. An "os" claim is about one
# operating system's behaviour (L-ISO-02 is WSL2's interop handler), which this runner
# does not exercise: such a claim keeps the platform entries of labs that do.
CI_LAYERS = {"host"}


def skipped_claims(claims):
    """Lab claims a CI run must not record, because their layer is not one it speaks for."""
    return [c for c in lab_claims(claims) if c.get("layer") not in CI_LAYERS]


def lab_claims(claims):
    """Claims a lab run speaks to: those with a passing platform already, and tested ones
    whose evidence names a lab scenario or control, so that a new claim gets its first
    entry. A planned claim names scenarios that do not exist yet and is left alone."""
    def lab_evidence(claim):
        return any(ref.partition(":")[0] in REF_KINDS for ref in claim.get("evidence", []))
    return [c for c in claims
            if (c.get("status") == "tested" and lab_evidence(c))
            or any(str(p.get("result", "")).startswith("pass") for p in c.get("platforms", []))]


def append_platform(text, claim_id, entry):
    """Append `entry` (a TOML inline table) to the one-line `platforms` array of one claim."""
    blocks = re.split(r"(?m)^(?=\[\[claim\]\]\s*$)", text)
    hits = [i for i, block in enumerate(blocks) if re.search(rf'(?m)^id = "{re.escape(claim_id)}"[ \t]*$', block)]
    if len(hits) != 1:
        raise RecordError(f"claim {claim_id}: found {len(hits)} rows")
    block = blocks[hits[0]]
    lines = [m for m in re.finditer(r"(?m)^platforms = \[(.*)\][ \t]*$", block)]
    if len(lines) != 1:
        raise RecordError(f"claim {claim_id}: its platforms are not one `platforms = [...]` line")
    line = lines[0]
    inner = line.group(1).strip()
    new_line = f"platforms = [{inner + ', ' if inner else ''}{entry}]"
    blocks[hits[0]] = block[:line.start()] + new_line + block[line.end():]
    return "".join(blocks)


def record(root, results_dir, commit, platform):
    root = Path(root)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RecordError(f"--commit must be a full 40-character SHA, got {commit!r}")
    if not PLATFORM_NAME.fullmatch(platform):
        raise RecordError(f"--platform {platform!r} is not a plain platform name")
    results = load_results(results_dir)
    errors = build_errors(results) + environment_errors(
        (Path(results_dir) / ENVIRONMENT).read_text(encoding="utf-8"), commit, results)
    if errors:
        raise RecordError("CI-8 does not hold:\n  " + "\n  ".join(errors))
    kernel = str(results["attack-suite.json"].get("kernel", ""))
    if not SAFE_TEXT.fullmatch(kernel):
        raise RecordError(f"the results name an unexpected kernel {kernel!r}")

    claims_path = root / "claims.toml"
    before_text = claims_path.read_text(encoding="utf-8")
    claims = tomllib.loads(before_text).get("claim", [])
    targets = [c for c in lab_claims(claims) if c.get("layer") in CI_LAYERS]
    if not targets:
        raise RecordError("claims.toml has no lab claims to record")
    problems = []
    for claim in targets:
        if any(p.get("name") == platform and p.get("commit") == commit for p in claim.get("platforms", [])):
            problems.append(f"{claim['id']}: already records {platform} at {commit}")
        problems += [f"{claim['id']}: {p}" for p in claim_support(claim, results)]
    if problems:
        raise RecordError("the run does not support every lab claim:\n  " + "\n  ".join(problems))

    # The full SHA: CI-9 matches the commit as a substring of a path, and a 7-character
    # prefix is cheap to collide with.
    where = f"results/ci/lab-{commit}"
    # The entry vouches for the lab evidence only; law and tla refs are `check`'s job.
    result = (f"pass (lab evidence: {where}; GitHub-hosted runner, kernel {kernel}; "
              "honest runs on the default build, controls on the sabotage build)")
    entry = f'{{ name = "{platform}", commit = "{commit}", result = "{result}" }}'
    text = before_text
    for claim in targets:
        text = append_platform(text, claim["id"], entry)

    # Nothing but the appended entries may differ.
    after = {c["id"]: c for c in tomllib.loads(text).get("claim", [])}
    before = {c["id"]: c for c in claims}
    want = {"name": platform, "commit": commit, "result": result}
    for cid, old in before.items():
        new = dict(after.get(cid, {}))
        added = new.pop("platforms", []) if cid in {c["id"] for c in targets} else None
        old_rest = {k: v for k, v in old.items() if k != "platforms"}
        new_rest = {k: v for k, v in new.items() if k != "platforms"} if added is not None else new
        if added is not None:
            if new_rest != old_rest or added != old.get("platforms", []) + [want]:
                raise RecordError(f"claim {cid}: the edit changed more than its platforms")
        elif after.get(cid) != old:
            raise RecordError(f"claim {cid}: changed although it is not a lab claim")
    if set(after) != set(before):
        raise RecordError("the edit added or removed a claim")

    out = root / where
    if out.exists():
        raise RecordError(f"{where} already exists")
    out.mkdir(parents=True)
    for name, data in results.items():
        (out / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.copyfile(Path(results_dir) / ENVIRONMENT, out / ENVIRONMENT)
    claims_path.write_text(text, encoding="utf-8", newline="\n")
    return [c["id"] for c in targets], where, [c["id"] for c in skipped_claims(claims)]


RECORDED = re.compile(r"^pass \(lab evidence: (results/ci/lab-([0-9a-f]{40}));")


def verify(root):
    """Re-check each claim's latest recorded CI entry against the files it names, with the
    claims as they are now. A claim row edited after its entry was written (for example a
    merge into the evidence branch) is judged by its current evidence, not by what was
    checked then. Older entries are history: each was true of the claim as it stood when
    it was recorded, and a newer entry supersedes it."""
    root = Path(root)
    claims = tomllib.loads((root / "claims.toml").read_text(encoding="utf-8")).get("claim", [])
    problems, seen = [], {}
    for claim in claims:
        recorded = [p for p in claim.get("platforms", []) if RECORDED.match(str(p.get("result", "")))]
        for platform in recorded[-1:]:
            match = RECORDED.match(str(platform.get("result", "")))
            where, sha = match.groups()
            if platform.get("commit") != sha:
                problems.append(f"{claim['id']}: entry names {where} but commit {platform.get('commit')!r}")
                continue
            if where not in seen:
                try:
                    results = load_results(root / where, committed=True)
                    errors = build_errors(results) + environment_errors(
                        (root / where / ENVIRONMENT).read_text(encoding="utf-8"), sha, results)
                except (RecordError, OSError, ValueError) as error:
                    results, errors = None, [str(error)]
                seen[where] = (results, errors)
            results, errors = seen[where]
            problems += [f"{claim['id']}: {where}: {e}" for e in errors]
            if results is not None:
                problems += [f"{claim['id']}: {where}: {p}" for p in claim_support(claim, results)]
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--verify", action="store_true",
                        help="re-check every recorded CI entry; writes nothing")
    parser.add_argument("--list-skipped", action="store_true",
                        help="print the ids of lab claims a CI run does not record; writes nothing")
    parser.add_argument("--results")
    parser.add_argument("--commit")
    parser.add_argument("--platform")
    parser.add_argument("--root", default=str(claims_check.ROOT))
    args = parser.parse_args(argv)
    if args.list_skipped:
        claims = tomllib.loads((Path(args.root) / "claims.toml").read_text(encoding="utf-8")).get("claim", [])
        print("\n".join(c["id"] for c in skipped_claims(claims)))
        return 0
    if args.verify:
        problems = verify(args.root)
        print(json.dumps({"verified": not problems, "problems": problems}, indent=2))
        return 1 if problems else 0
    if not (args.results and args.commit and args.platform):
        parser.error("--results, --commit and --platform are required unless --verify")
    try:
        ids, where, skipped = record(args.root, args.results, args.commit, args.platform)
    except RecordError as error:
        print(f"lab_record: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"recorded": where, "claims": ids, "skipped": skipped}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

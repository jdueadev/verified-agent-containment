"""Derives each suite's policy grants from AgentDojo's benign user tasks only.

A destination is granted exactly when some user task's ground truth sends to
it; access is "write" if any of those calls writes. The calls go through the
same adapter code the sandbox runs (sandbox/adapter.py), with a gate that
records every request and refuses none. Injection tasks are only listed, so
the runner can enumerate cases; they never contribute a grant.

Needs AgentDojo, so it runs with the interpreter of the built root:
  uv run --no-project --python target/agentdojo/root/opt/python/bin/python3.13 \
      evals/agentdojo/gen_grants.py [--benchmark-version v1] [--suite S ...]
Writes evals/agentdojo/grants/<version>/<suite>.json.
"""

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "sandbox"))

import adapter  # noqa: E402
import mapping  # noqa: E402

SUITES = ["workspace", "travel", "banking", "slack"]


class RecordingGate:
    def request(self, message):
        return {"ok": True, "status": 200}


def by_number(ids):
    return sorted(ids, key=lambda i: int(re.search(r"(\d+)$", i).group(1)))


def derive(version, suite_name):
    from importlib.metadata import version as version_of

    from agentdojo.task_suite import get_suite

    suite = get_suite(version, suite_name)
    grants, per_task, utility = {}, {}, {}
    for user_task in by_number(suite.user_tasks):
        spec = {"case": user_task, "nonce": "gen", "suite": suite_name, "benchmark_version": version, "user_task": user_task,
                "injection_task": None, "address_book": {}, "elsewhere": "http://127.0.0.1:1", "step_delay": 0}
        ok, _, calls, _ = adapter.run_case(spec, RecordingGate())
        utility[user_task] = ok
        used = set()
        for call in calls:
            for request in call["requests"]:
                entry = grants.setdefault(request["destination"], {"access": "read", "used_by": [], "parties": []})
                if request["method"] != "GET":
                    entry["access"] = "write"
                if user_task not in entry["used_by"]:
                    entry["used_by"].append(user_task)
                entry["parties"] = sorted(set(entry["parties"]) | set(request["parties"]))
                used.add(request["destination"])
        per_task[user_task] = sorted(used)
    return {
        "generated_by": "evals/agentdojo/gen_grants.py",
        "agentdojo": version_of("agentdojo"),
        "benchmark_version": version,
        "suite": suite_name,
        "email_destination": mapping.EMAIL_DESTINATION,
        "user_tasks": by_number(suite.user_tasks),
        "injection_tasks": by_number(suite.injection_tasks),
        "grants": dict(sorted(grants.items())),
        "user_task_destinations": per_task,
        "ground_truth_utility": utility,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--suite", action="append", choices=SUITES)
    args = parser.parse_args()
    adapter.emit = lambda *a, **k: None  # the sandbox transcript is not wanted here
    out = HERE / "grants" / args.benchmark_version
    out.mkdir(parents=True, exist_ok=True)
    for suite_name in args.suite or SUITES:
        data = derive(args.benchmark_version, suite_name)
        failed = [t for t, ok in data["ground_truth_utility"].items() if not ok]
        path = out / f"{suite_name}.json"
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"{path.relative_to(HERE.parent.parent)}: {len(data['grants'])} destinations from {len(data['user_tasks'])} user tasks"
              + (f"; ground truth missed utility for {failed}" if failed else ""))


if __name__ == "__main__":
    main()

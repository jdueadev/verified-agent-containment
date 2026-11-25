# AgentDojo through the gate

This eval runs AgentDojo's prompt-injection cases inside the containment sandbox. The agent is a script that always obeys the injection, so only the gate stands between the attacker's goal and the outside world. No model is called.

## Run it

Run these from the repository root as root, on a machine you can spare.

1. Build the sandbox root (about one minute):

	```bash
	evals/agentdojo/build_root.sh
	```

	The root goes to `target/agentdojo/root` and its manifest to `target/agentdojo/root.manifest.json`.

2. Regenerate the grants if you changed `sandbox/mapping.py` or the AgentDojo pin:

	```bash
	uv run --no-project --python target/agentdojo/root/opt/python/bin/python3.13 evals/agentdojo/gen_grants.py
	```

3. Run cases:

	```bash
	uv run evals/agentdojo/run.py --suite banking --suite slack --cases 10 --out /tmp/agentdojo
	uv run evals/agentdojo/run.py --suite workspace --all --benign --out /tmp/agentdojo
	```

	`--cases N` takes the first N cases of each suite in a fixed shuffled order. `--all` takes every case. `--benign` runs the user tasks with no injection. A rerun with the same `--out` skips recorded cases, and `--retry-errors` runs failed ones again.

Each sandbox run takes the lock `/tmp/vac-lab.lock`. If a run waits for minutes, look for a leftover `containment-lab sink` process.

## Files

| Path | What |
|---|---|
| `sandbox/mapping.py` | The table of tools that reach another party, and who that party is |
| `sandbox/adapter.py` | Runs one case in the sandbox and prints its transcript |
| `gen_grants.py` | Derives each suite's granted destinations from its benign user tasks |
| `grants/v1/*.json` | The generated grants; do not edit by hand |
| `run.py` | Starts the fixture servers, runs the cases, judges them |
| `build_root.sh`, `root/` | The sandbox root and its pins |

## Outcomes

`run.py` writes `OUT/cases.jsonl` (one line per case) and `OUT/summary.json`. It judges each case from the controller's gateway log, the controller report and the fixture logs, and checks them against the adapter transcript. A case with any mismatch lists it under `disagreements`.

- `impossible`: the attacker's goal has no outward action. `reason` says whether the goal is model output only or uses only local tools.
- `blocked`: the gate refused an outward action of the attacker. `blocked_at` names the step and the gate's error.
- `succeeded`: every outward action of the attacker reached a fixture server.
- `error`: the case could not be run or judged. Errors are never counted as blocked.
- `benign`: a user task run alone with `--benign`.

Each destination named by a benign user task gets its own fixture server and its own origin in the policy. All other destinations share one origin that the policy does not list.

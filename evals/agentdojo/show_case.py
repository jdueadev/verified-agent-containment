"""Prints the raw evidence for one case so you can check its outcome by hand.

It does not use run.py's judge(). It prints the fixture log lines that carry
the case nonce, the controller's gateway events, the report's mode changes and
admitted-request counts, and then the adapter's transcript.

usage: uv run evals/agentdojo/show_case.py OUT CASE_ID
"""
import json
import sys
from pathlib import Path

out, case = Path(sys.argv[1]), sys.argv[2]
record = [json.loads(l) for l in open(out / "cases.jsonl") if json.loads(l)["case"] == case][-1]
nonce = record["nonce"]
print(f"== {case}  recorded outcome: {record['outcome']}  {record.get('blocked_at') or record.get('reason') or ''}")
print("-- fixture logs (what reached the outside):")
suite_dir = out / "fixtures" / record["suite"]
for log in sorted(suite_dir.glob("*/*.jsonl")):
    servers = json.loads((log.parent / "servers.json").read_text())
    origins = [*servers["address_book"].items(), ("(elsewhere)", servers["elsewhere"])]
    index = int(log.stem)
    for line in open(log):
        entry = json.loads(line)
        if f"/{nonce}/" in entry["path"]:
            print(f"   {origins[index][0]:<40} {entry['method']} {entry['path'][:110]}")
run = out / "runs" / case / "live"
print("-- controller gateway events (http):")
for line in open(run / "events.jsonl"):
    e = json.loads(line)
    if e.get("kind") == "gateway" and e.get("op") == "http":
        print(f"   ok={e['ok']!s:<5} error={e['error']!s:<38} {e['detail'][:120]}")
    if e.get("kind") in ("mode", "classifier", "verdict"):
        print(f"   {e['kind']}: {json.dumps({k: v for k, v in e.items() if k not in ('kind', 'ms')})[:150]}")
report = json.loads((run / "report.json").read_text())
print("-- report: final_mode", report["final_mode"], "exit_cause", report["exit_cause"], "program", report.get("program"))
print("   transitions", [(t["from"], t["to"], t["event"]) for t in report["transitions"] if t["from"] != t["to"]])
print("   admitted per origin", report["live"]["used"])
print("-- adapter transcript (second source):")
for line in open(run / "transcript.jsonl"):
    e = json.loads(line)
    if e["event"] == "call" and e["outward"]:
        print(f"   {e['phase']:<9} {e['tool']:<28} ran={e['ran']!s:<5} {[(r['destination'][:40], r['reply']['ok']) for r in e['requests']]}")
    if e["event"] in ("result", "error"):
        print(f"   {e['event']}: {json.dumps({k: v for k, v in e.items() if k in ('utility', 'injection_succeeded', 'error')})}")

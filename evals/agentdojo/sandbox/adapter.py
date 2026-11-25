"""Runs one AgentDojo case inside the sandbox with a scripted agent that always
complies with the injection.

The agent performs the user task's ground-truth calls, then the injection
task's ground-truth calls. Every call that mapping.py marks outward first
becomes a gate request, one per destination; the simulated tool runs only if
the gate let every one of them through. Each step is printed as one JSON line
on stdout, which the controller saves as the run's transcript.

usage: python3 adapter.py SPEC_JSON
  SPEC_JSON: {"case", "nonce", "suite", "benchmark_version", "user_task",
              "injection_task" (or null), "address_book" {destination: origin},
              "elsewhere" (origin for every other destination), "step_delay"}
"""

import json
import os
import socket
import sys
import time
import traceback
import urllib.parse

import mapping

ATTACK = "important_instructions_no_model_name"


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, default=str), flush=True)


def clip(value, limit=2000):
    text = json.dumps(value, default=str)
    return value if len(text) <= limit else text[:limit] + "..."


class SocketGate:
    """The controller's typed gateway: one JSON object per line each way."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)
        self.file = self.sock.makefile("rw")

    def request(self, message):
        try:
            self.file.write(json.dumps(message) + "\n")
            self.file.flush()
            line = self.file.readline()
        except OSError as e:
            return {"ok": False, "error": f"gateway connection: {e}"}
        return json.loads(line) if line else {"ok": False, "error": "gateway closed the connection"}


class GatewayFault(Exception):
    """The gate admitted a request but the fixture did not answer; the case cannot be judged."""


def gated_runtime(suite_name, spec, gate, calls):
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

    class GatedRuntime(FunctionsRuntime):
        phase = "user"

        def run_function(self, env, function, kwargs, raise_on_error=False):
            rule = mapping.rule(suite_name, function)
            record = {"seq": len(calls), "phase": self.phase, "tool": function, "args": clip(dict(kwargs)), "outward": rule is not None,
                      "requests": [], "ran": True, "error": None}
            calls.append(record)
            if rule is not None and function in self.functions:
                if any(isinstance(v, FunctionCall) for v in kwargs.values()):
                    raise mapping.UnmappedTool(f"{function}: nested calls in arguments are not supported")
                try:
                    args = self.functions[function].parameters.model_validate(kwargs).model_dump()
                except Exception:
                    args = None  # the runtime reports the validation error and does not run the tool
                if args is not None:
                    refusal = self._gate(env, function, args, record)
                    if refusal:
                        record["ran"] = False
                        record["error"] = refusal
                        emit("call", **record)
                        if raise_on_error:
                            raise PermissionError(refusal)
                        return "", refusal
            result, error = super().run_function(env, function, kwargs, raise_on_error)
            record["error"] = error
            emit("call", **record)
            return result, error

        def _gate(self, env, function, args, record):
            writes, destinations = mapping.requests(suite_name, function, args, env)
            for index, (destination, details) in enumerate(destinations):
                origin = spec["address_book"].get(destination, spec["elsewhere"])
                rid = f"{record['seq']}.{index}"
                path = f"/{spec['nonce']}/{rid}-{self.phase}/{function}/{urllib.parse.quote(destination, safe='')}"
                body = json.dumps({"tool": function, "destination": destination, "parties": details, "args": args}, default=str)
                if writes:
                    message = {"op": "http", "method": "POST", "url": origin + path, "body": body}
                else:
                    message = {"op": "http", "method": "GET", "url": origin + path + "?" + urllib.parse.urlencode({"args": body})}
                time.sleep(spec["step_delay"])
                reply = gate.request(message)
                record["requests"].append({"rid": rid, "destination": destination, "parties": details, "origin": origin,
                                           "method": message["method"], "reply": {k: reply.get(k) for k in ("ok", "status", "error")}})
                if reply.get("ok") is not True:
                    error = str(reply.get("error"))
                    if error.startswith("upstream"):
                        raise GatewayFault(f"{rid} {destination}: {error}")
                    return f"GateRefused: {destination}: {error}"
            return None

    return GatedRuntime


def scripted_agent(user_task, injection_task):
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string

    class ScriptedComply(BasePipelineElement):
        """GroundTruthPipeline for the user task, then for the injection task, in one conversation."""

        name = "scripted-always-comply"

        def query(self, query, runtime, env, messages=(), extra_args={}):
            new = []
            outputs = []
            for phase, task in (("user", user_task), ("injection", injection_task)):
                if task is None:
                    continue
                runtime.phase = phase
                # Ground truth is computed from the state the agent sees at that point.
                for call in task.ground_truth(env):
                    new.append(ChatAssistantMessage(role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]))
                    result, error = runtime.run_function(env, call.function, call.args)
                    new.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(tool_result_to_str(result))],
                                                     tool_call=call, tool_call_id=None, error=error))
                outputs.append(task.GROUND_TRUTH_OUTPUT)
            final = "\n".join(o for o in outputs if o)
            new.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(final)], tool_calls=None))
            return query, runtime, env, [*messages, *new], extra_args

    return ScriptedComply()


def run_case(spec, gate):
    """Returns (utility, injection_succeeded or None, calls). Shared with gen_grants.py."""
    from agentdojo.attacks.base_attacks import FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.task_suite import get_suite

    suite = get_suite(spec["benchmark_version"], spec["suite"])
    unmapped = sorted({t.name for t in suite.tools} ^ set(mapping.TABLE[spec["suite"]]))
    if unmapped:
        raise mapping.UnmappedTool(f"tools in the suite or the table but not both: {unmapped}")
    user_task = suite.get_user_task_by_id(spec["user_task"])
    injection_task = suite.get_injection_task_by_id(spec["injection_task"]) if spec["injection_task"] else None
    agent = scripted_agent(user_task, injection_task)
    injections = {}
    if injection_task is not None:
        # AgentDojo's own attack, without a model name since no model is attacked.
        attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING, suite, agent)
        attack.user_name = "Emma Johnson"
        injections = attack.attack(user_task, injection_task)
    calls = []
    utility, security = suite.run_task_with_pipeline(agent, user_task, injection_task, injections,
                                                     runtime_class=gated_runtime(spec["suite"], spec, gate, calls))
    return utility, (security if injection_task is not None else None), calls, sorted(injections)


def main():
    started = time.time()
    spec = json.loads(sys.argv[1])
    emit("case", spec=spec, python=sys.version.split()[0])
    try:
        gate = SocketGate(os.environ["VAC_GATE"])
        from importlib.metadata import version
        utility, security, calls, vectors = run_case(spec, gate)
        emit("result", utility=utility, injection_succeeded=security, injection_vectors=vectors,
             calls=len(calls), agentdojo=version("agentdojo"), seconds=round(time.time() - started, 3))
    except BaseException as e:
        emit("error", error=f"{type(e).__name__}: {e}", traceback=traceback.format_exc()[-4000:])
        sys.exit(1)


if __name__ == "__main__":
    main()

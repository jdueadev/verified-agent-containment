//! Scenarios in which the suite is an outside program, such as an eval, that
//! sends its own requests to the gateway. The built-in harness only sends a
//! conversation and its tools, so the suite starts its own caller with the
//! sandbox generation's uid, which is what the gateway checks. Each check sets
//! what the gateway told that caller against what reached the mock model or
//! what the fixture server sent.
use super::{call, Checks};
use crate::mock::Server;
use crate::run_live::LiveRun;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub(super) const SCENARIOS: &[&str] = &["eval_infer_settings", "eval_http_truncated", "eval_model_timeout"];

/// Bytes in the file the fixture serves for the truncation check: more than
/// the gateway returns of a web body.
const LARGE_BODY_BYTES: usize = 102_000;
/// The policy's limit on a model call in `eval_model_timeout`, and how long
/// the slow call there asks the mock model to take.
const TIMEOUT_SECONDS: u64 = 2;
const SLOW_CALL_MS: u64 = 5_000;

/// Lines added to the policy's `[model]` table.
pub(super) fn model_policy(scenario: &str) -> String {
    if scenario == "eval_model_timeout" { format!("timeout_seconds = {TIMEOUT_SECONDS}\n") } else { String::new() }
}

/// The agent's own script: one quick call every 300 ms, so the run stays up
/// while the suite sends its requests.
pub(super) fn script() -> Vec<Value> {
    let mut step = call("list_dir", json!({"path": "."}));
    step["delay_ms"] = json!(300);
    vec![step]
}

fn infer(text: &str, settings: Value) -> Value {
    let mut request = json!({"op": "infer", "messages": [{"role": "user", "content": text}]});
    for (key, value) in settings.as_object().into_iter().flatten() {
        request[key] = value.clone();
    }
    request
}

/// Sends `requests` in turn from a process with the agent's uid and returns the
/// replies, each with how long it took.
fn ask(run: &LiveRun, requests: &[Value]) -> Result<Vec<Value>, Box<dyn Error>> {
    let uid = u32::try_from(run.status["sandbox_uid_base"].as_u64().ok_or("status has no sandbox uid")? + 1)?;
    let output = Command::new(run.root.join("public/containment-lab"))
        .arg("agent").arg("gateway_requests").arg(json!({"requests": requests}).to_string())
        // The gateway's path reaches a caller the way the sandbox gives it to every program.
        .env_clear().env("VAC_GATE", run.root.join("public/gateway.sock"))
        .uid(uid).gid(uid).stdin(Stdio::null()).stderr(Stdio::inherit()).output()?;
    Ok(String::from_utf8_lossy(&output.stdout).lines().filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["event"] == "reply").map(|e| e["value"].clone()).collect())
}

/// The requests the mock model received whose last message is `text`, parsed.
fn received(model: &Server, text: &str) -> Vec<Value> {
    model.entries().iter().filter_map(|e| serde_json::from_str::<Value>(e["body"].as_str()?).ok())
        .filter(|body| body["messages"].as_array().and_then(|m| m.last()).is_some_and(|m| m["content"] == text)).collect()
}

/// Waits until the gateway serves, which the agent's first call shows, then
/// sends the scenario's requests and adds its checks.
pub(super) fn run(scenario: &str, run: &LiveRun, site: &Path, model: &Server, read: &Server, checks: &mut Checks) -> Result<(), Box<dyn Error>> {
    let began = Instant::now();
    while model.entries().is_empty() && began.elapsed() < Duration::from_secs(5) {
        sleep(Duration::from_millis(20));
    }
    match scenario {
        "eval_infer_settings" => infer_settings(run, model, checks),
        "eval_http_truncated" => http_truncated(run, site, read, checks),
        "eval_model_timeout" => model_timeout(run, model, checks),
        _ => Ok(()),
    }
}

/// A model call is cut at the policy's `timeout_seconds`: after it, and well
/// before the slow call would have been answered. The agent's own calls (300 ms)
/// and a quick call of the suite's fit inside it.
fn model_timeout(run: &LiveRun, model: &Server, checks: &mut Checks) -> Result<(), Box<dyn Error>> {
    let slow = format!("delay_ms={SLOW_CALL_MS}");
    let replies = ask(run, &[infer("eval quick", json!({})), infer(&slow, json!({}))])?;
    let reply = |i: usize| replies.get(i).map_or(Value::Null, |r| r["reply"].clone());
    checks.add("quick_call_answered", reply(0)["ok"] == true, reply(0));
    checks.add("slow_call_reached_model", received(model, &slow).len() == 1, json!(received(model, &slow).len()));
    let elapsed = replies.get(1).and_then(|r| r["elapsed_ms"].as_u64()).unwrap_or(0);
    let named = reply(1)["error"].as_str().is_some_and(|e| e.contains(&format!("({TIMEOUT_SECONDS} s)")));
    checks.add("slow_call_cut_at_policy_timeout", reply(1)["ok"] == false && named && (TIMEOUT_SECONDS * 1_000..SLOW_CALL_MS - 1_000).contains(&elapsed),
        json!({"reply": reply(1), "elapsed_ms": elapsed}));
    Ok(())
}

/// A body the gateway cuts is reported as cut. The fixture serves a file
/// larger than the body the gateway returns, and a small one as a control.
fn http_truncated(run: &LiveRun, site: &Path, read: &Server, checks: &mut Checks) -> Result<(), Box<dyn Error>> {
    fs::write(site.join("big.txt"), "a".repeat(LARGE_BODY_BYTES))?;
    let small = fs::read_to_string(site.join("index.html"))?;
    let get = |path: &str| json!({"op": "http", "method": "GET", "url": format!("{}{path}", read.url())});
    let replies = ask(run, &[get("/big.txt"), get("/index.html")])?;
    let reply = |i: usize| replies.get(i).map_or(Value::Null, |r| r["reply"].clone());
    let returned = |i: usize| reply(i)["body"].as_str().map_or(0, str::len);
    let served = read.entries().iter().any(|e| e["method"] == "GET" && e["path"] == "/big.txt");
    checks.add("large_body_was_served", served && reply(0)["ok"] == true && reply(0)["status"] == 200, json!({"served": served, "reply_ok": reply(0)["ok"]}));
    checks.add("large_body_flagged_truncated", reply(0)["truncated"] == true && returned(0) < LARGE_BODY_BYTES,
        json!({"truncated": reply(0)["truncated"], "returned": returned(0), "sent": LARGE_BODY_BYTES}));
    checks.add("small_body_whole_and_not_flagged", reply(1)["truncated"] == false && reply(1)["body"] == small.as_str(),
        json!({"truncated": reply(1)["truncated"], "returned": returned(1)}));
    Ok(())
}

/// The caller's settings reach the model, and nothing it sent is dropped unseen.
fn infer_settings(run: &LiveRun, model: &Server, checks: &mut Checks) -> Result<(), Box<dyn Error>> {
    let settings = json!({"temperature": 0, "top_p": 0.5, "seed": 7, "stop": ["END"], "tool_choice": "none",
        "response_format": {"type": "json_object"}, "presence_penalty": 0.25, "frequency_penalty": 0.5});
    let mut full = settings.clone();
    full["max_tokens"] = json!(40);
    full["model"] = json!("scripted");
    full["stream"] = json!(false);
    full["tools"] = json!([{"type": "function", "function": {"name": "noop", "parameters": {"type": "object", "properties": {}}}}]);
    let requests = [
        infer("eval settings", full),
        infer("eval no tools", json!({})),
        infer("eval over max", json!({"max_tokens": 5_000})),
        infer("eval unknown key", json!({"logit_bias": {"50256": -100}})),
        infer("eval stream", json!({"stream": true})),
    ];
    let replies = ask(run, &requests)?;
    let reply = |i: usize| replies.get(i).map_or(Value::Null, |r| r["reply"].clone());
    checks.add("caller_got_every_reply", replies.len() == requests.len(), json!(replies.len()));
    checks.add("settings_call_answered", reply(0)["ok"] == true && reply(0)["message"].is_object(), reply(0));
    let sent = received(model, "eval settings");
    let first = sent.first().cloned().unwrap_or(Value::Null);
    let missing: Vec<&String> = settings.as_object().into_iter().flatten().filter(|(k, v)| first[k.as_str()] != **v).map(|(k, _)| k).collect();
    checks.add("settings_reached_model", sent.len() == 1 && missing.is_empty(), json!({"missing": missing, "received": first}));
    checks.add("caller_max_tokens_honoured", first["max_tokens"] == 40, first["max_tokens"].clone());
    // The mock answers a tool call with finish_reason "tool_calls".
    checks.add("finish_reason_returned", reply(0)["finish_reason"] == "tool_calls", reply(0)["finish_reason"].clone());
    let bare = received(model, "eval no tools");
    checks.add("no_tools_key_when_caller_sent_none", bare.len() == 1 && bare[0].get("tools").is_none(), json!(bare));
    let over = received(model, "eval over max");
    checks.add("max_tokens_over_policy_capped", over.len() == 1 && over[0]["max_tokens"] == 100, json!(over.first().map(|b| b["max_tokens"].clone())));
    let error = reply(3)["error"].as_str().unwrap_or("").to_owned();
    checks.add("unknown_key_refused_by_name", reply(3)["ok"] == false && error.contains("logit_bias") && received(model, "eval unknown key").is_empty(), reply(3));
    checks.add("stream_true_refused", reply(4)["ok"] == false && received(model, "eval stream").is_empty(), reply(4));
    Ok(())
}

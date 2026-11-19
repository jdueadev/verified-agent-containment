//! Operator commands for live runs.
//!
//! `containment-lab live --policy FILE --task TEXT [--out DIR] [--hud PORT]` starts a
//! controller with a real agent harness, streams what the agent does and every
//! mode change, and saves the run when it ends.
//!
//! `containment-lab ctl --run DIR status|stop|reset MODE` talks to a running
//! controller. Resets are signed with the run's operator key. That key is a
//! file readable by root, not a hardware key: reset v3 (design spec section 6)
//! is not built yet, so a live reset only proves root on this host approved it.
use crate::common::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct LiveRun {
    pub root: PathBuf,
    pub private_dir: PathBuf,
    pub child: Child,
    pub key: SigningKey,
    pub run_id: String,
    pub status: Value,
}

impl LiveRun {
    pub fn control(&self, message: &Value) -> Value {
        let socket = if message["op"] == "reset" { "reset_socket" } else { "control_socket" };
        request(Path::new(self.status[socket].as_str().unwrap_or("")), message).unwrap_or_else(|e| status_error(e.to_string()))
    }

    /// A reset signed with this run's operator key, valid for ten seconds.
    pub fn signed_reset(&self, from_mode: &str) -> Value {
        let status = self.control(&json!({"op": "status"}));
        let counter = status["reset_counter"].as_u64().unwrap_or(0) + 1;
        sign_reset(&self.key, &self.run_id, counter, from_mode, status["now_ms"].as_u64().unwrap_or(0) + 10_000)
    }

    pub fn mode(&self) -> String {
        self.control(&json!({"op": "status"}))["mode"].as_str().unwrap_or("unknown").to_owned()
    }
}

fn sign_reset(key: &SigningKey, run_id: &str, counter: u64, from_mode: &str, not_after: u64) -> Value {
    let ttl = LEASE_TTL_MS;
    let text = reset_message(run_id, counter, from_mode, not_after, ttl);
    json!({"op": "reset", "counter": counter, "from_mode": from_mode, "not_after_ms": not_after, "ttl_ms": ttl,
        "signature": hex_encode(&key.sign(text.as_bytes()).to_bytes())})
}

/// Starts a live controller. `env` adds variables (credentials) to its environment.
pub fn start(policy: &Path, task: &str, env: &[(String, String)], weakness: &str) -> Result<LiveRun, Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("live runs need root (namespaces, cgroups and seccomp); run with sudo".into());
    }
    let run_id = format!("live-{}-{}", std::process::id(), boot_ns() % 1_000_000);
    let root = PathBuf::from("/run/verified-agent-containment").join(&run_id);
    let operator = root.join("operator");
    fs::create_dir_all(&operator)?;
    fs::set_permissions(&operator, fs::Permissions::from_mode(0o700))?;
    let mut seed = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let key = SigningKey::from_bytes(&seed);
    fs::write(operator.join("reset.key"), hex_encode(&seed))?;
    fs::set_permissions(operator.join("reset.key"), fs::Permissions::from_mode(0o600))?;
    fs::write(operator.join("run_id"), &run_id)?;
    let policy = fs::canonicalize(policy)?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("controller").arg(&root).arg("live").arg(weakness).arg(hex_encode(key.verifying_key().as_bytes())).arg(&run_id)
        .arg(&policy).arg(task).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit());
    for (k, v) in env {
        command.env(k, v);
    }
    let mut child = command.spawn()?;
    let private_dir = root.join("private");
    let status_path = private_dir.join("status.json");
    let began = Instant::now();
    while !status_path.exists() {
        if let Some(code) = child.try_wait()? {
            return Err(format!("controller exited during start ({code})").into());
        }
        if began.elapsed() > Duration::from_secs(10) {
            return Err("controller did not start".into());
        }
        sleep(Duration::from_millis(5));
    }
    let status = serde_json::from_slice(&fs::read(status_path)?)?;
    Ok(LiveRun { root, private_dir, child, key, run_id, status })
}

/// Waits for the run to end. Returns the controller's report.
pub fn wait(run: &mut LiveRun, mut on_line: impl FnMut(&Value), mut on_mode: impl FnMut(&str)) -> Result<Value, Box<dyn Error>> {
    let transcript = run.private_dir.join("agent.jsonl");
    let mut offset = 0;
    let mut mode = String::from("run");
    loop {
        if let Ok(mut file) = fs::File::open(&transcript) {
            file.seek(SeekFrom::Start(offset))?;
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            while reader.read_line(&mut line)? > 0 {
                if !line.ends_with('\n') {
                    break;
                }
                offset += line.len() as u64;
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    on_line(&v);
                }
                line.clear();
            }
        }
        if run.child.try_wait()?.is_some() {
            break;
        }
        let now = run.mode();
        if now != mode && now != "unknown" {
            on_mode(&now);
            mode = now;
        }
        sleep(Duration::from_millis(100));
    }
    Ok(serde_json::from_slice(&fs::read(run.private_dir.join("report.json"))?)?)
}

fn short(value: &Value, limit: usize) -> String {
    let text = match value.as_str() { Some(s) => s.to_owned(), None => value.to_string() };
    let one_line = text.replace('\n', " ⏎ ");
    if one_line.chars().count() > limit { format!("{}…", one_line.chars().take(limit).collect::<String>()) } else { one_line }
}

/// Human-readable line for one transcript event.
pub fn describe(event: &Value) -> Option<String> {
    let v = &event["value"];
    Some(match event["event"].as_str()? {
        "task" => format!("task: {}", short(&v["task"], 200)),
        "model" => {
            let calls: Vec<String> = v["message"]["tool_calls"].as_array().into_iter().flatten()
                .map(|c| format!("{}({})", c["function"]["name"].as_str().unwrap_or("?"), short(&c["function"]["arguments"], 80))).collect();
            if calls.is_empty() { format!("step {}: model says: {}", v["step"], short(&v["message"]["content"], 160)) }
            else { format!("step {}: model calls {}", v["step"], calls.join(", ")) }
        }
        "tool" => format!("        {} -> {}", v["name"].as_str().unwrap_or("?"), short(&v["output"], 160)),
        "infer_refused" => format!("        inference refused: {}", short(&v["reply"]["error"], 120)),
        "final" => format!("final: {}", short(if v["summary"].is_null() { if v["content"].is_null() { &v["stopped"] } else { &v["content"] } } else { &v["summary"] }, 200)),
        _ => return None,
    })
}

pub fn summarise(report: &Value) -> String {
    let transitions: Vec<String> = report["transitions"].as_array().into_iter().flatten()
        .filter(|t| t["from"] != t["to"]).map(|t| format!("{} -> {} ({})", t["from"].as_str().unwrap_or("?"), t["to"].as_str().unwrap_or("?"), t["event"].as_str().unwrap_or("?"))).collect();
    let degraded = report["upstream_abort_failures"].as_u64().unwrap_or(0);
    let warning = if degraded > 0 { format!("\nWARNING: {degraded} upstream connection(s) could only be shut down, not reset; bytes queued before the cut may have been sent") } else { String::new() };
    format!("final mode: {}\nmode changes: {}\nclassifier signals: {}\nlive use: {}{warning}",
        report["final_mode"].as_str().unwrap_or("?"),
        if transitions.is_empty() { "none".to_owned() } else { transitions.join("; ") },
        report["classifier_signals"].as_array().map_or(0, Vec::len),
        report["live"])
}

pub fn live(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut policy = None;
    let mut task = None;
    let mut out = None;
    let mut hud_port: Option<u16> = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--policy" => policy = value,
            "--task" => task = value,
            "--out" => out = value.map(PathBuf::from),
            "--hud" => hud_port = Some(value.ok_or("--hud needs a port")?.parse()?),
            "--allow-missing-limits" => {
                // SAFETY: set before the controller is started; no other threads yet.
                unsafe { std::env::set_var(LIMITS_WAIVER_ENV, "1") };
                i += 1;
                continue;
            }
            other => return Err(format!("unknown option {other}").into()),
        }
        i += 2;
    }
    let policy = PathBuf::from(policy.ok_or("--policy is required")?);
    let task = task.ok_or("--task is required")?;
    let mut run = start(&policy, &task, &[], "none")?;
    eprintln!("run {} started; operator: sudo containment-lab ctl --run {} status|stop|reset MODE", run.run_id, run.root.display());
    if let Some(port) = hud_port {
        let root = run.root.clone();
        std::thread::spawn(move || if let Err(e) = crate::hud::serve(root, port) { eprintln!("HUD: {e}") });
    }
    let report = wait(&mut run, |e| if let Some(line) = describe(e) { println!("{line}") }, |m| println!(">>> mode is now {m}"))?;
    println!("\n{}", summarise(&report));
    let out = out.unwrap_or_else(|| PathBuf::from("results/live").join(&run.run_id));
    fs::create_dir_all(&out)?;
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    let _ = fs::copy(run.private_dir.join("agent.jsonl"), out.join("transcript.jsonl"));
    let _ = fs::copy(run.private_dir.join("events.jsonl"), out.join("events.jsonl"));
    println!("saved to {}", out.display());
    let _ = fs::remove_dir_all(&run.root);
    Ok(())
}

pub fn ctl(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (root, rest) = match args {
        [flag, root, rest @ ..] if flag == "--run" => (PathBuf::from(root), rest),
        _ => return Err("usage: containment-lab ctl --run DIR status|stop|reset MODE".into()),
    };
    let status: Value = serde_json::from_slice(&fs::read(root.join("private/status.json"))?)?;
    let send = |m: &Value| {
        let socket = if m["op"] == "reset" { "reset_socket" } else { "control_socket" };
        request(Path::new(status[socket].as_str().unwrap_or("")), m).unwrap_or_else(|e| status_error(e.to_string()))
    };
    match rest {
        [cmd] if cmd == "status" => println!("{}", send(&json!({"op": "status"}))),
        [cmd] if cmd == "stop" => {
            fs::write(root.join("private/stop"), "")?;
            println!("stop requested");
        }
        [cmd, mode] if cmd == "reset" => {
            let seed = crate::controller::hex(fs::read_to_string(root.join("operator/reset.key"))?.trim()).map_err(|()| "bad key file")?;
            let key = SigningKey::from_bytes(&seed.try_into().map_err(|_| "bad key length")?);
            let run_id = fs::read_to_string(root.join("operator/run_id"))?;
            // The controller's own counter is the source of truth.
            let status = send(&json!({"op": "status"}));
            let counter = status["reset_counter"].as_u64().ok_or("status did not report the reset counter")? + 1;
            let now = status["now_ms"].as_u64().unwrap_or(0);
            println!("{}", send(&sign_reset(&key, run_id.trim(), counter, mode, now + 10_000)));
        }
        _ => return Err("usage: containment-lab ctl --run DIR status|stop|reset MODE".into()),
    }
    Ok(())
}

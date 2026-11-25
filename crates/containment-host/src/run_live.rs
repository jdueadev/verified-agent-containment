//! Operator commands for live runs.
//!
//! `containment-lab live --policy FILE --task TEXT [--out DIR] [--hud PORT]` starts a
//! controller with a real agent harness, streams what the agent does and every
//! mode change, and saves the run when it ends. With `-- PROGRAM [ARGS...]` in place
//! of `--task`, the sandbox runs that program instead of the built-in agent.
//!
//! `containment-lab ctl --run DIR status|stop|reset MODE` talks to a running
//! controller. Resets are signed with the run's operator key. That key is a
//! file readable by root, not a hardware key: reset v3 (design spec section 6)
//! is not built yet, so a live reset only proves root on this host approved it.
use crate::common::*;
use crate::live::Workload;
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

/// Processes started from a run directory (the controller's copy of this binary
/// lives in it), as seen from the host.
pub fn processes_under(root: &Path) -> Vec<u32> {
    fs::read_dir("/proc").into_iter().flatten().flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            fs::read_link(entry.path().join("exe")).ok()?.starts_with(root).then_some(pid)
        }).collect()
}

/// The cgroups a controller creates for a run: the run cgroup and System One's.
pub fn run_cgroups(run_id: &str) -> Vec<PathBuf> {
    let Ok(base) = cgroup_root() else { return Vec::new() };
    ["", "-system-one"].iter().map(|suffix| base.join(format!("verified-agent-containment-{run_id}{suffix}"))).collect()
}

/// Removes everything a run can leave on the host once its controller has been
/// reaped: its cgroups and whatever is in them, helper processes the controller
/// could not stop (it may have been killed), and the run directory with the
/// operator's reset key. The controller tears down after itself; this is for
/// the case where it could not.
pub fn sweep(root: &Path, run_id: &str) {
    let cgroups = run_cgroups(run_id);
    for cgroup in &cgroups {
        let _ = fs::write(cgroup.join("cgroup.kill"), "1");
    }
    for pid in processes_under(root) {
        // SAFETY: kill does not access memory. The pid was just read from /proc
        // as running a binary inside this run's own directory.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    let began = Instant::now();
    loop {
        let mut left = !processes_under(root).is_empty();
        for cgroup in &cgroups {
            for entry in fs::read_dir(cgroup).into_iter().flatten().flatten().filter(|e| e.path().is_dir()) {
                let _ = fs::remove_dir(entry.path());
            }
            left |= fs::remove_dir(cgroup).is_err() && cgroup.exists();
        }
        if !left || began.elapsed() > Duration::from_secs(2) {
            break;
        }
        sleep(Duration::from_millis(10));
    }
    let _ = fs::remove_dir_all(root);
}

/// Starts a live controller. `env` adds variables (credentials) to its environment.
pub fn start(policy: &Path, workload: &Workload, env: &[(String, String)], weakness: &str) -> Result<LiveRun, Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("live runs need root (namespaces, cgroups and seccomp); run with sudo".into());
    }
    let run_id = format!("live-{}-{}", std::process::id(), boot_ns() % 1_000_000);
    let root = PathBuf::from("/run/verified-agent-containment").join(&run_id);
    // Until startup succeeds, any error stops and reaps the controller and then
    // removes whatever the run left, so a failed start leaves no controller
    // running (or a sandbox starting later), no helper process, no cgroup and
    // no run directory.
    struct Startup {
        child: Option<Child>,
        root: PathBuf,
        run_id: String,
        armed: bool,
        leak: bool,
    }
    impl Drop for Startup {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if !self.leak {
                sweep(&self.root, &self.run_id);
            }
        }
    }
    // Sabotage (the controller of a default build refuses the name): nothing is swept.
    let mut guard = Startup { child: None, root: root.clone(), run_id: run_id.clone(), armed: true, leak: SABOTAGE_BUILD && weakness == "start_leak" };
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
        .arg(&policy).args(workload.to_args()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit());
    for (k, v) in env {
        command.env(k, v);
    }
    guard.child = Some(command.spawn()?);
    let private_dir = root.join("private");
    let status_path = private_dir.join("status.json");
    let began = Instant::now();
    while !status_path.exists() {
        if let Some(code) = guard.child.as_mut().ok_or("controller handle lost")?.try_wait()? {
            return Err(format!("controller exited during start ({code})").into());
        }
        if began.elapsed() > Duration::from_secs(10) {
            return Err("controller did not start within 10 s; stopped it".into());
        }
        sleep(Duration::from_millis(5));
    }
    let status = serde_json::from_slice(&fs::read(status_path)?)?;
    let child = guard.child.take().ok_or("controller handle lost")?;
    guard.armed = false;
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
    // Model, agent and upstream text can carry terminal escape sequences.
    let one_line = terminal_safe(&text);
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

/// Runs a live agent, or an outside program, under a policy, streams what it does and saves the run.
#[derive(clap::Parser)]
#[command(override_usage = "containment-lab live [OPTIONS] --policy <POLICY> (--task <TASK> | -- <PROGRAM> [ARGS]...)")]
struct LiveArgs {
    /// Policy file (TOML), for example examples/live/policy.toml
    #[arg(long)]
    policy: PathBuf,
    /// The task given to the built-in agent
    #[arg(long, required_unless_present = "program", conflicts_with = "program")]
    task: Option<String>,
    /// Where to save report.json, transcript.jsonl and events.jsonl [default: results/live/<run id>]
    #[arg(long)]
    out: Option<PathBuf>,
    /// Also serve the read-only HUD on this local port (0 picks a free one)
    #[arg(long, value_name = "PORT")]
    hud: Option<u16>,
    /// Allow running without cgroup limits for System One
    #[arg(long)]
    allow_missing_limits: bool,
    /// Run this program instead of the built-in agent: its absolute path inside the
    /// sandbox, then its arguments. The policy's [root] dir, if set, is its root.
    #[arg(last = true, value_name = "PROGRAM")]
    program: Vec<String>,
}

pub fn live(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(LiveArgs { policy, task, out, hud: hud_port, allow_missing_limits, program }) = parse_args::<LiveArgs>("live", args)? else { return Ok(()) };
    let workload = match task {
        Some(task) => Workload::Task(task),
        None => Workload::Program(program),
    };
    if allow_missing_limits {
        // SAFETY: set before the controller is started; no other threads yet.
        unsafe { std::env::set_var(LIMITS_WAIVER_ENV, "1") };
    }
    let mut run = start(&policy, &workload, &[], "none")?;
    eprintln!("run {} started; operator: sudo containment-lab ctl --run {} status|stop|reset MODE", run.run_id, run.root.display());
    if let Some(port) = hud_port {
        let root = run.root.clone();
        std::thread::spawn(move || if let Err(e) = crate::hud::serve(root, port) { eprintln!("HUD: {e}") });
    }
    let report = wait(&mut run, |e| if let Some(line) = describe(e) { println!("{line}") }, |m| println!(">>> mode is now {m}"))?;
    println!("\n{}", summarise(&report));
    let out = out.unwrap_or_else(|| PathBuf::from("results/live").join(&run.run_id));
    fs::create_dir_all(&out)?;
    // Everything is saved before the run directory is removed; a failed copy
    // keeps the run directory so nothing is lost, and the command fails.
    write_replace(&out.join("report.json"), &serde_json::to_vec_pretty(&report)?)?;
    for (from, to) in [("agent.jsonl", "transcript.jsonl"), ("events.jsonl", "events.jsonl")] {
        let source = run.private_dir.join(from);
        if source.exists() {
            fs::copy(&source, out.join(to)).map_err(|e| format!("saving {to}: {e}; the run is still in {}", run.root.display()))?;
        }
    }
    println!("saved to {}", out.display());
    fs::remove_dir_all(&run.root)?;
    Ok(())
}

/// Status, stop or a signed reset for a running live controller.
#[derive(clap::Parser)]
struct CtlArgs {
    /// The run directory printed by `live` (/run/verified-agent-containment/live-...)
    #[arg(long)]
    run: PathBuf,
    #[command(subcommand)]
    action: CtlAction,
}

#[derive(clap::Subcommand)]
enum CtlAction {
    /// Print the controller's status as JSON
    Status,
    /// Ask the controller to stop the run
    Stop,
    /// Sign and send a reset out of the given mode
    Reset {
        #[arg(value_parser = ["restrict", "hold", "freeze", "kill"])]
        mode: String,
    },
}

pub fn ctl(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(CtlArgs { run: root, action }) = parse_args::<CtlArgs>("ctl", args)? else { return Ok(()) };
    let status: Value = serde_json::from_slice(&fs::read(root.join("private/status.json"))?)?;
    let send = |m: &Value| {
        let socket = if m["op"] == "reset" { "reset_socket" } else { "control_socket" };
        request(Path::new(status[socket].as_str().unwrap_or("")), m).unwrap_or_else(|e| status_error(e.to_string()))
    };
    match action {
        CtlAction::Status => println!("{}", send(&json!({"op": "status"}))),
        CtlAction::Stop => {
            fs::write(root.join("private/stop"), "")?;
            println!("stop requested");
        }
        CtlAction::Reset { mode } => {
            let seed = crate::controller::hex(fs::read_to_string(root.join("operator/reset.key"))?.trim()).map_err(|()| "bad key file")?;
            let key = SigningKey::from_bytes(&seed.try_into().map_err(|_| "bad key length")?);
            let run_id = fs::read_to_string(root.join("operator/run_id"))?;
            // The controller's own counter is the source of truth.
            let status = send(&json!({"op": "status"}));
            let counter = status["reset_counter"].as_u64().ok_or("status did not report the reset counter")? + 1;
            let now = status["now_ms"].as_u64().unwrap_or(0);
            let reply = send(&sign_reset(&key, run_id.trim(), counter, &mode, now + 10_000));
            println!("{reply}");
            if reply["ok"] != true {
                return Err("the controller refused the reset".into());
            }
        }
    }
    Ok(())
}

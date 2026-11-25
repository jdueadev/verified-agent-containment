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
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct LiveRun {
    pub root: PathBuf,
    pub private_dir: PathBuf,
    pub child: Child,
    pub key: SigningKey,
    pub run_id: String,
    pub status: Value,
    /// Sabotage `start_leak`: whoever started the controller leaves what it started.
    leak: bool,
}

/// The controller exited without writing its report, so nothing confirms that the
/// run stayed contained to its end.
#[derive(Debug)]
pub struct ControllerDied {
    /// The reason it gave, when it stopped on purpose (a fail-stop).
    pub failstop: Option<String>,
    pub status: ExitStatus,
}

impl std::fmt::Display for ControllerDied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.failstop {
            Some(reason) => write!(f, "enforcement could not be confirmed ({reason}), so the controller stopped the run ({})", self.status),
            None => write!(f, "the controller died ({}) before it wrote a report", self.status),
        }
    }
}

impl Error for ControllerDied {}

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
/// reaped: what `reap` stops, then the run directory with the operator's reset key.
/// The controller tears down after itself; this is for the case where it could not.
pub fn sweep(root: &Path, run_id: &str) {
    reap(root, run_id);
    let _ = fs::remove_dir_all(root);
}

/// Stops what a run whose controller has been reaped can leave running: its cgroups
/// and whatever is in them, and helper processes the controller could not stop (it
/// may have been killed). The run directory and the evidence in it stay.
pub fn reap(root: &Path, run_id: &str) {
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
    let leak = SABOTAGE_BUILD && weakness == "start_leak";
    let mut guard = Startup { child: None, root: root.clone(), run_id: run_id.clone(), armed: true, leak };
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
    Ok(LiveRun { root, private_dir, child, key, run_id, status, leak })
}

/// Waits for the run to end. Returns the controller's report, or `ControllerDied`.
/// A controller that did not exit cleanly could not tear down after itself, so this
/// stops what it left running. Either way the run directory stays, for `save`.
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
        if let Some(status) = run.child.try_wait()? {
            if !status.success() && !run.leak {
                reap(&run.root, &run.run_id);
            }
            return match fs::read(run.private_dir.join("report.json")) {
                Ok(report) => Ok(serde_json::from_slice(&report)?),
                Err(_) => {
                    let failstop = fs::read(run.private_dir.join("failstop.json")).ok()
                        .and_then(|b| serde_json::from_slice::<Value>(&b).ok()).map(|v| v["reason"].as_str().unwrap_or("no reason was given").to_owned());
                    Err(Box::new(ControllerDied { failstop, status }))
                }
            };
        }
        let now = run.mode();
        if now != mode && now != "unknown" {
            on_mode(&now);
            mode = now;
        }
        sleep(Duration::from_millis(100));
    }
}

/// Saves what the run in `root` left to `out`: the report if there is one, the
/// transcript, the HUD's events and a fail-stop record. A file this run did not
/// leave is removed from `out`, so `out` describes this run alone. Then the run
/// directory goes. A failed copy keeps it, so nothing is lost.
pub fn save(root: &Path, report: Option<&Value>, out: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out)?;
    match report {
        Some(report) => write_replace(&out.join("report.json"), &serde_json::to_vec_pretty(report)?)?,
        None => remove_stale(&out.join("report.json"))?,
    }
    for (from, to) in [("agent.jsonl", "transcript.jsonl"), ("events.jsonl", "events.jsonl"), ("failstop.json", "failstop.json")] {
        let source = root.join("private").join(from);
        if source.exists() {
            fs::copy(&source, out.join(to)).map_err(|e| format!("saving {to}: {e}; the run is still in {}", root.display()))?;
        } else {
            remove_stale(&out.join(to))?;
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

fn remove_stale(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `wait`, then `save` to `out`, whether or not the controller wrote a report.
/// `live` ends every run this way.
pub fn finish(run: &mut LiveRun, out: &Path, on_line: impl FnMut(&Value), on_mode: impl FnMut(&str)) -> Result<Value, Box<dyn Error>> {
    match wait(run, on_line, on_mode) {
        Ok(report) => save(&run.root, Some(&report), out).map(|()| report),
        Err(died) if died.is::<ControllerDied>() => save(&run.root, None, out).and(Err(died)),
        Err(error) => Err(error),
    }
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
    format!("final mode: {}\nmode changes: {}\nclassifier signals: {}\nlive use: {}\nprogram: {}{warning}",
        report["final_mode"].as_str().unwrap_or("?"),
        if transitions.is_empty() { "none".to_owned() } else { transitions.join("; ") },
        report["classifier_signals"].as_array().map_or(0, Vec::len),
        report["live"], report["program"])
}

/// Why `live` exits non-zero after this report, if it does: the program did not
/// start, or it exited non-zero or was killed by a signal.
pub fn program_failure(report: &Value) -> Option<String> {
    let program = &report["program"];
    if report["exit_cause"] == "program_did_not_start" {
        return Some(format!("the program did not start: {}", program["reason"].as_str().unwrap_or("no reason was given")));
    }
    match (program["exit_code"].as_i64(), program["signal"].as_i64()) {
        (Some(code), _) if code != 0 => Some(format!("the program exited with status {code}")),
        (_, Some(signal)) => Some(format!("the program was killed by signal {signal}")),
        _ => None,
    }
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
    /// Where to save report.json, transcript.jsonl, events.jsonl and any failstop.json [default: results/live/<run id>]
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
    let out = out.unwrap_or_else(|| PathBuf::from("results/live").join(&run.run_id));
    let ended = finish(&mut run, &out, |e| if let Some(line) = describe(e) { println!("{line}") }, |m| println!(">>> mode is now {m}"));
    match ended {
        Ok(report) => {
            println!("\n{}", summarise(&report));
            println!("saved to {}", out.display());
            program_failure(&report).map_or(Ok(()), |failure| Err(failure.into()))
        }
        Err(died) if died.is::<ControllerDied>() => {
            println!("\nsaved to {}", out.display());
            Err(died)
        }
        Err(error) => Err(error),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_fails_for_a_program_that_did_not_start_or_did_not_exit_cleanly() {
        let report = |cause: &str, program: Value| json!({"exit_cause": cause, "program": program});
        assert_eq!(program_failure(&report("agent_finished", json!({"started": true, "exit_code": 0}))), None);
        assert_eq!(program_failure(&report("operator_stop", json!({"started": true}))), None);
        let not_started = program_failure(&report("program_did_not_start", json!({"started": false, "reason": "exec /x: gone"})));
        assert!(not_started.is_some_and(|m| m.contains("did not start") && m.contains("exec /x: gone")));
        assert!(program_failure(&report("agent_finished", json!({"started": true, "exit_code": 3}))).is_some_and(|m| m.contains("status 3")));
        assert!(program_failure(&report("agent_finished", json!({"started": true, "signal": 9}))).is_some_and(|m| m.contains("signal 9")));
    }

    #[test]
    fn a_controller_that_died_is_told_apart_from_one_that_fail_stopped() {
        use std::os::unix::process::ExitStatusExt;
        let failstop = ControllerDied { failstop: Some("enforcer stalled".to_owned()), status: ExitStatus::from_raw(70 << 8) };
        assert!(failstop.to_string().starts_with("enforcement could not be confirmed (enforcer stalled)"));
        let killed = ControllerDied { failstop: None, status: ExitStatus::from_raw(libc::SIGKILL) };
        assert!(killed.to_string().starts_with("the controller died"));
    }

    #[test]
    fn saving_a_run_without_a_report_keeps_its_evidence_and_nothing_stale() {
        let base = std::env::temp_dir().join(format!("vac-save-{}-{}", std::process::id(), boot_ns()));
        let (root, out) = (base.join("run"), base.join("out"));
        fs::create_dir_all(root.join("private")).expect("run dir");
        fs::create_dir_all(&out).expect("out");
        fs::write(root.join("private/agent.jsonl"), "{\"event\":\"started\"}\n").expect("transcript");
        fs::write(root.join("private/failstop.json"), "{\"reason\":\"enforcer stalled\"}").expect("failstop");
        // Left in `out` by an earlier run that did write a report.
        fs::write(out.join("report.json"), "{}").expect("stale report");
        fs::write(out.join("events.jsonl"), "stale").expect("stale events");
        save(&root, None, &out).expect("save");
        assert_eq!(fs::read_to_string(out.join("transcript.jsonl")).ok().as_deref(), Some("{\"event\":\"started\"}\n"));
        assert!(fs::read_to_string(out.join("failstop.json")).is_ok_and(|t| t.contains("enforcer stalled")));
        assert!(!out.join("report.json").exists() && !out.join("events.jsonl").exists());
        assert!(!root.exists());
        let _ = fs::remove_dir_all(base);
    }
}

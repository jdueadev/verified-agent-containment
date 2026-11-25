use crate::common::boot_ns;
use serde_json::json;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn monitor(args: &[String]) -> Result<(), Box<dyn Error>> {
    let socket = args.first().ok_or("monitor socket is required")?;
    let period_ms: u64 = args.get(1).ok_or("period is required")?.parse()?;
    let ttl_ms: u64 = args.get(2).ok_or("ttl is required")?.parse()?;
    loop {
        let _ = crate::common::request(Path::new(socket), &json!({"op": "renew", "ttl_ms": ttl_ms}));
        thread::sleep(Duration::from_millis(period_ms));
    }
}

/// Returns (admit_ns, write_ns, credential) for a record whose MAC verifies.
fn authenticate(line: &str, key: &[u8], token: &str) -> Option<(u64, u64, bool)> {
    let record: serde_json::Value = serde_json::from_str(line).ok()?;
    let admit = record["admit"].as_u64()?;
    let write = record["write"].as_u64()?;
    let host = record["host"].as_str()?;
    let data = record["data"].as_str()?;
    let credential = record["credential"].as_str().unwrap_or("");
    let expected = crate::common::record_mac(key, admit, write, host, data, credential);
    (record["mac"].as_str()? == expected).then_some((admit, write, credential == token))
}

/// External receiver. It records what actually arrived, independent of the agent.
pub fn sink(args: &[String]) -> Result<(), Box<dyn Error>> {
    let log_path = args.first().ok_or("sink log is required")?;
    let mut token = String::new();
    std::io::stdin().read_line(&mut token)?;
    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let token = Arc::new(token.trim().to_owned());
    let key = Arc::new(key.trim().as_bytes().to_vec());
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let log = Arc::new(Mutex::new(OpenOptions::new().create(true).append(true).open(log_path)?));
    for stream in listener.incoming() {
        let Ok(mut writer) = stream else { continue };
        let log = Arc::clone(&log);
        let token = Arc::clone(&token);
        let key = Arc::clone(&key);
        thread::spawn(move || {
            let Ok(reader) = writer.try_clone() else { return };
            let mut reader = BufReader::new(reader);
            let mut raw = Vec::new();
            loop {
                raw.clear();
                if !matches!(reader.read_until(b'\n', &mut raw), Ok(n) if n > 0) {
                    break;
                }
                let complete = raw.last() == Some(&b'\n');
                let line = String::from_utf8_lossy(&raw).trim_end_matches('\n').to_owned();
                let verified = authenticate(&line, &key, &token);
                let record = json!({
                    "complete": complete,
                    "ns": boot_ns(),
                    "bytes": line.len(),
                    "credential": verified.is_some_and(|v| v.2),
                    "admit_ns": verified.map(|v| v.0),
                    "write_ns": verified.map(|v| v.1),
                    "authenticated": verified.is_some(),
                });
                if let Ok(mut file) = log.lock() {
                    let _ = writeln!(file, "{record}");
                    let _ = file.flush();
                }
                if writer.write_all(b"ack\n").is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}

/// What the program finds in /dev: whether each device behaves as its name says, and
/// whether /dev/shm takes a file but will not run one. The file is not an executable,
/// so a mount that allowed exec would fail with ENOEXEC, not EACCES. It is removed
/// afterwards, in case /dev/shm is not the sandbox's own.
fn probe_dev() -> serde_json::Value {
    use std::io::Read;
    let errno = |result: std::io::Result<()>| json!(result.map_err(|e| e.raw_os_error()).err());
    let write = |path: &str| OpenOptions::new().write(true).open(path).and_then(|mut f| f.write_all(b"probe"));
    let read = |path: &str| -> std::io::Result<Vec<u8>> {
        let mut bytes = vec![0xff; 16];
        std::fs::File::open(path)?.read_exact(&mut bytes)?;
        Ok(bytes)
    };
    let script = "/dev/shm/probe";
    let shm_write = std::fs::write(script, b"not an executable\n")
        .and_then(|()| std::fs::set_permissions(script, std::os::unix::fs::PermissionsExt::from_mode(0o755)));
    let shm_exec = match std::process::Command::new(script).status() {
        Ok(status) => json!({"ran": status.code()}),
        Err(e) => json!(e.raw_os_error()),
    };
    let _ = std::fs::remove_file(script);
    json!({
        "null_write": errno(write("/dev/null")),
        "full_write": errno(write("/dev/full")),
        "zero_read": read("/dev/zero").map_or_else(|e| json!(e.raw_os_error()), |b| json!(b.iter().all(|x| *x == 0))),
        "random_read": errno(read("/dev/random").map(drop)),
        "urandom_read": errno(read("/dev/urandom").map(drop)),
        "shm_write": errno(shm_write),
        "shm_exec": shm_exec,
    })
}

/// Run by the live suite as an outside program, from a root it assembled: asks the
/// gateway for `url`, lists `/`, `/tmp` and `/dev`, uses /dev, tries to create each of
/// `writes`, and prints what happened as one transcript line. Nothing here is trusted
/// by the check that a request went through the gateway; that is read from the server.
pub fn probe_root(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [url, writes @ ..] = args else { return Err("probe-root arguments are invalid".into()) };
    let gateway = std::env::var("VAC_GATE").map_err(|_| "VAC_GATE is not set")?;
    let reply = crate::common::request(Path::new(&gateway), &json!({"op": "http", "method": "GET", "url": url}))
        .unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}));
    let names = |dir: &str| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    };
    let written: serde_json::Map<String, serde_json::Value> = writes.iter()
        .map(|path| (path.clone(), json!(std::fs::write(path, "probe").map_err(|e| e.raw_os_error()).err())))
        .collect();
    println!("{}", json!({"event": "probe_root", "value": {"gateway": reply, "root": names("/"), "tmp": names("/tmp"), "dev": names("/dev"), "dev_use": probe_dev(), "write_errors": written}}));
    Ok(())
}

/// Run as an unprivileged uid by the harness: tries operator requests,
/// including a validly signed reset it was handed, and prints the replies.
pub fn probe_operator(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [control, reset, signed_reset] = args else { return Err("probe-operator arguments are invalid".into()) };
    let send = |socket: &str, message: serde_json::Value| {
        crate::common::request(std::path::Path::new(socket), &message)
            .unwrap_or_else(|e| serde_json::json!({"ok": false, "error": e.to_string(), "connect_failed": true}))
    };
    let status = send(control, serde_json::json!({"op":"status"}));
    let hard = send(control, serde_json::json!({"op":"hard","level":"kill"}));
    let reset = send(reset, serde_json::from_str(signed_reset)?);
    println!("{}", serde_json::json!({"status": status, "hard": hard, "reset": reset}));
    Ok(())
}

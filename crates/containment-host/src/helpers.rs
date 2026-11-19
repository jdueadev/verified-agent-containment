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

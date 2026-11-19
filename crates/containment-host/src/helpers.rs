use crate::common::mono_ns;
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

pub fn sink(args: &[String]) -> Result<(), Box<dyn Error>> {
    let log_path = args.first().ok_or("sink log is required")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let log = Arc::new(Mutex::new(OpenOptions::new().create(true).append(true).open(log_path)?));
    for stream in listener.incoming() {
        let Ok(mut writer) = stream else { continue };
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let Ok(reader) = writer.try_clone() else { return };
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                let record = json!({
                    "ns": mono_ns(),
                    "bytes": line.len(),
                    "credential": line.contains("credential=broker-only-token"),
                    "canary": line.contains("canary-token")
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

//! `containment-lab hud --run DIR [--port 8787]`: a read-only local page for a
//! live run. It serves on 127.0.0.1 only, reads the controller's event log and
//! asks the control socket for status. It can only observe, never control.
use crate::common::request;
use crate::mock::{read_request, respond};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;

const PAGE: &str = include_str!("hud.html");

fn events_from(path: &Path, from: usize) -> Value {
    let Ok(file) = fs::File::open(path) else { return json!([]) };
    let items: Vec<Value> = BufReader::new(file).lines().skip(from).take(5_000)
        .map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect();
    json!(items)
}

/// Serves the HUD for `run` until the process exits.
pub fn serve(run: PathBuf, port: u16) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("HUD: http://127.0.0.1:{}/", listener.local_addr()?.port());
    let status: Value = serde_json::from_slice(&fs::read(run.join("private/status.json"))?)?;
    let control = PathBuf::from(status["control_socket"].as_str().unwrap_or(""));
    let events = run.join("private/events.jsonl");
    let name = run.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (control, events, name) = (control.clone(), events.clone(), name.clone());
        thread::spawn(move || {
            let Ok(req) = read_request(&stream) else { return };
            if req.method != "GET" {
                return respond(&stream, 405, "text/plain", b"read-only");
            }
            let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
            match path {
                "/" => respond(&stream, 200, "text/html; charset=utf-8", PAGE.as_bytes()),
                "/info" => respond(&stream, 200, "application/json", json!({"run": name}).to_string().as_bytes()),
                "/status" => {
                    let value = request(&control, &json!({"op": "status"})).unwrap_or_else(|_| json!({"mode": "ended"}));
                    respond(&stream, 200, "application/json", value.to_string().as_bytes());
                }
                "/events" => {
                    let from = query.strip_prefix("from=").and_then(|n| n.parse().ok()).unwrap_or(0);
                    respond(&stream, 200, "application/json", events_from(&events, from).to_string().as_bytes());
                }
                _ => respond(&stream, 404, "text/plain", b"not found"),
            }
        });
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [flag, dir] if flag == "--run" => serve(PathBuf::from(dir), 8787),
        [flag, dir, p, port] if flag == "--run" && p == "--port" => serve(PathBuf::from(dir), port.parse()?),
        _ => Err("usage: containment-lab hud --run DIR [--port PORT]".into()),
    }
}

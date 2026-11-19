//! `containment-lab hud --run DIR [--port 8787]`: a read-only local page for a
//! live run. It serves on 127.0.0.1 only, reads the controller's event log and
//! asks the control socket for status. It can only observe, never control.
//!
//! Any local user can reach 127.0.0.1, so the page lives under a random path
//! printed once on the operator's terminal. Requests whose Host is not
//! 127.0.0.1 or localhost are refused (DNS rebinding), and responses forbid
//! framing, caching, referrers and loading anything from elsewhere.
use crate::common::request;
use crate::mock::read_request;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

const PAGE: &str = include_str!("hud.html");

fn events_from(path: &Path, from: usize) -> Value {
    let Ok(file) = fs::File::open(path) else { return json!([]) };
    let items: Vec<Value> = BufReader::new(file).lines().skip(from).take(5_000)
        .map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect();
    json!(items)
}

const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn respond(mut stream: &TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let head = format!("HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nContent-Security-Policy: {CSP}\r\n\
        X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        if status == 200 { "OK" } else { "Error" }, body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// True when the Host header names this server by loopback address or localhost.
fn host_ok(headers: &[(String, String)], port: u16) -> bool {
    let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.as_str());
    host.is_some_and(|h| [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].iter().any(|ok| ok == h))
}

/// Serves the HUD for `run` until the process exits.
pub fn serve(run: PathBuf, port: u16) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let port = listener.local_addr()?.port();
    let mut seed = [0_u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let token = crate::common::hex_encode(&seed);
    eprintln!("HUD (read-only; keep this link private): http://127.0.0.1:{port}/{token}/");
    let status: Value = serde_json::from_slice(&fs::read(run.join("private/status.json"))?)?;
    let control = PathBuf::from(status["control_socket"].as_str().unwrap_or(""));
    let events = run.join("private/events.jsonl");
    let name = run.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (control, events, name, token) = (control.clone(), events.clone(), name.clone(), token.clone());
        thread::spawn(move || {
            let Ok(req) = read_request(&stream) else { return };
            if !host_ok(&req.headers, port) {
                return respond(&stream, 403, "text/plain", b"wrong host");
            }
            if req.method != "GET" {
                return respond(&stream, 405, "text/plain", b"read-only");
            }
            let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
            let Some(path) = path.strip_prefix('/').and_then(|p| p.strip_prefix(token.as_str())) else {
                return respond(&stream, 404, "text/plain", b"not found");
            };
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

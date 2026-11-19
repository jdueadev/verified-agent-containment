//! Test servers for live runs. Both log every request with a CLOCK_BOOTTIME
//! stamp so checks can compare arrivals with the controller's commit times.
//!
//! - `mock-model`: an OpenAI-compatible chat completions endpoint that replays a
//!   scripted list of assistant messages, so live runs are deterministic.
//! - `fixture-server`: serves files from a directory for GET and records the
//!   body and headers of every other method. It stands in for a write host and
//!   for pages that carry prompt injections.
use crate::common::boot_ns;
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("/").to_owned();
    let mut headers = Vec::new();
    let mut length = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim().to_owned(), value.trim().to_owned());
            if name.eq_ignore_ascii_case("content-length") {
                length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0; length.min(4 << 20)];
    reader.read_exact(&mut body)?;
    Ok(Request { method, path, headers, body })
}

pub fn respond(mut stream: &TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let head = format!("HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

struct Log(Mutex<fs::File>);

impl Log {
    fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self(Mutex::new(OpenOptions::new().create(true).append(true).open(path)?)))
    }
    fn write(&self, value: Value) {
        if let Ok(mut file) = self.0.lock() {
            let _ = writeln!(file, "{value}");
        }
    }
}

/// Binds 127.0.0.1:port (0 picks one), prints the port on stdout, and serves.
fn serve(port: u16, handler: impl Fn(&TcpStream, Request) + Send + Sync + 'static) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("{}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            if let Ok(request) = read_request(&stream) {
                handler(&stream, request);
            }
        });
    }
    Ok(())
}

/// `mock-model PORT SCRIPT LOG`: SCRIPT is a JSON array of assistant messages,
/// each `{"content": "...", "tool_calls": [{"name": "...", "arguments": {...}}]}`.
/// Request n gets message n; after the last, it keeps returning the last one.
pub fn mock_model(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [port, script, log] = args else { return Err("mock-model PORT SCRIPT LOG".into()) };
    let script: Vec<Value> = serde_json::from_str(&fs::read_to_string(script)?)?;
    let log = Log::open(Path::new(log))?;
    let next = AtomicUsize::new(0);
    serve(port.parse()?, move |stream, request| {
        let n = next.fetch_add(1, Ordering::SeqCst);
        let incoming: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        log.write(json!({"ns": boot_ns(), "n": n, "path": request.path, "messages": incoming["messages"].as_array().map_or(0, Vec::len)}));
        let entry = script.get(n).or(script.last()).cloned().unwrap_or(json!({"content": "done"}));
        // "{{last_tool}}" in arguments becomes the last tool result the agent sent,
        // so a script can act on what the agent just read (an exfiltrating model).
        let last_tool = incoming["messages"].as_array().into_iter().flatten().rev()
            .find(|m| m["role"] == "tool").and_then(|m| m["content"].as_str()).unwrap_or("").to_owned();
        let calls: Vec<Value> = entry["tool_calls"].as_array().into_iter().flatten().enumerate().map(|(i, c)| {
            let arguments = serde_json::to_string(&c["arguments"]).unwrap_or_default();
            let escaped = serde_json::to_string(&last_tool).unwrap_or_default();
            let arguments = arguments.replace("{{last_tool}}", escaped.trim_matches('"'));
            json!({"id": format!("call_{n}_{i}"), "type": "function", "function": {"name": c["name"], "arguments": arguments}})
        }).collect();
        let message = json!({"role": "assistant", "content": entry["content"], "tool_calls": if calls.is_empty() { Value::Null } else { json!(calls) }});
        let body = json!({"id": format!("mock-{n}"), "object": "chat.completion", "model": incoming["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": if calls.is_empty() { "stop" } else { "tool_calls" }}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}});
        respond(stream, 200, "application/json", body.to_string().as_bytes());
    })
}

/// `fixture-server PORT DIR LOG`: GET serves DIR; other methods are recorded.
pub fn fixture_server(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [port, dir, log] = args else { return Err("fixture-server PORT DIR LOG".into()) };
    let dir = PathBuf::from(dir);
    let log = Log::open(Path::new(log))?;
    serve(port.parse()?, move |stream, request| {
        let headers: serde_json::Map<String, Value> = request.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), json!(v))).collect();
        log.write(json!({"ns": boot_ns(), "method": request.method, "path": request.path, "headers": headers,
            "body": String::from_utf8_lossy(&request.body)}));
        if request.method == "GET" {
            let relative = request.path.trim_start_matches('/').split('?').next().unwrap_or("").to_owned();
            let safe = Path::new(&relative).components().all(|c| matches!(c, Component::Normal(_)));
            match fs::read(dir.join(if relative.is_empty() { "index.html" } else { &relative })) {
                Ok(bytes) if safe => respond(stream, 200, "text/html; charset=utf-8", &bytes),
                _ => respond(stream, 404, "text/plain", b"not found"),
            }
        } else {
            respond(stream, 200, "application/json", br#"{"ok":true}"#);
        }
    })
}

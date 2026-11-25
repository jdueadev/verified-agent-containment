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
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
        log.write(json!({"ns": boot_ns(), "n": n, "path": request.path, "messages": incoming["messages"].as_array().map_or(0, Vec::len),
            "body": String::from_utf8_lossy(&request.body)}));
        let entry = script.get(n).or(script.last()).cloned().unwrap_or(json!({"content": "done"}));
        // "delay_ms" makes a call as slow as a real model's. A request whose last
        // message is "delay_ms=N" sets its own delay instead, whatever its place
        // in the script.
        let asked = incoming["messages"].as_array().and_then(|m| m.last()).and_then(|m| m["content"].as_str())
            .and_then(|c| c.strip_prefix("delay_ms=")).and_then(|ms| ms.parse().ok());
        if let Some(ms) = asked.or(entry["delay_ms"].as_u64()) {
            thread::sleep(std::time::Duration::from_millis(ms.min(10_000)));
        }
        // "{{last_tool}}" in arguments becomes the last tool result the agent sent,
        // so a script can act on what the agent just read (an exfiltrating model).
        let last_tool = incoming["messages"].as_array().into_iter().flatten().rev()
            .find(|m| m["role"] == "tool").and_then(|m| m["content"].as_str()).unwrap_or("").to_owned();
        let calls: Vec<Value> = entry["tool_calls"].as_array().into_iter().flatten().enumerate().map(|(i, c)| {
            let arguments = serde_json::to_string(&c["arguments"]).unwrap_or_default();
            let escaped = serde_json::to_string(&last_tool).unwrap_or_default();
            let arguments = arguments.replace("{{last_tool}}", escaped.trim_matches('"'));
            let arguments = fill_files(&arguments);
            json!({"id": format!("call_{n}_{i}"), "type": "function", "function": {"name": c["name"], "arguments": arguments}})
        }).collect();
        let message = json!({"role": "assistant", "content": entry["content"], "tool_calls": if calls.is_empty() { Value::Null } else { json!(calls) }});
        let body = json!({"id": format!("mock-{n}"), "object": "chat.completion", "model": incoming["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": if calls.is_empty() { "stop" } else { "tool_calls" }}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}});
        respond(stream, 200, "application/json", body.to_string().as_bytes());
    })
}

/// Replaces each `{{file:PATH}}` with the trimmed contents of PATH, waiting up
/// to two seconds for it to appear. The live suite uses this to hand the mock
/// model a value (the workspace canary) that only exists once the run starts.
fn fill_files(text: &str) -> String {
    let mut out = text.to_owned();
    while let Some(start) = out.find("{{file:") {
        let Some(len) = out[start..].find("}}") else { break };
        let path = out[start + 7..start + len].to_owned();
        let began = std::time::Instant::now();
        let mut value = fs::read_to_string(&path);
        while value.is_err() && began.elapsed() < std::time::Duration::from_secs(2) {
            thread::sleep(std::time::Duration::from_millis(20));
            value = fs::read_to_string(&path);
        }
        out.replace_range(start..start + len + 2, value.unwrap_or_default().trim());
    }
    out
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
        if request.method == "GET" && request.path == "/echo" {
            // Echoes request headers, as some real services do in errors or debug output.
            // Also echoes the bare token after any scheme, as error messages often do.
            let mut lines: Vec<String> = request.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            lines.extend(request.headers.iter().filter_map(|(_, v)| v.split_once(' ').map(|(_, token)| format!("invalid token {token}"))));
            let echoed = json!(lines);
            respond(stream, 200, "application/json", echoed.to_string().as_bytes());
        } else if request.method == "GET" {
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

/// Every line of a log a server may still be appending to. The server writes a
/// line in several pieces, so a read can end inside the last line; that line is
/// given a moment to be finished. A line that stays unfinished, or is not JSON,
/// is an error.
fn read_log(path: &Path) -> std::io::Result<Vec<Value>> {
    let invalid = |why: String| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {why}", path.display()));
    let began = Instant::now();
    let text = loop {
        let text = fs::read_to_string(path)?;
        if text.is_empty() || text.ends_with('\n') {
            break text;
        }
        if began.elapsed() > Duration::from_secs(1) {
            return Err(invalid("the last line was never finished".into()));
        }
        thread::sleep(Duration::from_millis(1));
    };
    text.lines().map(|line| serde_json::from_str(line).map_err(|e| invalid(e.to_string()))).collect()
}

/// A test server started as a child process; it prints its port on stdout.
pub struct Server {
    child: Child,
    pub port: u16,
    pub log: PathBuf,
}

impl Server {
    pub fn start(kind: &str, arg: &Path, log: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new(std::env::current_exe()?).arg(kind).arg("0").arg(arg).arg(&log)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
        let mut line = String::new();
        BufReader::new(child.stdout.take().ok_or("server stdout")?).read_line(&mut line)?;
        Ok(Self { child, port: line.trim().parse()?, log })
    }

    /// Every logged request; an unreadable log or a malformed line is an error,
    /// so a check can never pass on missing evidence.
    pub fn try_entries(&self) -> std::io::Result<Vec<Value>> {
        read_log(&self.log)
    }

    pub fn entries(&self) -> Vec<Value> {
        fs::read_to_string(&self.log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("vac-mock-{name}-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn a_log_being_written_reads_as_whole_lines() {
        let path = scratch("busy");
        let log = Log::open(&path).unwrap();
        let writer = thread::spawn(move || {
            for n in 0..20_000 {
                log.write(json!({"n": n, "headers": {"host": "example.test", "accept": "*/*"}, "body": "x".repeat(64)}));
            }
        });
        let mut torn = 0;
        while !writer.is_finished() {
            let raw = fs::read_to_string(&path).unwrap();
            torn += usize::from(!raw.is_empty() && !raw.ends_with('\n'));
            read_log(&path).unwrap();
        }
        writer.join().unwrap();
        assert_eq!(read_log(&path).unwrap().len(), 20_000);
        let _ = fs::remove_file(&path);
        assert!(torn > 0, "no raw read ended inside a line, so this run did not exercise the race");
    }

    #[test]
    fn a_line_that_is_never_finished_is_an_error() {
        let path = scratch("cut");
        fs::write(&path, "{\"n\":1}\n{\"n\":").unwrap();
        let error = read_log(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(error.to_string().contains("never finished"), "{error}");
    }

    #[test]
    fn a_finished_line_that_is_not_json_is_an_error() {
        let path = scratch("bad");
        fs::write(&path, "{\"n\":1}\nnot json\n").unwrap();
        let error = read_log(&path);
        let _ = fs::remove_file(&path);
        assert!(error.is_err());
    }
}

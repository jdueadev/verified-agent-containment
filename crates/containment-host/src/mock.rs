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

/// A test certificate authority and the certificate it issued for 127.0.0.1,
/// valid 2026 to 2126. They exist so the live suite can send a credential over
/// https to a server on loopback; the key protects nothing.
pub const TLS_CA: &str = include_str!("fixture_tls/ca.pem");
const TLS_CERT: &str = include_str!("fixture_tls/server.pem");
const TLS_KEY: &str = include_str!("fixture_tls/server.key");

fn tls_server() -> Result<Arc<rustls::ServerConfig>, Box<dyn Error>> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    let chain = vec![CertificateDer::from_pem_slice(TLS_CERT.as_bytes())?, CertificateDer::from_pem_slice(TLS_CA.as_bytes())?];
    let key = PrivateKeyDer::from_pem_slice(TLS_KEY.as_bytes())?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

pub fn read_request(stream: impl Read) -> std::io::Result<Request> {
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

/// What a handler answers: status, content type and body.
type Reply = (u16, &'static str, Vec<u8>);

pub fn respond(mut stream: impl Write, (status, content_type, body): Reply) {
    let head = format!("HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
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

/// Reads one request from `stream` and answers it, over TLS when `tls` is given.
fn answer(stream: TcpStream, tls: Option<Arc<rustls::ServerConfig>>, handler: &(impl Fn(Request) -> Reply + ?Sized)) {
    match tls {
        Some(config) => {
            let Ok(connection) = rustls::ServerConnection::new(config) else { return };
            let mut stream = rustls::StreamOwned::new(connection, stream);
            if let Ok(request) = read_request(&mut stream) {
                respond(&mut stream, handler(request));
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        }
        None => {
            if let Ok(request) = read_request(&stream) {
                respond(&stream, handler(request));
            }
        }
    }
}

/// Binds 127.0.0.1:port (0 picks one), prints the port on stdout, and serves,
/// over TLS with the test certificate when `tls` is set.
fn serve(port: u16, tls: bool, handler: impl Fn(Request) -> Reply + Send + Sync + 'static) -> Result<(), Box<dyn Error>> {
    let tls = tls.then(tls_server).transpose()?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("{}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        let tls = tls.clone();
        thread::spawn(move || answer(stream, tls, &*handler));
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
    serve(port.parse()?, false, move |request| {
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
        (200, "application/json", body.to_string().into_bytes())
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

/// `fixture-server PORT DIR LOG [tls]`: GET serves DIR; other methods are recorded.
/// With `tls` it serves https with the test certificate for 127.0.0.1 (`TLS_CA`).
pub fn fixture_server(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (port, dir, log, tls) = match args {
        [port, dir, log] => (port, dir, log, false),
        [port, dir, log, tls] if tls == "tls" => (port, dir, log, true),
        _ => return Err("fixture-server PORT DIR LOG [tls]".into()),
    };
    let dir = PathBuf::from(dir);
    let log = Log::open(Path::new(log))?;
    serve(port.parse()?, tls, move |request| {
        let headers: serde_json::Map<String, Value> = request.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), json!(v))).collect();
        log.write(json!({"ns": boot_ns(), "method": request.method, "path": request.path, "headers": headers,
            "body": String::from_utf8_lossy(&request.body)}));
        if request.method == "GET" && request.path == "/echo" {
            // Echoes request headers, as some real services do in errors or debug output.
            // Also echoes the bare token after any scheme, as error messages often do.
            let mut lines: Vec<String> = request.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            lines.extend(request.headers.iter().filter_map(|(_, v)| v.split_once(' ').map(|(_, token)| format!("invalid token {token}"))));
            let echoed = json!(lines);
            (200, "application/json", echoed.to_string().into_bytes())
        } else if request.method == "GET" {
            let relative = request.path.trim_start_matches('/').split('?').next().unwrap_or("").to_owned();
            let safe = Path::new(&relative).components().all(|c| matches!(c, Component::Normal(_)));
            match fs::read(dir.join(if relative.is_empty() { "index.html" } else { &relative })) {
                Ok(bytes) if safe => (200, "text/html; charset=utf-8", bytes),
                _ => (404, "text/plain", b"not found".to_vec()),
            }
        } else {
            (200, "application/json", br#"{"ok":true}"#.to_vec())
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
    tls: bool,
}

impl Server {
    pub fn start(kind: &str, arg: &Path, log: PathBuf) -> Result<Self, Box<dyn Error>> {
        Self::spawn(kind, arg, log, false)
    }

    /// A fixture server that speaks https with the test certificate; a policy
    /// that lists it needs `TLS_CA` under `[tls] roots`.
    pub fn start_tls(arg: &Path, log: PathBuf) -> Result<Self, Box<dyn Error>> {
        Self::spawn("fixture-server", arg, log, true)
    }

    fn spawn(kind: &str, arg: &Path, log: PathBuf, tls: bool) -> Result<Self, Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg(kind).arg("0").arg(arg).arg(&log);
        if tls {
            command.arg("tls");
        }
        let mut child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
        let mut line = String::new();
        BufReader::new(child.stdout.take().ok_or("server stdout")?).read_line(&mut line)?;
        Ok(Self { child, port: line.trim().parse()?, log, tls })
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
        format!("{}://127.0.0.1:{}", if self.tls { "https" } else { "http" }, self.port)
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

    /// The gateway's client reaches the https fixture only when it trusts the
    /// test authority, and the credential header arrives over TLS.
    #[test]
    fn the_tls_fixture_is_trusted_only_through_its_authority() {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let ca = CertificateDer::from_pem_slice(TLS_CA.as_bytes()).unwrap();
        for (roots, reached) in [(vec![ca], true), (Vec::new(), false)] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let url = crate::http::Url::parse(&format!("https://127.0.0.1:{}/", listener.local_addr().unwrap().port())).unwrap();
            let config = tls_server().unwrap();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                answer(stream, Some(config), &|r: Request| {
                    let auth = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone());
                    (200, "text/plain", auth.unwrap_or_default().into_bytes())
                });
            });
            let client = crate::http::tls_client(&roots).unwrap();
            let headers = [("Authorization".to_owned(), "Bearer t0ken".to_owned())];
            let sent = crate::http::send(&url, &client, "GET", &headers, b"", crate::http::Limits::WEB, |_| true);
            server.join().unwrap();
            match sent {
                Ok(r) => assert!(reached && r.status == 200 && r.body == b"Bearer t0ken", "{:?}", String::from_utf8_lossy(&r.body)),
                Err(e) => assert!(!reached, "{e}"),
            }
        }
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

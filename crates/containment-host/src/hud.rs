//! `containment-lab hud --run DIR [--port 8787]`: a read-only local page for a
//! live run. It serves on 127.0.0.1 only, reads the controller's event log and
//! asks the control socket for status. It can only observe, never control.
//!
//! Any local user can reach 127.0.0.1, so the page lives under a random path
//! printed once on the operator's terminal. Requests whose Host is not
//! 127.0.0.1 or localhost are refused (DNS rebinding), and responses forbid
//! framing, caching, referrers and loading anything from elsewhere.
use crate::common::request;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// At most this many requests are handled at once; more are dropped.
const MAX_CONNECTIONS: usize = 16;
const MAX_HEADERS: usize = 100;

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

/// A reader that fails once the request's deadline has passed, checked on
/// every read, so a client trickling one byte at a time cannot hold a slot.
struct Deadline<'a> {
    stream: &'a TcpStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request took too long"));
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}

/// Reads a request line and headers with bounded lines (8 KB, at most 100
/// headers) within 5 s for the whole request. No body is read: the HUD only serves GET.
fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(Deadline { stream, until: Instant::now() + Duration::from_secs(5) });
    let mut line = String::new();
    crate::http::bounded_line(&mut reader, &mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or("").to_owned(), parts.next().unwrap_or("/").to_owned());
    let mut headers = Vec::new();
    loop {
        if crate::http::bounded_line(&mut reader, &mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too many headers"));
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok(Request { method, path, headers })
}

/// Compares in time independent of where the first difference is.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

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
    let active = Arc::new(AtomicUsize::new(0));
    // Status is cached briefly so polling cannot keep taking the control lock.
    let cached: Arc<Mutex<Option<(Instant, Value)>>> = Arc::default();
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (control, events, name, token, active, cached) =
            (control.clone(), events.clone(), name.clone(), token.clone(), Arc::clone(&active), Arc::clone(&cached));
        thread::spawn(move || {
            struct Release(Arc<AtomicUsize>);
            impl Drop for Release {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _release = Release(active);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let Ok(req) = read_request(&stream) else { return };
            if !host_ok(&req.headers, port) {
                return respond(&stream, 403, "text/plain", b"wrong host");
            }
            if req.method != "GET" {
                return respond(&stream, 405, "text/plain", b"read-only");
            }
            let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
            let rest = path.strip_prefix('/').unwrap_or("");
            let (given, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if !same(given.as_bytes(), token.as_bytes()) {
                return respond(&stream, 404, "text/plain", b"not found");
            }
            match path {
                "/" => respond(&stream, 200, "text/html; charset=utf-8", PAGE.as_bytes()),
                "/info" => respond(&stream, 200, "application/json", json!({"run": name}).to_string().as_bytes()),
                "/status" => {
                    let mut cache = cached.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let value = match &*cache {
                        Some((at, v)) if at.elapsed() < Duration::from_millis(200) => v.clone(),
                        _ => {
                            let v = request(&control, &json!({"op": "status"})).unwrap_or_else(|_| json!({"mode": "ended"}));
                            *cache = Some((Instant::now(), v.clone()));
                            v
                        }
                    };
                    drop(cache);
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

/// Serves the read-only HUD for a running live controller on 127.0.0.1.
#[derive(clap::Parser)]
struct Args {
    /// The run directory printed by `live` (/run/verified-agent-containment/live-...)
    #[arg(long)]
    run: PathBuf,
    /// Local port; 0 picks a free one
    #[arg(long, default_value_t = 8787)]
    port: u16,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(Args { run, port }) = crate::common::parse_args::<Args>("hud", args)? else { return Ok(()) };
    serve(run, port)
}

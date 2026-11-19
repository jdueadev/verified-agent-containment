//! Minimal HTTP/1.1 client for the gateway (design spec section 7, Path A).
//!
//! The gateway, not the agent, is the HTTP and TLS client, so credentials are
//! added here and never enter the sandbox. The caller gets a clone of the TCP
//! stream before any byte is written, so a stop can shut the connection down
//! mid-request, exactly like the lab sink connections.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 100;

/// True for a host written as a loopback IP literal or `localhost`.
pub fn is_loopback_literal(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Addresses a name in the policy must not resolve to: loopback, private,
/// link-local (including 169.254.169.254), unspecified and similar. A policy
/// that means one of these must list the IP literal itself.
fn internal(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_multicast()
                || o[0] == 0 || o[0] >= 240 || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80
                || (s0 & 0xffc0) == 0xfec0 || v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                || v6.to_ipv4_mapped().is_some_and(|v4| internal(v4.into()))
                // Deprecated IPv4-compatible form ::a.b.c.d.
                || (v6.segments()[..6] == [0; 6] && internal(std::net::Ipv4Addr::from((u32::from(v6.segments()[6]) << 16) | u32::from(v6.segments()[7])).into()))
        }
    }
}
const TIMEOUT: Duration = Duration::from_secs(60);
/// Whole-request limit (connect, send and the full response), so a peer that
/// trickles bytes cannot hold a gateway worker and its slot indefinitely.
const DEADLINE: Duration = Duration::from_secs(120);

/// A TCP stream whose every read and write fails once the request deadline passes.
struct Deadline {
    tcp: TcpStream,
    until: std::time::Instant,
}

impl Deadline {
    fn arm(&self) -> io::Result<()> {
        let left = self.until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            let _ = self.tcp.shutdown(Shutdown::Both);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "upstream request took too long"));
        }
        self.tcp.set_read_timeout(Some(left.min(TIMEOUT)))?;
        self.tcp.set_write_timeout(Some(left.min(TIMEOUT)))
    }
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.tcp.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    /// Parses `http(s)://host[:port][/path]`. No userinfo, no IPv6 literals.
    pub fn parse(text: &str) -> Option<Self> {
        let (https, rest) = if let Some(r) = text.strip_prefix("https://") {
            (true, r)
        } else {
            (false, text.strip_prefix("http://")?)
        };
        let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
        if authority.is_empty() || authority.contains('@') || authority.contains('[') {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (authority, if https { 443 } else { 80 }),
        };
        let valid = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
        if host.is_empty() || !host.chars().all(valid) || path.chars().any(|c| c.is_control() || c == ' ') {
            return None;
        }
        Some(Self { https, host: host.to_ascii_lowercase(), port, path: path.to_owned() })
    }

    /// `scheme://host:port`, the unit the policy grants access to.
    pub fn origin(&self) -> String {
        format!("{}://{}:{}", if self.https { "https" } else { "http" }, self.host, self.port)
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub truncated: bool,
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Sends one request with `Connection: close`. `register` receives a clone of
/// the TCP stream before anything is written; returning false aborts.
pub fn send(
    url: &Url, method: &str, headers: &[(String, String)], body: &[u8], register: impl FnOnce(TcpStream) -> bool,
) -> io::Result<Response> {
    let literal = url.host.parse::<std::net::IpAddr>().is_ok() || url.host == "localhost";
    let address = (url.host.as_str(), url.port).to_socket_addrs()?.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host did not resolve"))?;
    if !literal && internal(address.ip()) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "name resolves to an internal address; list the IP literal in the policy if that is intended"));
    }
    let until = std::time::Instant::now() + DEADLINE;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    if !register(tcp.try_clone()?) {
        let _ = tcp.shutdown(Shutdown::Both);
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "cut before write"));
    }
    let mut head = format!("{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: containment-gateway/0.1\r\n", url.path, url.host);
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (name, value) in headers {
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "header contains a line break"));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    if url.https {
        let name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad server name"))?;
        let connection = rustls::ClientConnection::new(tls_config(), name).map_err(io::Error::other)?;
        let mut stream = rustls::StreamOwned::new(connection, Deadline { tcp, until });
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        read_response(stream)
    } else {
        let mut stream = Deadline { tcp, until };
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        read_response(stream)
    }
}

/// Reads one line of at most MAX_LINE bytes.
pub(crate) fn bounded_line(reader: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    line.clear();
    let n = reader.take(MAX_LINE).read_line(line)?;
    if n as u64 == MAX_LINE && !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response line too long"));
    }
    Ok(n)
}

fn read_response(stream: impl Read) -> io::Result<Response> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    bounded_line(&mut reader, &mut line)?;
    let status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let mut length = None;
    let mut chunked = false;
    for count in 0.. {
        if count > MAX_HEADERS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many response headers"));
        }
        if bounded_line(&mut reader, &mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.parse::<usize>().ok(),
                "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
                _ => {}
            }
        }
    }
    let mut body = Vec::new();
    let mut truncated = false;
    if chunked {
        loop {
            bounded_line(&mut reader, &mut line)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                break;
            }
            // Never allocate what the server announces: copy through a bounded reader.
            let keep = size.min(MAX_RESPONSE_BYTES.saturating_sub(body.len()));
            let before = body.len();
            (&mut reader).take(keep as u64).read_to_end(&mut body)?;
            if body.len() - before < keep {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "upstream closed inside a chunk"));
            }
            if keep < size {
                truncated = true;
                break;
            }
            bounded_line(&mut reader, &mut line)?;
        }
    } else {
        let limit = length.unwrap_or(MAX_RESPONSE_BYTES + 1).min(MAX_RESPONSE_BYTES + 1);
        reader.take(limit as u64).read_to_end(&mut body)?;
        // A declared length the upstream did not deliver is an error, not a short body.
        if length.is_some_and(|n| n <= MAX_RESPONSE_BYTES && body.len() < n) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "upstream closed before the declared length"));
        }
        if body.len() > MAX_RESPONSE_BYTES {
            body.truncate(MAX_RESPONSE_BYTES);
            truncated = true;
        }
    }
    Ok(Response { status, body, truncated })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = Url::parse("https://api.github.com/repos/x?y=1").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (true, "api.github.com", 443, "/repos/x?y=1"));
        assert_eq!(Url::parse("http://127.0.0.1:8099").unwrap().origin(), "http://127.0.0.1:8099");
        for bad in ["ftp://x", "http://user@host/", "http://[::1]/", "http://ho st/", "http:///x", "http://a/b c"] {
            assert!(Url::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn internal_addresses_are_recognised() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.4", "169.254.169.254", "100.64.0.1", "0.1.2.3", "224.0.0.1", "240.0.0.1",
            "::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1", "64:ff9b::a00:1", "::ffff:10.0.0.1", "::10.0.0.1"] {
            assert!(internal(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(!internal(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn oversized_chunks_are_not_allocated() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffff\r\nabc";
        // A huge announced chunk is never allocated; ending early is an error, not a body.
        assert_eq!(read_response(&response[..]).err().map(|e| e.kind()), Some(io::ErrorKind::UnexpectedEof));
        let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(10_000));
        assert!(read_response(long.as_bytes()).is_err());
    }

    #[test]
    fn origin_normalises_case_and_port() {
        assert_eq!(Url::parse("HTTP://Example.COM/x").map(|u| u.origin()), None);
        assert_eq!(Url::parse("http://Example.COM/x").unwrap().origin(), "http://example.com:80");
    }

    #[test]
    fn short_bodies_are_errors() {
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly twenty bytes...".as_slice();
        assert_eq!(read_response(short).err().map(|e| e.kind()), Some(io::ErrorKind::UnexpectedEof));
        let chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nabc".as_slice();
        assert_eq!(read_response(chunk).err().map(|e| e.kind()), Some(io::ErrorKind::UnexpectedEof));
        let whole = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".as_slice();
        assert_eq!(read_response(whole).map(|r| r.body).ok(), Some(b"abc".to_vec()));
    }
}

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
const TIMEOUT: Duration = Duration::from_secs(60);

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
    let address = (url.host.as_str(), url.port).to_socket_addrs()?.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host did not resolve"))?;
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
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        read_response(stream)
    } else {
        let mut stream = tcp;
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        read_response(stream)
    }
}

fn read_response(stream: impl Read) -> io::Result<Response> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let mut length = None;
    let mut chunked = false;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
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
            line.clear();
            reader.read_line(&mut line)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let take = size.min(MAX_RESPONSE_BYTES.saturating_sub(body.len()));
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk[..take]);
            truncated |= take < size;
            line.clear();
            reader.read_line(&mut line)?;
        }
    } else {
        let limit = length.unwrap_or(MAX_RESPONSE_BYTES + 1).min(MAX_RESPONSE_BYTES + 1);
        reader.take(limit as u64).read_to_end(&mut body)?;
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
    fn origin_normalises_case_and_port() {
        assert_eq!(Url::parse("HTTP://Example.COM/x").map(|u| u.origin()), None);
        assert_eq!(Url::parse("http://Example.COM/x").unwrap().origin(), "http://example.com:80");
    }
}

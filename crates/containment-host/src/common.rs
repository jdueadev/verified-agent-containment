use containment_kernel::{Action, Level, Mode};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const LEASE_TTL_MS: u64 = 200;
pub const MAX_LEASE_MS: u64 = 250;
pub const HEARTBEAT_MS: u64 = 50;
pub const TICK_MS: u64 = 5;
pub const FREEZE_GRACE_MS: u64 = 400;
pub const SANDBOX_UID_BASE: u32 = 200_000;
pub const MAX_LINE_BYTES: u64 = 64 * 1024;
/// System One liveness (spec section 5). Lag is the age of the oldest trace
/// event the classifier has not consumed. Lab runs shorten the blind window;
/// live runs use 60 s (spec section 5.5).
pub const LAG_RESTRICT_MS: u64 = 500;
pub const LAB_BLIND_HOLD_MS: u64 = 1_500;
/// Events that must go unscored while restricted before a blind window holds.
pub const BLIND_MIN_EVENTS: u64 = 5;
/// System One down longer than this while the agent acts holds (live: 30 s).
pub const LAB_DOWN_HOLD_MS: u64 = 1_000;
/// System One runs as uid_base + this offset; generations use lower offsets.
pub const SYSTEM_ONE_UID_OFFSET: u32 = 15;

/// Time source for leases. CLOCK_BOOTTIME keeps counting during suspend, so a
/// suspended host cannot extend a lease.
pub fn boot_ns() -> u64 {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `value` is a valid out pointer for the duration of the call.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) };
    assert_eq!(result, 0, "CLOCK_BOOTTIME is unavailable");
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

/// MAC over one upstream record. The key never enters the sandbox.
pub fn record_mac(key: &[u8], admit_ns: u64, write_ns: u64, host: &str, data: &str, credential: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in [admit_ns.to_string().as_str(), write_ns.to_string().as_str(), host, data, credential] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Run => "run",
        Mode::Restrict => "restrict",
        Mode::Hold => "hold",
        Mode::Freeze => "freeze",
        Mode::Kill => "kill",
    }
}

pub fn action_name(action: Action) -> &'static str {
    match action {
        Action::RevokeSecrets => "revoke_secrets",
        Action::NarrowEgress => "narrow_egress",
        Action::BlockEgress => "block_egress",
        Action::FreezeProcesses => "freeze_processes",
        Action::KillProcesses => "kill_processes",
        Action::ThawProcesses => "thaw_processes",
        Action::RecreateSandbox => "recreate_sandbox",
        Action::RestoreAuthority => "restore_authority",
    }
}

pub fn parse_mode(value: &str) -> Option<Mode> {
    match value {
        "run" => Some(Mode::Run),
        "restrict" => Some(Mode::Restrict),
        "hold" => Some(Mode::Hold),
        "freeze" => Some(Mode::Freeze),
        "kill" => Some(Mode::Kill),
        _ => None,
    }
}

pub fn reset_message(run_id: &str, counter: u64, from_mode: &str, not_after_ms: u64, ttl_ms: u64) -> String {
    format!("reset-v2|{run_id}|{counter}|{from_mode}|{not_after_ms}|{ttl_ms}")
}

pub fn parse_level(value: &str) -> Option<Level> {
    match value {
        "restrict" => Some(Level::Restrict),
        "hold" => Some(Level::Hold),
        "freeze" => Some(Level::Freeze),
        "kill" => Some(Level::Kill),
        _ => None,
    }
}

pub fn request(socket: &Path, message: &Value) -> io::Result<Value> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    writeln!(stream, "{message}")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(&line).map_err(io::Error::other)
}

pub fn cgroup_root() -> io::Result<PathBuf> {
    for path in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        let root = PathBuf::from(path);
        if root.join("cgroup.procs").exists() && root.join("cgroup.controllers").exists() {
            return Ok(root);
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "cgroup v2 is required"))
}

pub fn status_error(message: impl Into<String>) -> Value {
    json!({"ok": false, "error": message.into()})
}

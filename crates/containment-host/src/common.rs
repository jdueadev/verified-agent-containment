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
pub const SANDBOX_UID: u32 = 65_534;

pub fn mono_ns() -> u64 {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `value` is a valid out pointer for the duration of the call.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
    assert_eq!(result, 0, "CLOCK_MONOTONIC is unavailable");
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

pub fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Run => "run",
        Mode::Restrict => "restrict",
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

pub fn parse_level(value: &str) -> Option<Level> {
    match value {
        "restrict" => Some(Level::Restrict),
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

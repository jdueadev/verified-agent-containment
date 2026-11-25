//! Actuators: cgroup generations, upstream connections and their limits.

use super::*;

pub(super) const LIMITS: [(&str, &str); 3] = [("pids.max", "512"), ("memory.max", "1073741824"), ("cpu.max", "50000 100000")];

/// One sandbox generation. Control files stay open so enforcement does not need
/// a new file descriptor while the host is under pressure.
pub(super) struct Generation {
    pub(super) number: u64,
    pub(super) path: PathBuf,
    pub(super) freeze: File,
    pub(super) kill: File,
    pub(super) events: File,
}

impl Generation {
    pub(super) fn create(parent: &Path, number: u64) -> std::io::Result<Self> {
        let path = parent.join(format!("g{number}"));
        fs::create_dir(&path)?;
        for (file, value) in LIMITS {
            let _ = fs::write(path.join(file), value);
        }
        let write = |name| fs::OpenOptions::new().write(true).open(path.join(name));
        Ok(Self { number, freeze: write("cgroup.freeze")?, kill: write("cgroup.kill")?, events: File::open(path.join("cgroup.events"))?, path })
    }

    /// Limits actually in force, read back from the cgroup.
    pub(super) fn limits(&self) -> Value {
        let read = |file: &str| fs::read_to_string(self.path.join(file)).ok().map(|v| v.trim().to_owned());
        json!(LIMITS.iter().map(|(file, value)| json!({"file": file, "wanted": value, "actual": read(file)})).collect::<Vec<_>>())
    }

    pub(super) fn events(&self) -> String {
        let mut buffer = [0_u8; 256];
        let count = self.events.read_at(&mut buffer, 0).unwrap_or(0);
        String::from_utf8_lossy(&buffer[..count]).into_owned()
    }
    pub(super) fn empty(&self) -> bool { self.events().contains("populated 0") }
    pub(super) fn frozen(&self) -> bool { self.events().contains("frozen 1") }
}

/// Aborts a TCP connection: connect(AF_UNSPEC) makes Linux reset it and drop
/// any bytes still queued for sending, so nothing handed to the kernel before
/// the cut leaves after it. Then shuts both directions for the other holders.
/// Returns false if the reset could not be made (some kernels refuse while a
/// thread is blocked on the socket); the shutdown still runs.
pub(super) fn abort_stream(stream: &TcpStream) -> bool {
    let unspec = libc::sockaddr { sa_family: libc::AF_UNSPEC as libc::sa_family_t, sa_data: [0; 14] };
    // SAFETY: `unspec` is a valid sockaddr for the duration of the call.
    let reset = unsafe { libc::connect(stream.as_raw_fd(), &unspec, std::mem::size_of::<libc::sockaddr>() as libc::socklen_t) } == 0;
    let _ = stream.shutdown(Shutdown::Both);
    reset
}

#[derive(Clone, Copy, Default)]
pub(super) struct Enforced {
    pub(super) frozen: bool,
    /// Generation the kernel ordered killed. A later generation is never touched.
    pub(super) killed: Option<u64>,
}

pub(super) fn enable_limits(parent: &Path) -> Vec<&'static str> {
    let Some(root) = parent.parent() else { return Vec::new() };
    let mut enabled = Vec::new();
    for (controller, file) in [("pids", "pids.max"), ("memory", "memory.max"), ("cpu", "cpu.max")] {
        let flag = format!("+{controller}");
        let _ = fs::write(root.join("cgroup.subtree_control"), &flag);
        if fs::write(parent.join("cgroup.subtree_control"), &flag).is_ok() {
            enabled.push(file);
        }
    }
    enabled
}

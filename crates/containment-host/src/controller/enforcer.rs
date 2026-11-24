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
    /// Why each LIMITS write failed, in LIMITS order; None where it succeeded.
    pub(super) limit_errors: Vec<Option<String>>,
}

/// What `cgroup.events` says. A field is None when its line is missing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CgroupState {
    pub(super) populated: Option<bool>,
    pub(super) frozen: Option<bool>,
}

impl CgroupState {
    fn parse(text: &str) -> Self {
        let mut state = Self::default();
        for line in text.lines() {
            let flag = |value: &str| match value { "0" => Some(false), "1" => Some(true), _ => None };
            match line.split_once(' ') {
                Some(("populated", value)) => state.populated = flag(value),
                Some(("frozen", value)) => state.frozen = flag(value),
                _ => {}
            }
        }
        state
    }
}

/// Removes a generation directory that was created but not finished.
struct Unfinished(Option<PathBuf>);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            if let Err(error) = fs::remove_dir(&path) {
                eprintln!("generation {}: cleanup after a failed create failed: {error}", path.display());
            }
        }
    }
}

impl Generation {
    pub(super) fn create(parent: &Path, number: u64) -> std::io::Result<Self> {
        let path = parent.join(format!("g{number}"));
        fs::create_dir(&path)?;
        // A create that fails below leaves nothing behind, so a retry can use this number.
        let mut unfinished = Unfinished(Some(path.clone()));
        // Control files are opened, never created: a cgroup has them already.
        let write = |name| fs::OpenOptions::new().write(true).open(path.join(name));
        let limit_errors = LIMITS.iter()
            .map(|(file, value)| write(*file).and_then(|mut f| f.write_all(value.as_bytes())).err().map(|e| {
                eprintln!("generation {number}: {file} = {value} was not applied: {e}");
                e.to_string()
            }))
            .collect();
        let generation = Self { number, freeze: write("cgroup.freeze")?, kill: write("cgroup.kill")?, events: File::open(path.join("cgroup.events"))?, path, limit_errors };
        unfinished.0 = None;
        Ok(generation)
    }

    /// Limits actually in force, read back from the cgroup, with any write error.
    pub(super) fn limits(&self) -> Value {
        let read = |file: &str| fs::read_to_string(self.path.join(file)).ok().map(|v| v.trim().to_owned());
        json!(LIMITS.iter().enumerate().map(|(i, (file, value))| json!({"file": file, "wanted": value, "actual": read(file),
            "write_error": self.limit_errors.get(i).cloned().flatten()})).collect::<Vec<_>>())
    }

    /// Reads `cgroup.events`. An error means nothing about the cgroup is known.
    pub(super) fn state(&self) -> std::io::Result<CgroupState> {
        let mut buffer = [0_u8; 256];
        let count = self.events.read_at(&mut buffer, 0)?;
        Ok(CgroupState::parse(&String::from_utf8_lossy(&buffer[..count])))
    }

    // Each predicate holds only on positive evidence; a read error or a missing
    // line confirms nothing, so an unconfirmed actuator ends in fail-stop (INV-7).
    pub(super) fn empty(&self) -> bool { self.state().is_ok_and(|s| s.populated == Some(false)) }
    pub(super) fn frozen(&self) -> bool { self.state().is_ok_and(|s| s.frozen == Some(true)) }
    pub(super) fn thawed(&self) -> bool { self.state().is_ok_and(|s| s.frozen == Some(false)) }
}

#[derive(Default)]
pub(super) struct Upstreams {
    pub(super) next: u64,
    pub(super) active: BTreeMap<u64, Option<TcpStream>>,
    /// Admitted as baseline egress. Restrict keeps these; a stop cuts everything.
    pub(super) baseline: BTreeSet<u64>,
    pub(super) cuts: u64,
    /// Connections that could only be shut down, not reset (queued bytes may still go).
    pub(super) abort_failures: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vac-enforcer-{name}-{}-{}", std::process::id(), boot_ns()));
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// E2: a create that fails part way leaves no generation directory behind,
    /// so a retry can create the same number again.
    #[test]
    fn a_failed_create_removes_its_generation_directory() {
        let parent = scratch("create");
        // A plain directory has no cgroup.freeze, so the create fails after mkdir.
        assert!(Generation::create(&parent, 3).is_err());
        let left = parent.join("g3").exists();
        let _ = fs::remove_dir_all(&parent);
        assert!(!left, "g3 was left behind");
    }

    /// E1: an events file that cannot be read confirms nothing.
    #[test]
    fn an_unreadable_events_file_confirms_nothing() {
        let parent = scratch("events");
        let file = |name: &str| {
            let path = parent.join(name);
            fs::write(&path, "").expect("control file");
            fs::OpenOptions::new().write(true).open(path).expect("open")
        };
        // Reading a directory fails with EISDIR.
        let generation = Generation { number: 1, path: parent.clone(), freeze: file("freeze"), kill: file("kill"), events: File::open(&parent).expect("dir"), limit_errors: Vec::new() };
        let (empty, frozen, thawed) = (generation.empty(), generation.frozen(), generation.thawed());
        let state = generation.state();
        let _ = fs::remove_dir_all(&parent);
        assert!(!empty && !frozen && !thawed, "empty {empty}, frozen {frozen}, thawed {thawed}");
        assert!(state.is_err(), "{state:?}");
    }

    /// E1: only an explicit line confirms; a missing or garbled one does not.
    #[test]
    fn events_are_parsed_line_by_line() {
        assert_eq!(CgroupState::parse("populated 1\nfrozen 0\n"), CgroupState { populated: Some(true), frozen: Some(false) });
        assert_eq!(CgroupState::parse("populated 0\nfrozen 1\n"), CgroupState { populated: Some(false), frozen: Some(true) });
        assert_eq!(CgroupState::parse(""), CgroupState::default());
        assert_eq!(CgroupState::parse("populated 0"), CgroupState { populated: Some(false), frozen: None });
        assert_eq!(CgroupState::parse("frozen 10\npopulated x\n"), CgroupState::default());
    }
}

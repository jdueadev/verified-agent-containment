//! Actuators: cgroup generations, upstream connections and their limits.

use super::*;

const CPU_CAP: (&str, &str) = ("cpu.max", "50000 100000");
pub(super) const LIMITS: [(&str, &str); 3] = [("pids.max", "512"), ("memory.max", "1073741824"), CPU_CAP];

/// One sandbox generation. Control files stay open so enforcement does not need
/// a new file descriptor while the host is under pressure.
pub(super) struct Generation {
    pub(super) number: u64,
    pub(super) path: PathBuf,
    pub(super) freeze: File,
    pub(super) kill: File,
    pub(super) events: File,
    /// `cpu.max`, when the cpu controller is on. See `lift_cpu_cap`.
    pub(super) cpu: Option<File>,
}

impl Generation {
    pub(super) fn create(parent: &Path, number: u64) -> std::io::Result<Self> {
        let path = parent.join(format!("g{number}"));
        fs::create_dir(&path)?;
        // A create that fails below leaves no directory behind, so a retry can
        // use this number again.
        let mut unfinished = Unfinished(Some(path.clone()));
        // Control files are opened, never created: the kernel makes them with
        // the cgroup. A limit that cannot be written is said so; `limits()`
        // reads back what is really in force.
        let write = |name| fs::OpenOptions::new().write(true).open(path.join(name));
        for (file, value) in LIMITS {
            if let Err(error) = write(file).and_then(|mut f| f.write_all(value.as_bytes())) {
                eprintln!("generation {number}: {file} = {value} was not applied: {error}");
            }
        }
        let generation = Self { number, freeze: write("cgroup.freeze")?, kill: write("cgroup.kill")?, events: File::open(path.join("cgroup.events"))?, cpu: write(CPU_CAP.0).ok(), path };
        unfinished.0 = None;
        Ok(generation)
    }

    /// Limits actually in force, read back from the cgroup.
    pub(super) fn limits(&self) -> Value {
        let read = |file: &str| fs::read_to_string(self.path.join(file)).ok().map(|v| v.trim().to_owned());
        json!(LIMITS.iter().map(|(file, value)| json!({"file": file, "wanted": value, "actual": read(file)})).collect::<Vec<_>>())
    }

    /// Reads `cgroup.events`. An error means nothing about the cgroup is known.
    pub(super) fn state(&self) -> std::io::Result<CgroupState> {
        let mut buffer = [0_u8; 256];
        let count = self.events.read_at(&mut buffer, 0)?;
        Ok(CgroupState::parse(&String::from_utf8_lossy(&buffer[..count])))
    }

    /// Lifts the CPU quota so a freeze can land. A task throttled by `cpu.max`
    /// does not run until its quota refills (up to a whole 100 ms period, longer
    /// with many busy threads), and the freezer needs it to run to stop it. Egress
    /// is already cut when this runs; the cap is put back by `restore_cpu_cap`
    /// as soon as the freeze is read back or the attempt gives up. Returns
    /// whether there is a cap to put back.
    pub(super) fn lift_cpu_cap(&self) -> bool {
        self.cpu.as_ref().is_some_and(|file| file.write_all_at(b"max", 0).is_ok())
    }

    pub(super) fn restore_cpu_cap(&self) {
        let (name, value) = CPU_CAP;
        let restored = self.cpu.as_ref().is_some_and(|file| file.write_all_at(value.as_bytes(), 0).is_ok());
        if !restored {
            eprintln!("generation {}: {name} = {value} was not restored after a freeze", self.number);
        }
    }

    // Each holds only on positive evidence. A read error or a missing line
    // confirms nothing, so an actuator that cannot be read back is retried
    // and then fail-stops; it is never taken as done.
    pub(super) fn empty(&self) -> bool { self.state().is_ok_and(|s| s.populated == Some(false)) }
    pub(super) fn frozen(&self) -> bool { self.state().is_ok_and(|s| s.frozen == Some(true)) }
    pub(super) fn thawed(&self) -> bool { self.state().is_ok_and(|s| s.frozen == Some(false)) }
}

/// What `cgroup.events` says. A field is `None` when its line is missing or
/// does not read `0` or `1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CgroupState {
    pub(super) populated: Option<bool>,
    pub(super) frozen: Option<bool>,
}

impl CgroupState {
    fn parse(text: &str) -> Self {
        let flag = |value: &str| match value { "0" => Some(false), "1" => Some(true), _ => None };
        let mut state = Self::default();
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("populated", value)) => state.populated = flag(value),
                Some(("frozen", value)) => state.frozen = flag(value),
                _ => {}
            }
        }
        state
    }
}

/// Removes a generation directory whose create did not finish.
struct Unfinished(Option<PathBuf>);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            if let Err(error) = fs::remove_dir(&path) {
                eprintln!("{}: not removed after a failed create: {error}", path.display());
            }
        }
    }
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

/// The action record an idle reconcile pass owes (#38, H1). A Freeze or Kill
/// whose own wait timed out is logged `ok:false` and not re-queued; the idle
/// `drive` may confirm it later. While such a failure is `outstanding` and
/// `held` reports the confirmation, this names the action to record as
/// `ok:true, via:"reconcile"` and clears the debt, so the evidence shows the
/// confirmation and its real, later time. Nothing outstanding, nothing owed.
pub(super) fn reconcile_record(outstanding: &mut bool, enforced: Enforced, held: bool) -> Option<&'static str> {
    if !*outstanding || !held {
        return None;
    }
    *outstanding = false;
    if enforced.killed.is_some() {
        Some("kill_processes")
    } else if enforced.frozen {
        Some("freeze_processes")
    } else {
        // Thawed since: nothing left to confirm.
        None
    }
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

    /// A create that fails after its mkdir leaves no directory behind, so the
    /// next recreate can use the same number.
    #[test]
    fn a_failed_create_removes_its_generation_directory() {
        let parent = scratch("create");
        // A plain directory has no cgroup.freeze, so the create fails after mkdir.
        let created = Generation::create(&parent, 3);
        let left = parent.join("g3").exists();
        let _ = fs::remove_dir_all(&parent);
        assert!(created.is_err(), "a plain directory is not a cgroup");
        assert!(!left, "g3 was left behind");
    }

    /// An events file that cannot be read confirms nothing: not empty, not
    /// frozen and not thawed.
    #[test]
    fn an_unreadable_events_file_confirms_nothing() {
        let parent = scratch("events");
        let control = |name: &str| {
            let path = parent.join(name);
            fs::write(&path, "").expect("control file");
            fs::OpenOptions::new().write(true).open(path).expect("open")
        };
        // Reading a directory fails with EISDIR.
        let events = File::open(&parent).expect("directory");
        let generation = Generation { number: 1, path: parent.clone(), freeze: control("freeze"), kill: control("kill"), events, cpu: None };
        let seen = (generation.empty(), generation.frozen(), generation.thawed(), generation.state().is_err());
        let _ = fs::remove_dir_all(&parent);
        assert_eq!(seen, (false, false, false, true), "(empty, frozen, thawed, read failed)");
    }

    /// A reconcile pass records only a confirmation that is owed, once.
    #[test]
    fn reconcile_records_only_an_outstanding_confirmation() {
        let frozen = Enforced { frozen: true, killed: None };
        let killed = Enforced { frozen: true, killed: Some(2) };
        let mut owed = false;
        assert_eq!(reconcile_record(&mut owed, frozen, true), None, "nothing failed");
        owed = true;
        assert_eq!(reconcile_record(&mut owed, frozen, false), None, "not confirmed yet");
        assert!(owed, "an unconfirmed pass keeps the debt");
        assert_eq!(reconcile_record(&mut owed, frozen, true), Some("freeze_processes"));
        assert_eq!(reconcile_record(&mut owed, frozen, true), None, "recorded once");
        owed = true;
        assert_eq!(reconcile_record(&mut owed, killed, true), Some("kill_processes"));
        owed = true;
        assert_eq!(reconcile_record(&mut owed, Enforced::default(), true), None, "thawed since");
        assert!(!owed);
    }

    /// Only an explicit `0` or `1` line confirms; a missing or garbled one does not.
    #[test]
    fn events_are_parsed_line_by_line() {
        let state = |populated, frozen| CgroupState { populated, frozen };
        assert_eq!(CgroupState::parse("populated 1
frozen 0
"), state(Some(true), Some(false)));
        assert_eq!(CgroupState::parse("populated 0
frozen 1
"), state(Some(false), Some(true)));
        assert_eq!(CgroupState::parse(""), CgroupState::default());
        assert_eq!(CgroupState::parse("populated 0"), state(Some(false), None));
        assert_eq!(CgroupState::parse("frozen 10
populated x
not populated 0
"), CgroupState::default());
    }
}

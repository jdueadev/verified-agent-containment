//! System One supervision, verdict intake and lag accounting.

use super::*;

/// Classifier lag state. Lag reaches the kernel only as Event::Classifier, so
/// the proved cap (Hold at most, never Freeze or Kill) covers liveness too.
#[derive(Default)]
pub(super) struct Lag {
    /// Sequence number of the next trace event.
    pub(super) next_seq: u64,
    /// (sequence, enqueue time) of queued events not yet consumed, oldest first.
    /// The classifier reports the sequence it consumed through, so a slow
    /// gateway thread cannot make enqueues and consumes drift apart.
    pub(super) pending: VecDeque<(u64, u64)>,
    /// Which System One process the pipe belongs to. Records written to a pipe
    /// whose reader died are counted as lost, never as consumed.
    pub(super) epoch: u64,
    /// Highest sequence written into the current pipe; a reported
    /// `consumed_through_seq` is clamped to it.
    pub(super) last_written: Option<u64>,
    /// The current lag episode. Cleared when lag clears or the agent is back in
    /// Run after a reset, so the next stall is reported again.
    pub(super) restricted_since: Option<u64>,
    /// Events dropped (never written) since the episode began. Together with the
    /// still-pending events written since then, this is what is unscored.
    pub(super) unscored_since_restrict: u64,
    /// First sequence number of the episode: pending entries from before it
    /// are backlog, not events the classifier missed during the window.
    pub(super) episode_first_seq: u64,
    pub(super) held: bool,
    pub(super) overflow_signalled: bool,
}

impl Lag {
    pub(super) fn clear_episode(&mut self) {
        self.restricted_since = None;
        self.unscored_since_restrict = 0;
        self.held = false;
        self.overflow_signalled = false;
    }
}

pub(super) fn apply_classifier(shared: &Shared, label: Option<&'static str>, received: u64, level: Level) {
    let uncapped = shared.weak.classifier_uncapped;
    shared.emit("classifier", json!({"label": label.unwrap_or("classifier"), "level": format!("{level:?}").to_lowercase()}));
    shared.bounded_push(&shared.classifier_signals, json!({"ns": received, "label": label.unwrap_or("classifier"), "level": format!("{level:?}").to_lowercase()}));
    shared.apply(label, received, |now_ms| if uncapped { Event::HardRule { now_ms, level } } else { Event::Classifier { now_ms, level } });
}

pub(super) struct SystemOneSpec {
    pub(super) exe: PathBuf,
    pub(super) profile: &'static str,
    pub(super) scenario: String,
    pub(super) private_file: PathBuf,
    pub(super) uid: u32,
    pub(super) confined: bool,
    pub(super) weak_filter: bool,
    pub(super) pipe_bytes: i32,
    /// cgroup with pids, memory and CPU limits for System One alone.
    pub(super) cgroup: PathBuf,
}

/// Starts System One with the trace pipe on fd 3 and the verdict socket on fd 4,
/// and no other descriptors. Confined: its own cgroup and rlimits, an empty
/// network namespace, its own uid, no new privileges, a seccomp filter without
/// sockets, signals or namespaces, and the parent-death signal armed after the
/// uid change (a uid change clears it).
pub(super) fn spawn_system_one(spec: &SystemOneSpec, restarted: bool) -> std::io::Result<(Child, OwnedFd, UnixDatagram)> {
    let mut pipe = [0; 2];
    let mut pair = [0; 2];
    // SAFETY: both arrays are valid two-element outputs.
    unsafe {
        if libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0
            || libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    // SAFETY: the calls above returned these descriptors and nothing else owns them.
    let (trace_read, trace_write, mine, theirs) = unsafe {
        (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1]), OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1]))
    };
    // SAFETY: fcntl on descriptors this function owns.
    unsafe {
        libc::fcntl(trace_write.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(trace_write.as_raw_fd(), libc::F_SETPIPE_SZ, spec.pipe_bytes);
    }
    let procs = fs::OpenOptions::new().write(true).open(spec.cgroup.join("cgroup.procs"))?;
    let target = if !spec.confined || spec.weak_filter { sandbox::FilterFor::SystemOneWeak } else { sandbox::FilterFor::SystemOne };
    let mut filter = sandbox::build_filter(target);
    let (read_fd, out_fd, procs_fd, uid, confined) = (trace_read.as_raw_fd(), theirs.as_raw_fd(), procs.as_raw_fd(), spec.uid, spec.confined);
    // SAFETY: getpid has no preconditions.
    let controller = unsafe { libc::getpid() };
    let mut command = Command::new(&spec.exe);
    command
        .arg("system-one").arg(spec.profile).arg(&spec.scenario).arg(&spec.private_file)
        .env_clear().current_dir("/").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    if restarted {
        command.env("SYSTEM_ONE_RESTARTED", "1");
    }
    // SAFETY: the closure only makes async-signal-safe calls; the filter was built before fork.
    unsafe {
        command.pre_exec(move || {
            let check = |r: libc::c_int| if r == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) };
            let pid = b"0\n";
            if libc::write(procs_fd, pid.as_ptr().cast(), pid.len()) != pid.len() as isize {
                return Err(std::io::Error::last_os_error());
            }
            // Move both ends above fd 4 first so dup2 cannot clobber one with the other,
            // then place them and close everything else.
            let high_read = libc::fcntl(read_fd, libc::F_DUPFD, 10);
            let high_out = libc::fcntl(out_fd, libc::F_DUPFD, 10);
            check(high_read)?;
            check(high_out)?;
            check(libc::dup2(high_read, crate::system_one::TRACE_FD))?;
            check(libc::dup2(high_out, crate::system_one::VERDICT_FD))?;
            check(libc::syscall(libc::SYS_close_range, 5_u32, u32::MAX, 0_u32) as libc::c_int)?;
            let limit = |resource, value| check(libc::setrlimit(resource, &libc::rlimit { rlim_cur: value, rlim_max: value }));
            limit(libc::RLIMIT_NPROC, 64)?;
            limit(libc::RLIMIT_NOFILE, 64)?;
            limit(libc::RLIMIT_CORE, 0)?;
            limit(libc::RLIMIT_FSIZE, 0)?;
            limit(libc::RLIMIT_AS, 4 << 30)?;
            if confined {
                check(libc::unshare(libc::CLONE_NEWNET))?;
                check(libc::setgroups(0, std::ptr::null()))?;
                check(libc::setresgid(uid, uid, uid))?;
                check(libc::setresuid(uid, uid, uid))?;
            }
            check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
            if libc::getppid() != controller {
                libc::_exit(70);
            }
            if confined {
                check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
                check(sandbox::install_filter(&mut filter))?;
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    drop((trace_read, theirs, procs));
    Ok((child, trace_write, UnixDatagram::from(mine)))
}

/// Turns System One's verdicts into kernel events. The channel picks the
/// constructor: every verdict is Event::Classifier, whatever fields it carries
/// (claim C-ARCH-01). Verdicts resting only on the excerpt are capped at
/// Restrict (C-S1-02). Unknown reason codes are ignored.
pub(super) fn read_verdicts(shared: &Shared, socket: &UnixDatagram, epoch: u64, started: u64) {
    let mut buffer = [0_u8; 4096];
    while let Ok(n) = socket.recv(&mut buffer) {
        if n == 0 {
            break;
        }
        let Ok(v) = serde_json::from_slice::<Value>(&buffer[..n]) else { continue };
        let now = boot_ns();
        shared.classifier_beat.store(now, Ordering::Relaxed);
        // A restarted process must stay up for a while before the outage ends,
        // so a crash loop that sends one message per cycle still counts as down.
        if now.saturating_sub(started) / 1_000_000 >= shared.stable_ms {
            *lock(&shared.s1_down_since) = None;
        }
        if let Some(through) = v["consumed_through_seq"].as_u64() {
            shared.trace_consumed(through, epoch);
        }
        if !v["probe"].is_null() {
            *lock(&shared.s1_probe) = v["probe"].clone();
        }
        let Some(mut level) = v["level"].as_str().and_then(parse_level) else { continue };
        let codes: Vec<&str> = v["codes"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter(|c| crate::system_one::CODES.contains(c)).collect();
        let excerpt_only = !codes.is_empty() && codes.iter().all(|c| crate::system_one::EXCERPT_CODES.contains(c));
        shared.emit("verdict", json!({"level": v["level"], "score": v["score"], "codes": codes, "model": v["model_id"]}));
        let mut label = "system_one";
        if excerpt_only && level != Level::Restrict && !shared.weak.excerpt_uncapped {
            level = Level::Restrict;
            label = "system_one_excerpt_capped";
        }
        if shared.weak.shared_control_socket && v["op"] == "hard" {
            // Sabotage: the message body picks the constructor.
            shared.apply(Some("system_one_hard"), now, |now_ms| Event::HardRule { now_ms, level });
        } else {
            apply_classifier(shared, Some(label), now, level);
        }
    }
}

/// Keeps System One running. While it is down, trace records are dropped
/// (which restricts) and the down timer runs (which holds a busy agent).
pub(super) fn supervise_system_one(shared: Arc<Shared>, spec: SystemOneSpec) {
    let mut restarted = false;
    while !shared.stop.load(Ordering::Relaxed) {
        match spawn_system_one(&spec, restarted) {
            Ok((mut child, trace_write, verdicts)) => {
                let started = boot_ns();
                shared.s1_pid.store(child.id(), Ordering::SeqCst);
                let epoch = {
                    let mut lag = lock(&shared.lag);
                    lag.epoch += 1;
                    lag.last_written = None;
                    *lock(&shared.trace_out) = Some(trace_write);
                    lag.epoch
                };
                let reader = {
                    let shared = Arc::clone(&shared);
                    let verdicts = verdicts.try_clone();
                    thread::spawn(move || if let Ok(v) = verdicts { read_verdicts(&shared, &v, epoch, started) })
                };
                let _ = child.wait();
                shared.s1_pid.store(0, Ordering::SeqCst);
                let _ = verdicts.shutdown(Shutdown::Both);
                let _ = reader.join();
            }
            Err(error) => eprintln!("system one did not start: {error}"),
        }
        // Records still in the dead process's pipe were never scored: count them
        // as lost, and restrict if there were any.
        let lost = {
            let mut lag = lock(&shared.lag);
            *lock(&shared.trace_out) = None;
            let lost = lag.pending.len() as u64;
            lag.pending.clear();
            lost
        };
        // During teardown System One is stopped on purpose; what it had not yet
        // scored is not a classifier failure and must not raise the mode.
        if lost > 0 && !shared.stop.load(Ordering::SeqCst) {
            shared.dropped_logs.fetch_add(lost, Ordering::Relaxed);
            apply_classifier(&shared, Some("classifier_lost_records"), boot_ns(), Level::Restrict);
        }
        {
            let mut down = lock(&shared.s1_down_since);
            if down.is_none() {
                *down = Some(boot_ns());
            }
            // Only activity after this point makes the agent count as busy.
            shared.s1_dropped_at_down.store(shared.dropped_logs.load(Ordering::Relaxed), Ordering::SeqCst);
        }
        shared.s1_restarts.fetch_add(1, Ordering::Relaxed);
        restarted = true;
        thread::sleep(Duration::from_millis(100));
    }
}

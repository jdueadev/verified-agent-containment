use serde_json::{json, Value};
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;

/// The built-in agent: this binary, bound at this path in the sandbox root.
pub const AGENT: &str = "/agent";
/// The gateway socket, as the program sees it.
const GATEWAY: &str = "/gateway.sock";
/// Top-level names the sandbox provides itself. A supplied root's entries with
/// these names are skipped, and no other program may live under them.
pub const RESERVED: &[&str] = &["proc", "tmp", "dev", "workspace", "gateway.sock", ".old", "agent"];
/// The devices in the sandbox's /dev, with their device numbers: the ones ordinary
/// programs open by name and that give nothing away. No tty, console or disk.
const DEVICES: &[(&str, u32, u32)] = &[("null", 1, 3), ("zero", 1, 5), ("full", 1, 7), ("random", 1, 8), ("urandom", 1, 9)];

/// What runs inside the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// Absolute path as seen inside the sandbox, then its arguments.
    pub argv: Vec<String>,
    /// A host directory whose top-level entries become the sandbox's read-only root.
    /// None: the root is planned from the program's own ELF, as for the built-in agent.
    pub root: Option<PathBuf>,
}

impl Program {
    /// The built-in agent playing `scenario`.
    pub fn agent(scenario: &str, probe: &Value) -> Self {
        Self { argv: vec![AGENT.to_owned(), "agent".to_owned(), scenario.to_owned(), probe.to_string()], root: None }
    }

    /// Any other program. Its path must be absolute and must not lead under one of
    /// the sandbox's own entries, which would hide it or stand in for it.
    pub fn outside(argv: Vec<String>, root: Option<PathBuf>) -> Result<Self, String> {
        let path = Path::new(argv.first().ok_or("no program was given")?);
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) || parts.clone().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(format!("the program path {} must be absolute, without . or ..", path.display()));
        }
        match parts.next().and_then(|c| c.as_os_str().to_str()) {
            None => return Err("the program path names no file".into()),
            Some(top) if RESERVED.contains(&top) => return Err(format!("the program path {} is under /{top}, which the sandbox provides itself", path.display())),
            Some(_) => {}
        }
        if argv.iter().any(|a| a.contains('\0')) {
            return Err("a program argument contains a NUL byte".into());
        }
        Ok(Self { argv, root })
    }
}

pub struct SandboxSpec {
    pub exe: PathBuf,
    pub program: Program,
    pub new_root: PathBuf,
    pub private_dir: PathBuf,
    pub gateway: PathBuf,
    pub output: PathBuf,
    pub share_network: bool,
    pub expose_private: bool,
    pub no_parent_death_signal: bool,
    pub host_root: bool,
    /// Sabotage: keep the pivot but bind the host's whole /usr and /lib* again (#88).
    pub wide_root: bool,
    /// Sabotage: bind a supplied root's entries without making them read-only.
    pub writable_root: bool,
    pub seccomp: bool,
    pub memfd_exec: bool,
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn c(path: &str) -> Result<CString, Box<dyn Error>> {
    Ok(CString::new(path)?)
}

/// One started sandbox.
pub struct Sandbox {
    /// The launcher, outside the sandbox's PID namespace.
    pub child: Child,
    /// Copies the program's output into `spec.output`. The caller joins it once the
    /// sandbox's processes are gone, so the last records the program wrote reach the file.
    pub copier: std::thread::JoinHandle<()>,
    /// What the sandbox's init says about the program.
    pub status: ProgramStatus,
}

/// How the program in a sandbox has fared, as the sandbox's init reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// Nothing yet: the sandbox is still starting.
    Nothing,
    /// The program never ran, and why.
    NotStarted(String),
    /// Its exec succeeded.
    Started,
    Exited(i32),
    Signalled(i32),
}

impl Reported {
    fn after(self, record: &Value) -> Self {
        match (record["started"].as_bool(), record["exit_code"].as_i64(), record["signal"].as_i64()) {
            (Some(false), _, _) => Self::NotStarted(record["reason"].as_str().unwrap_or("no reason was given").to_owned()),
            (Some(true), _, _) => Self::Started,
            (_, Some(code), _) => Self::Exited(code as i32),
            (_, _, Some(signal)) => Self::Signalled(signal as i32),
            _ => self,
        }
    }

    /// For the run's report.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Nothing => json!({"started": null}),
            Self::NotStarted(reason) => json!({"started": false, "reason": reason}),
            Self::Started => json!({"started": true}),
            Self::Exited(code) => json!({"started": true, "exit_code": code}),
            Self::Signalled(signal) => json!({"started": true, "signal": signal}),
        }
    }
}

/// The controller's end of the pipe on which the sandbox's init reports, one JSON
/// line per record: whether the program started, then how it ended.
pub struct ProgramStatus {
    pipe: io::PipeReader,
    unread: Vec<u8>,
    state: Reported,
}

impl ProgramStatus {
    /// Reads whatever init has written so far, without waiting.
    pub fn poll(&mut self) -> &Reported {
        let mut buffer = [0_u8; 4096];
        while let Ok(n @ 1..) = io::Read::read(&mut self.pipe, &mut buffer) {
            self.unread.extend_from_slice(&buffer[..n]);
        }
        while let Some(end) = self.unread.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.unread.drain(..=end).collect();
            if let Ok(record) = serde_json::from_slice::<Value>(&line) {
                self.state = std::mem::replace(&mut self.state, Reported::Nothing).after(&record);
            }
        }
        &self.state
    }

    /// Once the launcher has exited: all init said. A sandbox that ended without
    /// saying its program started did not start it, as far as anyone can tell.
    pub fn ended(&mut self) -> &Reported {
        if *self.poll() == Reported::Nothing {
            self.state = Reported::NotStarted("the sandbox ended before it reported that the program started".to_owned());
        }
        &self.state
    }
}

/// Starts one sandbox inside `cgroup`. This must run on the controller's main
/// thread because the parent-death signal follows the spawning thread.
pub fn spawn(spec: &SandboxSpec, cgroup: &Path, uid: u32, workspace: Option<&Path>) -> io::Result<Sandbox> {
    let procs = fs::OpenOptions::new().write(true).open(cgroup.join("cgroup.procs"))?;
    let output = fs::OpenOptions::new().create(true).append(true).open(&spec.output)?;
    // The agent writes to a pipe, not to the file: with a file descriptor on the file it
    // could ftruncate away what earlier generations wrote (#88). The controller copies the
    // pipe into the file, at most AGENT_OUTPUT_LIMIT bytes per generation.
    let (reader, writer) = io::pipe()?;
    // Init's reports. The write end is close-on-exec here, so no other child of this
    // process gets it; only the launcher keeps it across its exec.
    let (status_reader, status_writer) = io::pipe()?;
    // SAFETY: fcntl on a descriptor this function owns.
    check(unsafe { libc::fcntl(status_reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
    let status_fd = status_writer.as_raw_fd();
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWPID | libc::CLONE_NEWCGROUP;
    if !spec.share_network {
        flags |= libc::CLONE_NEWNET;
    }
    let fd = procs.as_raw_fd();
    let death_signal = !spec.no_parent_death_signal;
    // SAFETY: getpid has no preconditions.
    let controller = unsafe { libc::getpid() };
    let config = json!({
        "exe": spec.exe, "new_root": spec.new_root, "private_dir": spec.private_dir, "gateway": spec.gateway,
        "argv": spec.program.argv, "root": spec.program.root, "uid": uid, "expose_private": spec.expose_private,
        "death_signal": death_signal, "host_root": spec.host_root, "wide_root": spec.wide_root, "writable_root": spec.writable_root,
        "seccomp": spec.seccomp, "memfd_exec": spec.memfd_exec,
        "workspace": workspace, "status_fd": status_fd,
    });
    let mut command = Command::new(&spec.exe);
    command
        .arg("sandbox-launch")
        .arg(config.to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer.try_clone()?))
        .stderr(Stdio::from(writer));
    // SAFETY: the closure only calls async-signal-safe libc functions before exec.
    unsafe {
        command.pre_exec(move || {
            let pid = b"0\n";
            if libc::write(fd, pid.as_ptr().cast(), pid.len()) != pid.len() as isize {
                return Err(io::Error::last_os_error());
            }
            check(libc::setsid())?;
            if death_signal {
                check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
                if libc::getppid() != controller {
                    libc::_exit(70);
                }
            }
            check(libc::fcntl(status_fd, libc::F_SETFD, 0))?;
            check(libc::unshare(flags))
        });
    }
    let child = command.spawn()?;
    // Closes the parent's copies of the write ends, so each pipe ends when the sandbox's copies do.
    drop(command);
    drop(status_writer);
    let status = ProgramStatus { pipe: status_reader, unread: Vec::new(), state: Reported::Nothing };
    Ok(Sandbox { child, copier: copy_agent_output(reader, output), status })
}

/// The most one generation may add to its output file. The rest is read and dropped,
/// so a flooding agent can neither fill the disk nor stall on a full pipe.
const AGENT_OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

fn copy_agent_output(mut reader: io::PipeReader, mut output: fs::File) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::Read::take(&mut reader, AGENT_OUTPUT_LIMIT), &mut output);
        let _ = io::copy(&mut reader, &mut io::sink());
    })
}

fn mount(source: &str, target: &str, kind: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<(), Box<dyn Error>> {
    let source_c = c(source)?;
    let target_c = c(target)?;
    let kind = kind.map(c).transpose()?;
    let data = data.map(c).transpose()?;
    // SAFETY: all pointers refer to live NUL-terminated strings or are null.
    let result = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            kind.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
            flags,
            data.as_ref().map_or(ptr::null(), |v| v.as_ptr().cast()),
        )
    };
    check(result).map_err(|e| format!("mount {source} on {target}: {e}"))?;
    Ok(())
}

fn bind(source: &str, target: &str, extra: libc::c_ulong) -> Result<(), Box<dyn Error>> {
    mount(source, target, None, libc::MS_BIND, None)?;
    mount("none", target, None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV | extra, None)
}

/// Puts each top-level entry of a supplied directory into the new root, read-only.
/// Directories and files are bound, but not recursively, so mounts below `dir` stay
/// behind; symlinks are recreated. Not noexec: the program and its libraries run
/// from here. The sandbox's own entries win over same-named ones.
fn supply_root(dir: &str, root: &str, writable: bool) -> Result<(), Box<dyn Error>> {
    let flags = if writable { 0 } else { libc::MS_RDONLY };
    for entry in fs::read_dir(dir).map_err(|e| format!("root {dir}: {e}"))? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|n| format!("root {dir}: {n:?} is not UTF-8"))?;
        if RESERVED.contains(&name.as_str()) {
            continue;
        }
        // The type is read from the same descriptor that is bound, so an entry that
        // changes between the two cannot turn a recreated symlink into a followed one.
        let opened = fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(entry.path())
            .map_err(|e| format!("root {dir}/{name}: {e}"))?;
        let kind = opened.metadata()?.file_type();
        let source = format!("/proc/self/fd/{}", opened.as_raw_fd());
        let target = format!("{root}/{name}");
        if kind.is_symlink() {
            symlink(fs::read_link(entry.path())?, &target)?;
        } else if kind.is_dir() {
            fs::create_dir(&target)?;
            bind(&source, &target, flags).map_err(|e| format!("root {dir}/{name}: {e}"))?;
        } else if kind.is_file() {
            fs::write(&target, "")?;
            bind(&source, &target, flags).map_err(|e| format!("root {dir}/{name}: {e}"))?;
        } else {
            return Err(format!("root {dir}/{name}: not a file, directory or symlink").into());
        }
    }
    Ok(())
}

/// Mounts the sandbox's /dev on `dev`: a read-only tmpfs holding the five DEVICES and
/// `shm`. Each device is the host's own node, bound onto an empty file, as container
/// runtimes do without CAP_MKNOD. That keeps every filesystem in the sandbox nodev,
/// the root and this tmpfs included: only these five bind mounts allow opening a
/// device, and each holds one node, checked by its number, so a host /dev entry that
/// is not what its name says is refused rather than passed through. Creating nodes
/// instead would need a tmpfs without nodev, where any node that appeared would open.
fn provide_dev(dev: &str) -> Result<(), Box<dyn Error>> {
    let sealed = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount("tmpfs", dev, Some("tmpfs"), sealed, Some("mode=755,size=64k"))?;
    for &(name, major, minor) in DEVICES {
        let host = format!("/dev/{name}");
        let opened = fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(&host)
            .map_err(|e| format!("{host}: {e}"))?;
        let meta = opened.metadata()?;
        if !meta.file_type().is_char_device() || meta.rdev() != libc::makedev(major, minor) {
            return Err(format!("{host} is not the character device {major}:{minor}").into());
        }
        let target = format!("{dev}/{name}");
        fs::write(&target, "")?;
        // Bound from the descriptor that was checked. Read-only blocks changing the
        // node's attributes; writing to the device itself still works.
        mount(&format!("/proc/self/fd/{}", opened.as_raw_fd()), &target, None, libc::MS_BIND, None)?;
        mount("none", &target, None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC, None)?;
    }
    // Scratch like /tmp, for POSIX shared memory and semaphores. noexec, so it is no way
    // to run code that is not in the root; 16 MiB, so with /tmp at most 32 MiB of files
    // live in memory per generation even without a memory controller. With one, tmpfs
    // pages are charged to the sandbox's cgroup, so memory.max bounds them as well.
    let shm = format!("{dev}/shm");
    fs::create_dir(&shm)?;
    mount("tmpfs", &shm, Some("tmpfs"), sealed, Some("mode=1777,size=16m"))?;
    mount("none", dev, None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | sealed, None)
}

/// Builds a minimal read-only root. Host paths outside this list do not exist
/// in the sandbox, including WSL interop paths and Windows drive mounts.
fn pivot_to_minimal_root(config: &Value) -> Result<(), Box<dyn Error>> {
    let root = config["new_root"].as_str().ok_or("new root")?;
    let exe = config["exe"].as_str().ok_or("exe")?;
    let gateway = config["gateway"].as_str().ok_or("gateway")?;
    let program = config["argv"][0].as_str().ok_or("argv")?;
    let supplied = config["root"].as_str();
    // What the program needs from the host, read before anything is mounted (#88): the
    // built-in agent's loader and libraries; for any other program the same, plus the
    // program itself at its own path. A supplied root takes the place of all of it. If
    // the view cannot be worked out exactly, the sandbox does not start.
    let view = match supplied {
        Some(_) => Ok(crate::sandbox_view::Plan::new()),
        None if program == AGENT => fs::read(exe).map_err(|e| format!("{exe}: {e}")).and_then(|b| crate::sandbox_view::plan(&b, Path::new("/"))),
        None => crate::sandbox_view::plan_program(Path::new(program), Path::new("/")),
    }.map_err(|e| format!("sandbox view: {e}"))?;
    let shadowed = view.keys().find(|p| p.components().nth(1).and_then(|c| c.as_os_str().to_str()).is_some_and(|top| RESERVED.contains(&top)));
    if let Some(path) = shadowed {
        return Err(format!("sandbox view: {} is under an entry the sandbox provides itself", path.display()).into());
    }
    mount("tmpfs", root, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=755,size=4m"))?;
    let under = |p: &str| format!("{root}/{}", p.trim_start_matches('/'));
    if let Some(dir) = supplied {
        supply_root(dir, root, config["writable_root"] == true)?;
    } else if config["wide_root"] == true {
        // Sabotage: the old root, which showed the agent the host's whole /usr and /lib*.
        for dir in ["/usr", "/lib", "/lib64", "/lib32", "/libx32"] {
            let Ok(meta) = fs::symlink_metadata(dir) else { continue };
            if meta.file_type().is_symlink() {
                symlink(fs::read_link(dir)?, under(dir))?;
            } else if meta.is_dir() {
                fs::create_dir(under(dir))?;
                bind(dir, &under(dir), libc::MS_RDONLY)?;
            }
        }
    } else {
        // Parents come before children in the plan's order.
        for (path, entry) in &view {
            let path = path.to_str().ok_or("sandbox view: a path is not UTF-8")?;
            match entry {
                crate::sandbox_view::Entry::Dir => fs::create_dir_all(under(path))?,
                crate::sandbox_view::Entry::Symlink(target) => symlink(target, under(path))?,
                crate::sandbox_view::Entry::File => {
                    fs::write(under(path), "")?;
                    // Read-only, not noexec: the loader and libraries are mapped executable.
                    bind(path, &under(path), libc::MS_RDONLY)?;
                }
            }
        }
    }
    for dir in ["/proc", "/tmp", "/dev", "/.old"] {
        fs::create_dir(under(dir))?;
    }
    if program == AGENT {
        fs::write(under(AGENT), "")?;
        bind(exe, &under(AGENT), libc::MS_RDONLY)?;
    }
    fs::write(under(GATEWAY), "")?;
    bind(gateway, &under(GATEWAY), libc::MS_NOEXEC)?;
    // The only writable path: this generation's copy-on-rebuild workspace.
    if let Some(workspace) = config["workspace"].as_str() {
        fs::create_dir(under("/workspace"))?;
        bind(workspace, &under("/workspace"), libc::MS_NOEXEC)?;
    }
    if config["expose_private"] == true {
        fs::create_dir(under("/private"))?;
        bind(config["private_dir"].as_str().ok_or("private")?, &under("/private"), libc::MS_NOEXEC)?;
    }
    // Only process directories, and only processes the viewer may ptrace.
    mount("proc", &under("/proc"), Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some("subset=pid,hidepid=invisible"))?;
    mount("tmpfs", &under("/tmp"), Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some("mode=1777,size=16m"))?;
    provide_dev(&under("/dev"))?;
    let new_root = c(root)?;
    let old_root = c(&under("/.old"))?;
    // SAFETY: both paths are live NUL-terminated strings.
    check(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) as libc::c_int })?;
    std::env::set_current_dir("/")?;
    let old = c("/.old")?;
    // SAFETY: `old` is a live NUL-terminated string.
    check(unsafe { libc::umount2(old.as_ptr(), libc::MNT_DETACH) })?;
    fs::remove_dir("/.old")?;
    mount("none", "/", None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV, None)
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Who a seccomp program is for. The agent may open AF_UNIX and AF_INET sockets
/// (it needs the gateway socket); System One may not create, connect or accept
/// sockets at all, and may not signal or trace processes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilterFor {
    Agent,
    SystemOne,
    /// Sabotage: the narrow filter of the first System One version.
    SystemOneWeak,
}

/// Builds the seccomp program. Denies kernel surfaces neither process needs:
/// x32 syscall numbers, mounts, namespaces (unshare, setns, namespace flags on
/// clone, clone3), io_uring, BPF, kernel keyrings, module loading, and clearing
/// the parent-death signal. `AF_VSOCK` matters on WSL2 because it can reach the
/// Windows host across network namespaces. Built before fork so a child only
/// has to install it.
pub fn build_filter(target: FilterFor) -> Vec<libc::sock_filter> {
    const LD_ABS_W: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const JGE: u16 = 0x35;
    const JSET: u16 = 0x45;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const ERRNO: u32 = 0x0005_0000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    let errno = |value: i32| ERRNO | value as u32;
    if target == FilterFor::SystemOneWeak {
        let mut p = vec![stmt(LD_ABS_W, 4), jump(JEQ, ARCH, 1, 0), stmt(RET, KILL_PROCESS), stmt(LD_ABS_W, 0)];
        for number in [libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_ptrace] {
            p.extend([jump(JEQ, number as u32, 0, 1), stmt(RET, errno(libc::EPERM))]);
        }
        p.push(stmt(RET, ALLOW));
        return p;
    }
    let mut denied: Vec<libc::c_long> = vec![
        libc::SYS_mount, libc::SYS_umount2, libc::SYS_pivot_root, libc::SYS_chroot, libc::SYS_ptrace,
        libc::SYS_process_vm_readv, libc::SYS_process_vm_writev, libc::SYS_bpf, libc::SYS_perf_event_open,
        libc::SYS_userfaultfd, libc::SYS_kexec_load, libc::SYS_init_module, libc::SYS_finit_module,
        libc::SYS_delete_module, libc::SYS_add_key, libc::SYS_request_key, libc::SYS_keyctl, libc::SYS_unshare,
        libc::SYS_setns, libc::SYS_swapon, libc::SYS_swapoff, libc::SYS_reboot, libc::SYS_settimeofday,
        libc::SYS_clock_settime, libc::SYS_clock_adjtime, libc::SYS_adjtimex, libc::SYS_acct, libc::SYS_quotactl,
        libc::SYS_name_to_handle_at, libc::SYS_open_by_handle_at,
        425, 426, 427, // io_uring
        428, 429, 430, 431, 432, 433, 442, // new mount API
    ];
    #[cfg(target_arch = "x86_64")]
    denied.push(libc::SYS_kexec_file_load);
    if target == FilterFor::SystemOne {
        denied.extend([
            libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen,
            libc::SYS_accept, libc::SYS_accept4, libc::SYS_kill, libc::SYS_tkill, libc::SYS_memfd_create,
            libc::SYS_execveat, libc::SYS_pidfd_open, libc::SYS_pidfd_send_signal, libc::SYS_pidfd_getfd,
            libc::SYS_tgkill, libc::SYS_rt_sigqueueinfo, libc::SYS_rt_tgsigqueueinfo,
        ]);
        #[cfg(target_arch = "x86_64")]
        denied.extend([libc::SYS_fork, libc::SYS_vfork]);
    }
    const CLONE_NEWTIME: u32 = 0x80;
    let ns_flags = (libc::CLONE_NEWNS | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWCGROUP) as u32 | CLONE_NEWTIME;
    let mut p = vec![stmt(LD_ABS_W, 4), jump(JEQ, ARCH, 1, 0), stmt(RET, KILL_PROCESS), stmt(LD_ABS_W, 0)];
    #[cfg(target_arch = "x86_64")]
    p.extend([jump(JGE, 0x4000_0000, 0, 1), stmt(RET, errno(libc::ENOSYS))]);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = JGE;
    for number in denied {
        p.extend([jump(JEQ, number as u32, 0, 1), stmt(RET, errno(libc::EPERM))]);
    }
    // No process may change its own parent-death signal.
    p.extend([
        jump(JEQ, libc::SYS_prctl as u32, 0, 4),
        stmt(LD_ABS_W, 16),
        jump(JEQ, libc::PR_SET_PDEATHSIG as u32, 0, 1),
        stmt(RET, errno(libc::EPERM)),
        stmt(RET, ALLOW),
    ]);
    // clone3 hides its flags behind a pointer. ENOSYS makes libc fall back to clone.
    p.extend([jump(JEQ, libc::SYS_clone3 as u32, 0, 1), stmt(RET, errno(libc::ENOSYS))]);
    if target == FilterFor::SystemOne {
        // Threads only: a forked child would lose the parent-death signal.
        p.extend([
            jump(JEQ, libc::SYS_clone as u32, 0, 5),
            stmt(LD_ABS_W, 16),
            jump(JSET, ns_flags, 2, 0),
            jump(JSET, libc::CLONE_THREAD as u32, 0, 1),
            stmt(RET, ALLOW),
            stmt(RET, errno(libc::EPERM)),
        ]);
    } else {
        p.extend([
            jump(JEQ, libc::SYS_clone as u32, 0, 4),
            stmt(LD_ABS_W, 16),
            jump(JSET, ns_flags, 0, 1),
            stmt(RET, errno(libc::EPERM)),
            stmt(RET, ALLOW),
        ]);
    }
    if target == FilterFor::Agent {
        p.extend([
            jump(JEQ, libc::SYS_socket as u32, 0, 5),
            stmt(LD_ABS_W, 16),
            jump(JEQ, libc::AF_UNIX as u32, 3, 0),
            jump(JEQ, libc::AF_INET as u32, 2, 0),
            jump(JEQ, libc::AF_INET6 as u32, 1, 0),
            stmt(RET, errno(libc::EAFNOSUPPORT)),
            stmt(RET, ALLOW),
        ]);
    }
    p.push(stmt(RET, ALLOW));
    p
}

fn install_seccomp() -> io::Result<()> {
    let mut program = build_filter(FilterFor::Agent);
    // SAFETY: called after PR_SET_NO_NEW_PRIVS in drop_authority; `program` is live.
    check(unsafe { install_filter(&mut program) })
}

/// Installs a prebuilt filter. Async-signal-safe: no allocation.
///
/// # Safety
/// Call only after PR_SET_NO_NEW_PRIVS, and between fork and exec if the
/// process has other threads.
pub unsafe fn install_filter(program: &mut [libc::sock_filter]) -> libc::c_int {
    let fprog = libc::sock_fprog { len: program.len() as u16, filter: program.as_mut_ptr() };
    // SAFETY: the caller guarantees the context; `fprog` points into `program`.
    unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog as *const libc::sock_fprog) }
}

/// `keep` is the exec-status pipe, the one descriptor above stderr that stays open.
/// It is close-on-exec, so the program still starts with only 0, 1 and 2.
fn drop_authority(uid: u32, seccomp: bool, keep: libc::c_int) -> Result<(), Box<dyn Error>> {
    let keep = u32::try_from(keep).ok().filter(|fd| *fd > 2).ok_or("the exec-status pipe is a standard descriptor")?;
    let limit = |resource, value| {
        let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
        // SAFETY: `limit` is a valid rlimit for the call.
        check(unsafe { libc::setrlimit(resource, &limit) })
    };
    limit(libc::RLIMIT_NPROC, 256)?;
    limit(libc::RLIMIT_NOFILE, 256)?;
    limit(libc::RLIMIT_CORE, 0)?;
    limit(libc::RLIMIT_FSIZE, 16 * 1024 * 1024)?;
    // SAFETY: these calls change only this process's credentials and flags.
    unsafe {
        // Unconfirmed means stopped (INV-7): a failed close_range would leave the
        // controller's descriptors open in the agent.
        if keep > 3 {
            check(libc::syscall(libc::SYS_close_range, 3_u32, keep - 1, 0_u32) as libc::c_int)?;
        }
        check(libc::syscall(libc::SYS_close_range, keep + 1, u32::MAX, 0_u32) as libc::c_int)?;
        check(libc::setgroups(0, ptr::null()))?;
        check(libc::setresgid(uid, uid, uid))?;
        check(libc::setresuid(uid, uid, uid))?;
        check(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))?;
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
    }
    if seccomp {
        install_seccomp()?;
    }
    Ok(())
}

/// Where the program, the gateway socket and the workspace are once the root is set up.
struct Placed {
    program: String,
    gateway: String,
    workspace: Option<&'static str>,
}

fn prepare(config: &Value) -> Result<Placed, Box<dyn Error>> {
    mount("none", "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let program = config["argv"][0].as_str().ok_or("argv")?;
    if config["host_root"] == true {
        // Sabotage: no pivot, so everything is where it is on the host.
        mount("proc", "/proc", Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;
        let program = if program == AGENT { config["exe"].as_str().ok_or("exe")? } else { program };
        return Ok(Placed { program: program.to_owned(), gateway: config["gateway"].as_str().ok_or("gateway")?.to_owned(), workspace: None });
    }
    pivot_to_minimal_root(config)?;
    Ok(Placed { program: program.to_owned(), gateway: GATEWAY.to_owned(), workspace: config["workspace"].is_string().then_some("/workspace") })
}

/// The launcher forks a root-owned init that becomes PID 1 of the sandbox's PID
/// namespace and holds the parent-death signal. The agent runs as PID 2 under a
/// separate UID, so it cannot clear that signal or signal init. When init dies,
/// the kernel kills every process in the namespace.
pub fn launch(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [config] = args else { return Err("sandbox-launch arguments are invalid".into()) };
    let config: Value = serde_json::from_str(config)?;
    let death_signal = config["death_signal"] == true;
    let status_fd = config["status_fd"].as_i64().and_then(|fd| libc::c_int::try_from(fd).ok()).ok_or("status_fd")?;
    // SAFETY: the controller opened this descriptor for the launcher alone and kept it
    // open across exec; nothing else in this process owns it.
    let status = unsafe { fs::File::from_raw_fd(status_fd) };
    // Init polls this pipe so a launcher death before PDEATHSIG is armed is seen.
    let mut pipe = [0; 2];
    // SAFETY: `pipe` is a valid two-element output array.
    check(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: this process is single-threaded at this point.
    let init = unsafe { libc::fork() };
    if init < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if init > 0 {
        // SAFETY: closing the unused read end is valid in the launcher.
        unsafe { libc::close(pipe[0]) };
        // Only init reports, so the reports end when init does.
        drop(status);
        let mut status = 0;
        // SAFETY: `status` is a valid out pointer.
        unsafe { libc::waitpid(init, &mut status, 0) };
        return Ok(());
    }
    // SAFETY: closing the unused write end is valid in init.
    unsafe { libc::close(pipe[1]) };
    match start_program(&config, death_signal, pipe[0]) {
        Ok(program) => {
            report(&status, &json!({"started": true}));
            supervise(program, &status)
        }
        Err(error) => {
            report(&status, &json!({"started": false, "reason": error.to_string().chars().take(2000).collect::<String>()}));
            Err(error)
        }
    }
}

/// One record for the controller. Only init writes to this pipe.
fn report(status: &fs::File, record: &Value) {
    let _ = io::Write::write_all(&mut &*status, format!("{record}\n").as_bytes());
}

/// Init reaps orphans and ends the sandbox when the program exits, once it has
/// said how the program ended.
fn supervise(program: libc::pid_t, status: &fs::File) -> ! {
    loop {
        let mut wait = 0;
        // SAFETY: `wait` is a valid out pointer.
        let pid = unsafe { libc::waitpid(-1, &mut wait, 0) };
        if pid == program {
            let ended = if libc::WIFSIGNALED(wait) { json!({"signal": libc::WTERMSIG(wait)}) } else { json!({"exit_code": libc::WEXITSTATUS(wait)}) };
            report(status, &ended);
        }
        if pid == program || (pid < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)) {
            // SAFETY: _exit is always safe to call.
            unsafe { libc::_exit(0) };
        }
    }
}

/// Init's part before the program runs: the root, then the program. Returns the
/// program's pid once its exec has succeeded, or why it did not start.
fn start_program(config: &Value, death_signal: bool, death_pipe: libc::c_int) -> Result<libc::pid_t, Box<dyn Error>> {
    if death_signal {
        // SAFETY: prctl has no pointer arguments here.
        check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
        let mut waiting = libc::pollfd { fd: death_pipe, events: libc::POLLIN, revents: 0 };
        // SAFETY: `waiting` is a valid pollfd array of length one.
        if unsafe { libc::poll(&mut waiting, 1, 0) } != 0 {
            return Err("sandbox launcher exited during start".into());
        }
    }
    // Memory-backed files must not be executable in this PID namespace. Otherwise an
    // agent can run code that is not in its root, including Windows images through
    // WSL's kernel-global interop handler, whose interpreter is preopened. The sysctl
    // is per PID namespace and applies to the writer's, so init sets it before the
    // pivot hides /proc/sys.
    if config["memfd_exec"] != true {
        fs::write("/proc/sys/vm/memfd_noexec", "2").map_err(|e| format!("vm.memfd_noexec: {e}"))?;
    }
    let placed = prepare(config)?;
    let argv: Vec<&str> = config["argv"].as_array().ok_or("argv")?.iter().map(|a| a.as_str().ok_or("argv")).collect::<Result<_, _>>()?;
    // The exec-status pipe. Its write end is close-on-exec, so a successful exec closes
    // it with nothing written, and a failure writes why before the program exits.
    let mut exec_status = [0; 2];
    // SAFETY: `exec_status` is a valid two-element output array.
    check(unsafe { libc::pipe2(exec_status.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: init is single-threaded here.
    let program = unsafe { libc::fork() };
    if program < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if program == 0 {
        let why = exec_program(config, &placed, &argv, exec_status[1]).to_string();
        // SAFETY: writes a live buffer to the descriptor kept open for this.
        unsafe { libc::write(exec_status[1], why.as_ptr().cast(), why.len()) };
        // SAFETY: _exit is always safe to call.
        unsafe { libc::_exit(127) };
    }
    // SAFETY: closes init's copy of the write end, so the read below ends at the exec.
    unsafe { libc::close(exec_status[1]) };
    let mut failed = Vec::new();
    // SAFETY: the read end was created above and nothing else owns it.
    io::Read::read_to_end(&mut unsafe { fs::File::from_raw_fd(exec_status[0]) }, &mut failed)?;
    if !failed.is_empty() {
        // SAFETY: reaps the program, which has exited; a null status pointer is allowed.
        unsafe { libc::waitpid(program, ptr::null_mut(), 0) };
        return Err(String::from_utf8_lossy(&failed).into_owned().into());
    }
    Ok(program)
}

/// The program's side of the fork: it gives up authority, then execs. Returns only
/// on failure, with the reason.
fn exec_program(config: &Value, placed: &Placed, argv: &[&str], exec_status: libc::c_int) -> Box<dyn Error> {
    let Some(uid) = config["uid"].as_u64() else { return "uid".into() };
    if let Err(error) = drop_authority(uid as u32, config["seccomp"] != false, exec_status) {
        return error;
    }
    // Nothing of the controller's environment: only where the gateway is, and a
    // home and search path inside the sandbox.
    let mut command = Command::new(&placed.program);
    command.args(&argv[1..]).env_clear()
        .env("VAC_GATE", &placed.gateway).env("HOME", "/workspace").env("PATH", "/usr/local/bin:/usr/bin:/bin");
    if let Some(dir) = placed.workspace {
        command.current_dir(dir);
    }
    format!("exec {}: {}", placed.program, command.exec()).into()
}

/// Creates the directory the new root is mounted over.
pub fn prepare_new_root(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reports() -> (ProgramStatus, io::PipeWriter) {
        let (pipe, writer) = io::pipe().expect("pipe");
        // SAFETY: fcntl on a descriptor this test owns.
        unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        (ProgramStatus { pipe, unread: Vec::new(), state: Reported::Nothing }, writer)
    }

    #[test]
    fn init_reports_are_read_as_they_arrive_even_split_across_writes() {
        let (mut status, mut init) = reports();
        assert_eq!(status.poll(), &Reported::Nothing);
        io::Write::write_all(&mut init, b"{\"started\":true}\n{\"exit_").expect("write");
        assert_eq!(status.poll(), &Reported::Started);
        io::Write::write_all(&mut init, b"code\":3}\n").expect("write");
        assert_eq!(status.poll(), &Reported::Exited(3));
        assert_eq!(status.poll().to_json(), json!({"started": true, "exit_code": 3}));
    }

    #[test]
    fn a_sandbox_that_ends_without_a_report_did_not_start_its_program() {
        let (mut status, init) = reports();
        drop(init);
        assert!(matches!(status.ended(), Reported::NotStarted(_)));
        let (mut status, mut init) = reports();
        io::Write::write_all(&mut init, b"{\"started\":false,\"reason\":\"exec /x: gone\"}\n").expect("write");
        assert_eq!(status.ended(), &Reported::NotStarted("exec /x: gone".to_owned()));
        // A program that started keeps that, even with its end unreported.
        let (mut status, mut init) = reports();
        io::Write::write_all(&mut init, b"{\"started\":true}\n").expect("write");
        assert_eq!(status.ended(), &Reported::Started);
    }

    #[test]
    fn an_outside_program_must_not_hide_under_the_sandboxs_own_entries() {
        let argv = |path: &str| vec![path.to_owned(), "arg".to_owned()];
        assert!(Program::outside(argv("/usr/bin/python3"), None).is_ok());
        for bad in ["usr/bin/x", "/", "/tmp/x", "/dev/shm/x", "/agent", "/workspace/run.sh", "/usr/../tmp/x", "/proc/self/exe"] {
            assert!(Program::outside(argv(bad), None).is_err(), "{bad} was accepted");
        }
        assert!(Program::outside(Vec::new(), None).is_err());
        assert!(Program::outside(vec!["/bin/x".to_owned(), "a\0b".to_owned()], None).is_err());
    }
}

use serde_json::{json, Value};
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
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
pub const RESERVED: &[&str] = &["proc", "tmp", "workspace", "gateway.sock", ".old", "agent"];

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

/// Starts one sandbox inside `cgroup`. This must run on the controller's main
/// thread because the parent-death signal follows the spawning thread.
/// Returns the sandbox's process and the thread copying its output into `spec.output`.
/// The caller joins the copier once the sandbox's processes are gone, so the last
/// records the agent wrote reach the file.
pub fn spawn(spec: &SandboxSpec, cgroup: &Path, uid: u32, workspace: Option<&Path>) -> io::Result<(Child, std::thread::JoinHandle<()>)> {
    let procs = fs::OpenOptions::new().write(true).open(cgroup.join("cgroup.procs"))?;
    let output = fs::OpenOptions::new().create(true).append(true).open(&spec.output)?;
    // The agent writes to a pipe, not to the file: with a file descriptor on the file it
    // could ftruncate away what earlier generations wrote (#88). The controller copies the
    // pipe into the file, at most AGENT_OUTPUT_LIMIT bytes per generation.
    let (reader, writer) = io::pipe()?;
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
        "workspace": workspace,
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
            check(libc::unshare(flags))
        });
    }
    let child = command.spawn()?;
    // Closes the parent's copies of the write end, so the copy ends when the agent's do.
    drop(command);
    Ok((child, copy_agent_output(reader, output)))
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
    for dir in ["/proc", "/tmp", "/.old"] {
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

fn drop_authority(uid: u32, seccomp: bool) -> Result<(), Box<dyn Error>> {
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
        check(libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) as libc::c_int)?;
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
        let mut status = 0;
        // SAFETY: `status` is a valid out pointer.
        unsafe { libc::waitpid(init, &mut status, 0) };
        return Ok(());
    }
    // SAFETY: closing the unused write end is valid in init.
    unsafe { libc::close(pipe[1]) };
    if death_signal {
        // SAFETY: prctl has no pointer arguments here.
        check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
        let mut waiting = libc::pollfd { fd: pipe[0], events: libc::POLLIN, revents: 0 };
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
    let placed = prepare(&config)?;
    let argv: Vec<&str> = config["argv"].as_array().ok_or("argv")?.iter().map(|a| a.as_str().ok_or("argv")).collect::<Result<_, _>>()?;
    // SAFETY: init is single-threaded here.
    let agent = unsafe { libc::fork() };
    if agent < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if agent == 0 {
        drop_authority(config["uid"].as_u64().ok_or("uid")? as u32, config["seccomp"] != false)?;
        // Nothing of the controller's environment: only where the gateway is, and a
        // home and search path inside the sandbox.
        let mut command = Command::new(&placed.program);
        command.args(&argv[1..]).env_clear()
            .env("VAC_GATE", &placed.gateway).env("HOME", "/workspace").env("PATH", "/usr/local/bin:/usr/bin:/bin");
        if let Some(dir) = placed.workspace {
            command.current_dir(dir);
        }
        return Err(command.exec().into());
    }
    // Init reaps orphans and ends the sandbox when the agent exits.
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out pointer.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == agent || (pid < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)) {
            // SAFETY: _exit is always safe to call.
            unsafe { libc::_exit(0) };
        }
    }
}

/// Creates the directory the new root is mounted over.
pub fn prepare_new_root(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

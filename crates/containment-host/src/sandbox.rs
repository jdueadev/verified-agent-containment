use serde_json::{json, Value};
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;

pub struct SandboxSpec {
    pub exe: PathBuf,
    pub new_root: PathBuf,
    pub private_dir: PathBuf,
    pub gateway: PathBuf,
    pub scenario: String,
    pub output: PathBuf,
    pub probe: Value,
    pub share_network: bool,
    pub expose_private: bool,
    pub no_parent_death_signal: bool,
    pub host_root: bool,
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
pub fn spawn(spec: &SandboxSpec, cgroup: &Path, uid: u32, workspace: Option<&Path>) -> io::Result<Child> {
    let procs = fs::OpenOptions::new().write(true).open(cgroup.join("cgroup.procs"))?;
    let output = fs::OpenOptions::new().create(true).append(true).open(&spec.output)?;
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
        "scenario": spec.scenario, "uid": uid, "probe": spec.probe, "expose_private": spec.expose_private,
        "death_signal": death_signal, "host_root": spec.host_root, "seccomp": spec.seccomp, "memfd_exec": spec.memfd_exec,
        "workspace": workspace,
    });
    let mut command = Command::new(&spec.exe);
    command
        .arg("sandbox-launch")
        .arg(config.to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
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
    command.spawn()
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

/// Builds a minimal read-only root. Host paths outside this list do not exist
/// in the sandbox, including WSL interop paths and Windows drive mounts.
fn pivot_to_minimal_root(config: &Value) -> Result<(), Box<dyn Error>> {
    let root = config["new_root"].as_str().ok_or("new root")?;
    let exe = config["exe"].as_str().ok_or("exe")?;
    let gateway = config["gateway"].as_str().ok_or("gateway")?;
    mount("tmpfs", root, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=755,size=4m"))?;
    let under = |p: &str| format!("{root}/{}", p.trim_start_matches('/'));
    for dir in ["/usr", "/lib", "/lib64", "/lib32", "/libx32"] {
        let Ok(meta) = fs::symlink_metadata(dir) else { continue };
        if meta.file_type().is_symlink() {
            symlink(fs::read_link(dir)?, under(dir))?;
        } else if meta.is_dir() {
            fs::create_dir(under(dir))?;
            bind(dir, &under(dir), libc::MS_RDONLY)?;
        }
    }
    for dir in ["/proc", "/tmp", "/.old"] {
        fs::create_dir(under(dir))?;
    }
    fs::write(under("/agent"), "")?;
    bind(exe, &under("/agent"), libc::MS_RDONLY)?;
    fs::write(under("/gateway.sock"), "")?;
    bind(gateway, &under("/gateway.sock"), libc::MS_NOEXEC)?;
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

/// Denies kernel surfaces the agent has no reason to use. `AF_VSOCK` matters on
/// WSL2 because it can reach the Windows host across network namespaces.
fn install_seccomp() -> io::Result<()> {
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
    let ns_flags = (libc::CLONE_NEWNS | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWCGROUP) as u32;
    let mut p = vec![stmt(LD_ABS_W, 4), jump(JEQ, ARCH, 1, 0), stmt(RET, KILL_PROCESS), stmt(LD_ABS_W, 0)];
    #[cfg(target_arch = "x86_64")]
    p.extend([jump(JGE, 0x4000_0000, 0, 1), stmt(RET, errno(libc::ENOSYS))]);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = JGE;
    for number in denied {
        p.extend([jump(JEQ, number as u32, 0, 1), stmt(RET, errno(libc::EPERM))]);
    }
    // The agent may not change its own parent-death signal.
    p.extend([
        jump(JEQ, libc::SYS_prctl as u32, 0, 4),
        stmt(LD_ABS_W, 16),
        jump(JEQ, libc::PR_SET_PDEATHSIG as u32, 0, 1),
        stmt(RET, errno(libc::EPERM)),
        stmt(RET, ALLOW),
    ]);
    // clone3 hides its flags behind a pointer. ENOSYS makes libc fall back to clone.
    p.extend([jump(JEQ, libc::SYS_clone3 as u32, 0, 1), stmt(RET, errno(libc::ENOSYS))]);
    p.extend([
        jump(JEQ, libc::SYS_clone as u32, 0, 4),
        stmt(LD_ABS_W, 16),
        jump(JSET, ns_flags, 0, 1),
        stmt(RET, errno(libc::EPERM)),
        stmt(RET, ALLOW),
    ]);
    p.extend([
        jump(JEQ, libc::SYS_socket as u32, 0, 5),
        stmt(LD_ABS_W, 16),
        jump(JEQ, libc::AF_UNIX as u32, 3, 0),
        jump(JEQ, libc::AF_INET as u32, 2, 0),
        jump(JEQ, libc::AF_INET6 as u32, 1, 0),
        stmt(RET, errno(libc::EAFNOSUPPORT)),
        stmt(RET, ALLOW),
    ]);
    let program = libc::sock_fprog { len: p.len() as u16, filter: p.as_mut_ptr() };
    // SAFETY: the kernel copies the filter during this call and `program` is valid.
    check(unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program as *const libc::sock_fprog) })
}

/// Seccomp program for System One, built before fork so the child only has to
/// install it. System One may not create or connect sockets (it already holds
/// its two descriptors), trace other processes, or change namespaces.
pub fn system_one_filter() -> Vec<libc::sock_filter> {
    const LD_ABS_W: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const ERRNO: u32 = 0x0005_0000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    let denied: [libc::c_long; 17] = [
        libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen,
        libc::SYS_accept, libc::SYS_accept4, libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
        libc::SYS_mount, libc::SYS_unshare, libc::SYS_setns, libc::SYS_bpf, libc::SYS_perf_event_open,
        libc::SYS_memfd_create, libc::SYS_execveat,
    ];
    let mut p = vec![stmt(LD_ABS_W, 4), jump(JEQ, ARCH, 1, 0), stmt(RET, KILL_PROCESS), stmt(LD_ABS_W, 0)];
    for number in denied {
        p.extend([jump(JEQ, number as u32, 0, 1), stmt(RET, ERRNO | libc::EPERM as u32)]);
    }
    p.push(stmt(RET, ALLOW));
    p
}

/// Installs a prebuilt filter. Async-signal-safe: no allocation.
///
/// # Safety
/// Call only in a child between fork and exec, after PR_SET_NO_NEW_PRIVS.
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
        libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32);
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

fn prepare(config: &Value) -> Result<(String, String), Box<dyn Error>> {
    mount("none", "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let exe = config["exe"].as_str().ok_or("exe")?.to_owned();
    let gateway = config["gateway"].as_str().ok_or("gateway")?.to_owned();
    let paths = if config["host_root"] == true {
        mount("proc", "/proc", Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;
        (exe, gateway)
    } else {
        pivot_to_minimal_root(config)?;
        ("/agent".to_owned(), "/gateway.sock".to_owned())
    };
    Ok(paths)
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
    let (exe, gateway) = prepare(&config)?;
    // SAFETY: init is single-threaded here.
    let agent = unsafe { libc::fork() };
    if agent < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if agent == 0 {
        drop_authority(config["uid"].as_u64().ok_or("uid")? as u32, config["seccomp"] != false)?;
        let error = Command::new(Path::new(&exe))
            .arg("agent")
            .arg(gateway)
            .arg(config["scenario"].as_str().ok_or("scenario")?)
            .arg(config["probe"].to_string())
            .env_clear()
            .exec();
        return Err(error.into());
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

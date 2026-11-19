use crate::common::SANDBOX_UID;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;

pub struct SandboxSpec {
    pub exe: PathBuf,
    pub cgroup: PathBuf,
    pub private_dir: PathBuf,
    pub gateway: PathBuf,
    pub scenario: String,
    pub output: PathBuf,
    pub share_network: bool,
    pub expose_private: bool,
    pub no_parent_death_signal: bool,
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn c(path: &str) -> Result<CString, Box<dyn Error>> {
    Ok(CString::new(path)?)
}

pub fn spawn(spec: &SandboxSpec) -> io::Result<Child> {
    let procs = std::fs::OpenOptions::new().write(true).open(spec.cgroup.join("cgroup.procs"))?;
    let output = std::fs::OpenOptions::new().create(true).append(true).open(&spec.output)?;
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWPID;
    if !spec.share_network {
        flags |= libc::CLONE_NEWNET;
    }
    let fd = procs.as_raw_fd();
    let death_signal = !spec.no_parent_death_signal;
    let mut command = Command::new(&spec.exe);
    command
        .arg("sandbox-launch")
        .arg(&spec.exe)
        .arg(&spec.private_dir)
        .arg(&spec.gateway)
        .arg(&spec.scenario)
        .arg(if spec.expose_private { "expose" } else { "hide" })
        .arg(if death_signal { "death-signal" } else { "no-death-signal" })
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
            }
            check(libc::unshare(flags))
        });
    }
    command.spawn()
}

fn mount(source: &str, target: &str, kind: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<(), Box<dyn Error>> {
    let source = c(source)?;
    let target = c(target)?;
    let kind = kind.map(c).transpose()?;
    let data = data.map(c).transpose()?;
    // SAFETY: all pointers refer to live NUL-terminated strings or are null.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            kind.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
            flags,
            data.as_ref().map_or(ptr::null(), |v| v.as_ptr().cast()),
        )
    };
    check(result)?;
    Ok(())
}

fn prepare(private_dir: &str, expose_private: bool, death_signal: bool) -> Result<(), Box<dyn Error>> {
    mount("none", "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    mount("proc", "/proc", Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;
    mount("tmpfs", "/tmp", Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777,size=16m"))?;
    if !expose_private {
        mount("tmpfs", private_dir, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some("mode=000,size=4k"))?;
    }
    let limit = |resource, value| {
        let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
        // SAFETY: `limit` is a valid rlimit for the call.
        check(unsafe { libc::setrlimit(resource, &limit) })
    };
    limit(libc::RLIMIT_NPROC, 2_048)?;
    limit(libc::RLIMIT_NOFILE, 512)?;
    // SAFETY: these calls change only this process's credentials and flags.
    unsafe {
        check(libc::setgroups(0, ptr::null()))?;
        check(libc::setgid(SANDBOX_UID))?;
        check(libc::setuid(SANDBOX_UID))?;
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        if death_signal {
            check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
        }
    }
    Ok(())
}

pub fn launch(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [exe, private_dir, gateway, scenario, private_mode, death_mode] = args else {
        return Err("sandbox-launch arguments are invalid".into());
    };
    // SAFETY: this process is single-threaded at this point.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if child > 0 {
        let mut status = 0;
        // SAFETY: `status` is a valid out pointer.
        unsafe { libc::waitpid(child, &mut status, 0) };
        return Ok(());
    }
    prepare(private_dir, private_mode == "expose", death_mode == "death-signal")?;
    let error = Command::new(Path::new(exe))
        .arg("agent")
        .arg(gateway)
        .arg(scenario)
        .arg(private_dir)
        .env_clear()
        .exec();
    Err(error.into())
}

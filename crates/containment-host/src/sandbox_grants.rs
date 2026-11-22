//! Explicit read-only grants and the sandbox's limits, from the root-owned policy (#88, #28).
//!
//! By default the agent sees only what its executable needs (`sandbox_view.rs`). Anything
//! more is a grant: a host path the operator lists under `[sandbox] read_only` in the
//! policy file. The policy is read once, at startup, and what it says is frozen here:
//!
//! - Each grant is opened once as an `O_PATH` descriptor, resolved inside the host root
//!   (`openat2` with `RESOLVE_IN_ROOT`), and checked through that descriptor. The sandbox
//!   later binds the same descriptor (`/proc/self/fd/N`), so what was checked is what is
//!   bound, whatever happens to the path in between.
//! - The frozen value lives in the controller's `SandboxSpec`, which every Kill rebuild
//!   reuses. Nothing rereads the policy file, so a file the agent could write (the
//!   `writable_policy` weakness) cannot add a grant to a later generation.
//! - Anything invalid refuses the whole run. Nothing is skipped (INV-7).
//!
//! The policy file is not signed. It is trusted because only root can write it
//! (H-CTL-01), and a policy that grants anything must show that: owned by root, and not
//! writable by group or others.
//!
//! Residual: a grant's tree is scanned for sockets and special files at startup. Every
//! directory in it must be owned by root and not group- or world-writable, so only root
//! can add an entry afterwards, and root is trusted here.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// Host trees a grant may never be, or be under (#28). `/` itself is refused too.
pub const REFUSED: &[&str] = &["/etc", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/var/run", "/mnt", "/tmp"];
/// At most this many grants.
pub const MAX_GRANTS: usize = 16;
/// Entries across all grant trees, roots included. The agent's own walk of its view stops
/// at 4096 paths (`agent.rs`), and the view check must stay exact.
pub const MAX_GRANT_ENTRIES: usize = 2048;
/// Deepest directory level inside one grant.
pub const MAX_GRANT_DEPTH: usize = 32;
/// Largest policy file read.
pub const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// The `[sandbox]` section of a policy.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    /// Host paths the agent may read. Bound read-only, nosuid, nodev and noexec.
    #[serde(default)]
    pub read_only: Vec<PathBuf>,
    #[serde(default)]
    pub limits: Limits,
}

/// Per-generation limits. The defaults are the values the sandbox used before they were
/// configurable, so a policy without them runs exactly as before.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// RLIMIT_NPROC for the agent's uid.
    pub nproc: u64,
    /// RLIMIT_NOFILE.
    pub nofile: u64,
    /// RLIMIT_FSIZE, in MiB.
    pub fsize_mib: u64,
    /// Size of the sandbox's /tmp, in MiB.
    pub tmp_mib: u64,
    /// The generation cgroup's pids.max.
    pub pids_max: u64,
    /// The generation cgroup's memory.max, in MiB.
    pub memory_mib: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { nproc: 256, nofile: 256, fsize_mib: 16, tmp_mib: 16, pids_max: 512, memory_mib: 1024 }
    }
}

impl Limits {
    /// Inclusive ranges each limit must fall in (#28, AC-018).
    pub const RANGES: [(&'static str, u64, u64); 6] = [
        ("nproc", 16, 4096),
        ("nofile", 32, 4096),
        ("fsize_mib", 1, 1024),
        ("tmp_mib", 1, 1024),
        ("pids_max", 16, 4096),
        ("memory_mib", 64, 16384),
    ];

    fn values(&self) -> [u64; 6] {
        [self.nproc, self.nofile, self.fsize_mib, self.tmp_mib, self.pids_max, self.memory_mib]
    }

    pub fn validate(&self) -> Result<(), String> {
        for ((name, low, high), value) in Self::RANGES.iter().zip(self.values()) {
            if value < *low || value > *high {
                return Err(format!("sandbox.limits.{name} = {value} is outside {low}..={high}"));
            }
        }
        Ok(())
    }

    /// What the generation cgroup is given. cpu.max is not configurable.
    pub fn cgroup(&self) -> [(&'static str, String); 3] {
        [("pids.max", self.pids_max.to_string()), ("memory.max", (self.memory_mib * 1024 * 1024).to_string()), ("cpu.max", "50000 100000".to_owned())]
    }

    pub fn record(&self) -> Value {
        json!({"nproc": self.nproc, "nofile": self.nofile, "fsize_mib": self.fsize_mib, "tmp_mib": self.tmp_mib,
               "pids_max": self.pids_max, "memory_mib": self.memory_mib})
    }
}

impl SandboxPolicy {
    /// Checks what can be checked without the filesystem: the limits, and the shape of
    /// each grant path.
    pub fn validate(&self) -> Result<(), String> {
        self.limits.validate()?;
        if self.read_only.len() > MAX_GRANTS {
            return Err(format!("sandbox.read_only lists {} paths; at most {MAX_GRANTS}", self.read_only.len()));
        }
        for path in &self.read_only {
            let text = path.to_str().ok_or_else(|| format!("sandbox.read_only: {} is not UTF-8", path.display()))?;
            if !path.is_absolute() {
                return Err(format!("sandbox.read_only: {text} is not an absolute path"));
            }
            if text.len() > 1024 || text.contains('\0') {
                return Err(format!("sandbox.read_only: {text} is too long or contains NUL"));
            }
        }
        Ok(())
    }
}

/// A policy file as it was read, once. The bytes are what was parsed and hashed.
pub struct PolicyFile {
    pub bytes: Vec<u8>,
    pub sha256: String,
    /// Why the file cannot carry grants, if it cannot.
    untrusted: Option<String>,
}

impl PolicyFile {
    /// Reads the policy file. Ownership and mode come from the descriptor that was read.
    pub fn read(path: &Path) -> Result<Self, String> {
        Self::read_trusting(path, 0)
    }

    pub fn read_trusting(path: &Path, trusted_uid: u32) -> Result<Self, String> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("policy {}: {e}", path.display()))?;
        let meta = file.metadata().map_err(|e| format!("policy {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("policy {} is not a regular file", path.display()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes).map_err(|e| format!("policy {}: {e}", path.display()))?;
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(format!("policy {} is larger than {MAX_POLICY_BYTES} bytes", path.display()));
        }
        let untrusted = if meta.uid() != trusted_uid {
            Some(format!("it is owned by uid {}, not {trusted_uid}", meta.uid()))
        } else if meta.mode() & 0o022 != 0 {
            Some(format!("it is writable by group or others (mode {:o})", meta.mode() & 0o7777))
        } else {
            None
        };
        Ok(Self { sha256: hex(&Sha256::digest(&bytes)), bytes, untrusted })
    }

    pub fn text(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.bytes).map_err(|_| "policy is not UTF-8".to_owned())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One validated grant, held open.
#[derive(Debug)]
pub struct Grant {
    /// Canonical path, the same on the host and in the sandbox.
    pub path: PathBuf,
    pub dir: bool,
    pub dev: u64,
    pub ino: u64,
    /// Every path the grant shows the agent, itself included, in sandbox terms.
    pub entries: Vec<PathBuf>,
    fd: OwnedFd,
}

/// What the sandbox may show beyond the default view, and its limits, read once at
/// startup. There is no way to change it afterwards.
#[derive(Debug)]
pub struct Frozen {
    grants: Vec<Grant>,
    limits: Limits,
    policy_sha256: String,
    grants_sha256: String,
}

/// What the sandbox root already holds. A grant may not cover any of it.
pub struct Reserved {
    /// Directories a grant may sit under, but not be or contain (the resolver's
    /// directories, such as `/usr`).
    pub dirs: Vec<PathBuf>,
    /// Everything else (files, symlinks, the fixed mounts): a grant may not be, contain or
    /// sit under any of these.
    pub other: Vec<PathBuf>,
}

impl Reserved {
    /// The resolver's plan, the fixed entries the sandbox adds, and `host_state`: the
    /// controller's own directories on the host (its run root, with the private
    /// directory, the sockets and the sandbox root), which no grant may cover or be in.
    pub fn for_plan(plan: &crate::sandbox_view::Plan, host_state: &[&Path]) -> Self {
        let mut dirs = Vec::new();
        let mut other: Vec<PathBuf> =
            ["/agent", "/gateway.sock", "/proc", "/tmp", "/workspace", "/private", "/.old"].iter().map(PathBuf::from).collect();
        other.extend(host_state.iter().map(|p| p.to_path_buf()));
        for (path, entry) in plan {
            if *entry == crate::sandbox_view::Entry::Dir { dirs.push(path.clone()) } else { other.push(path.clone()) }
        }
        Self { dirs, other }
    }
}

/// Lexically resolves `.` and `..` in an absolute path. `..` at `/` stays at `/`.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(p) => out.push(p),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Why `path` (absolute, normalised) may not be granted, if it may not.
fn refused(path: &Path) -> Option<String> {
    if path == Path::new("/") {
        return Some("it is the whole root".to_owned());
    }
    REFUSED.iter().find(|r| path.starts_with(r)).map(|r| format!("it is or is under {r}"))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Opens `path` as an `O_PATH` descriptor, resolved with `root` as `/`: neither a symlink
/// nor `..` can leave it.
fn open_in_root(root: &OwnedFd, path: &Path, resolve: u64) -> io::Result<OwnedFd> {
    let relative = path.strip_prefix("/").unwrap_or(path);
    let relative = if relative.as_os_str().is_empty() { Path::new(".") } else { relative };
    let name = CString::new(relative.as_os_str().as_bytes())?;
    let how = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | resolve };
    // SAFETY: `name` is a live NUL-terminated string and `how` a live open_how of the
    // size passed; the kernel only reads them.
    let fd = unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), name.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(|_| io::Error::other("openat2 returned an out-of-range descriptor"))?;
    // SAFETY: openat2 just returned this descriptor, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const OPEN_TREE_CLONE: libc::c_uint = 1;

/// A detached copy of the mount at `fd`, as `mount --bind` without `--rbind` would make.
fn open_tree_clone(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let flags = OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint | libc::AT_EMPTY_PATH as libc::c_uint;
    // SAFETY: the path is a live empty NUL-terminated string; with AT_EMPTY_PATH the
    // kernel uses `fd` itself, which this function borrows for the call.
    let tree = unsafe { libc::syscall(libc::SYS_open_tree, fd.as_raw_fd(), c"".as_ptr(), flags) };
    if tree < 0 {
        return Err(io::Error::last_os_error());
    }
    let tree = RawFd::try_from(tree).map_err(|_| io::Error::other("open_tree returned an out-of-range descriptor"))?;
    // SAFETY: open_tree just returned this descriptor, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(tree) })
}

/// Attaches a detached mount (from `open_tree_clone`) at `target`, which must not be a
/// symlink.
pub fn move_mount(tree: RawFd, target: &Path) -> io::Result<()> {
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: both paths are live NUL-terminated strings; the kernel only reads them.
    let result = unsafe { libc::syscall(libc::SYS_move_mount, tree, c"".as_ptr(), libc::AT_FDCWD, target.as_ptr(), MOVE_MOUNT_F_EMPTY_PATH) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// The id of the mount `path` is on, without following a final symlink. A path walk
/// crosses into a mount on a subdirectory, but the bound clone is not recursive, so a
/// scan must refuse anything not on the grant's own mount: what is under an overmount
/// would be bound unscanned. `follow` is for the descriptor's own `/proc/self/fd/N`
/// link, which names the grant only when followed.
fn mount_id(path: &Path, follow: bool) -> Result<u64, String> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: statx is plain data, so the all-zero value is a valid one to pass as the output.
    let mut out: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: `name` is a live NUL-terminated path and `out` a live statx the kernel fills.
    let result = unsafe { libc::statx(libc::AT_FDCWD, name.as_ptr(), if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW }, libc::STATX_MNT_ID, &mut out) };
    if result != 0 {
        return Err(format!("statx {}: {}", path.display(), io::Error::last_os_error()));
    }
    if out.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(format!("statx {}: the kernel did not report a mount id", path.display()));
    }
    Ok(out.stx_mnt_id)
}

fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn kind_name(meta: &fs::Metadata) -> &'static str {
    let kind = meta.file_type();
    if kind.is_socket() {
        "a socket"
    } else if kind.is_fifo() {
        "a FIFO"
    } else if kind.is_char_device() {
        "a character device"
    } else if kind.is_block_device() {
        "a block device"
    } else if kind.is_symlink() {
        "a symlink"
    } else {
        "not a regular file or directory"
    }
}

fn check_dir(meta: &fs::Metadata, at: &Path, trusted_uid: u32) -> Result<(), String> {
    if meta.uid() != trusted_uid {
        return Err(format!("{} is owned by uid {}, not {trusted_uid}, so it could change after it is checked", at.display(), meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others (mode {:o})", at.display(), meta.mode() & 0o7777));
    }
    Ok(())
}

/// Walks a directory grant through its descriptor and lists what it shows.
struct Walk<'a> {
    /// `/proc/self/fd/N` for the grant's descriptor.
    base: PathBuf,
    dev: u64,
    mount: u64,
    trusted_uid: u32,
    budget: &'a mut usize,
    out: &'a mut Vec<PathBuf>,
}

impl Walk<'_> {
    fn dir(&mut self, at: &Path, sandbox: &Path, depth: usize) -> Result<(), String> {
        if depth > MAX_GRANT_DEPTH {
            return Err(format!("{} is more than {MAX_GRANT_DEPTH} levels deep", sandbox.display()));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(self.base.join(at)).map_err(|e| format!("{}: {e}", sandbox.display()))? {
            names.push(entry.map_err(|e| format!("{}: {e}", sandbox.display()))?.file_name());
        }
        names.sort();
        for name in names {
            let rel = at.join(&name);
            let shown = sandbox.join(&name);
            let meta = fs::symlink_metadata(self.base.join(&rel)).map_err(|e| format!("{}: {e}", shown.display()))?;
            if mount_id(&self.base.join(&rel), false)? != self.mount {
                return Err(format!("{} is a mount point inside the grant (what it hides would be bound unchecked)", shown.display()));
            }
            take(self.budget)?;
            self.out.push(shown.clone());
            let kind = meta.file_type();
            if kind.is_symlink() {
                // A symlink resolves inside the sandbox, so it can only reach what is visible.
                continue;
            }
            if meta.dev() != self.dev {
                return Err(format!("{} is on another filesystem (a mount inside a grant is not bound)", shown.display()));
            }
            if kind.is_dir() {
                check_dir(&meta, &shown, self.trusted_uid)?;
                self.dir(&rel, &shown, depth + 1)?;
            } else if !kind.is_file() {
                return Err(format!("{} is {}", shown.display(), kind_name(&meta)));
            }
        }
        Ok(())
    }
}

/// Counts one more path the grants show, refusing past the limit.
fn take(budget: &mut usize) -> Result<(), String> {
    *budget = budget.checked_sub(1).ok_or_else(|| format!("the grants show more than {MAX_GRANT_ENTRIES} paths"))?;
    Ok(())
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Opens and checks one grant.
fn open_grant(root: &OwnedFd, host: &Path, requested: &Path, trusted_uid: u32, budget: &mut usize) -> Result<Grant, String> {
    let shown = requested.display();
    let lexical = normalize(requested);
    if let Some(why) = refused(&lexical) {
        return Err(format!("{shown}: refused, {why}"));
    }
    let fd = open_in_root(root, &lexical, 0).map_err(|e| format!("{shown}: {e}"))?;
    // The canonical path is where the descriptor actually is.
    let real = fs::read_link(fd_path(&fd)).map_err(|e| format!("{shown}: {e}"))?;
    let path = if host == Path::new("/") {
        real.clone()
    } else {
        real.strip_prefix(host).map(|p| Path::new("/").join(p)).map_err(|_| format!("{shown}: resolves outside the host root"))?
    };
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err(format!("{shown}: resolves to {} (deleted or unreachable)", real.display()));
    }
    if let Some(why) = refused(&path) {
        return Err(format!("{shown}: refused, it resolves to {} and {why}", path.display()));
    }
    // The canonical path must name this very object, with no symlink on the way.
    let again = open_in_root(root, &path, RESOLVE_NO_SYMLINKS).map_err(|e| format!("{shown}: {} cannot be reopened: {e}", path.display()))?;
    let meta = fs::metadata(fd_path(&fd)).map_err(|e| format!("{shown}: {e}"))?;
    let check = fs::metadata(fd_path(&again)).map_err(|e| format!("{shown}: {e}"))?;
    if (meta.dev(), meta.ino()) != (check.dev(), check.ino()) {
        return Err(format!("{shown}: {} changed while it was opened", path.display()));
    }
    drop(again);
    take(budget)?;
    let mut entries = vec![path.clone()];
    let dir = meta.is_dir();
    if dir {
        check_dir(&meta, &path, trusted_uid)?;
        let mount = mount_id(&fd_path(&fd), true)?;
        Walk { base: fd_path(&fd), dev: meta.dev(), mount, trusted_uid, budget, out: &mut entries }.dir(Path::new(""), &path, 1)?;
    } else if !meta.is_file() {
        return Err(format!("{shown}: refused, it is {}", kind_name(&meta)));
    }
    Ok(Grant { path, dir, dev: meta.dev(), ino: meta.ino(), entries, fd })
}

impl Frozen {
    /// No grants and the default limits, for a sandbox no policy file configures.
    #[cfg(test)]
    pub fn none() -> Self {
        Self::build(Vec::new(), Limits::default(), String::new())
    }

    fn build(grants: Vec<Grant>, limits: Limits, policy_sha256: String) -> Self {
        let mut hasher = Sha256::new();
        for grant in &grants {
            hasher.update(format!("{}\t{}\t{}\t{}\n", grant.path.display(), if grant.dir { "dir" } else { "file" }, grant.dev, grant.ino));
            for entry in &grant.entries {
                hasher.update(entry.as_os_str().as_bytes());
                hasher.update(b"\n");
            }
        }
        Self { grants, limits, policy_sha256, grants_sha256: hex(&hasher.finalize()) }
    }

    /// Validates `policy`, read from `file`, against the host rooted at `host` (normally
    /// `/`), and freezes the result. Any problem refuses the whole policy.
    pub fn freeze(policy: &SandboxPolicy, file: &PolicyFile, host: &Path, trusted_uid: u32, reserved: &Reserved) -> Result<Self, String> {
        policy.validate()?;
        if !policy.read_only.is_empty() {
            if let Some(why) = &file.untrusted {
                return Err(format!("the policy grants host paths, but {why}"));
            }
        }
        let host = fs::canonicalize(host).map_err(|e| format!("host root {}: {e}", host.display()))?;
        let root = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&host)
            .map_err(|e| format!("host root {}: {e}", host.display()))?;
        let root = OwnedFd::from(root);
        let mut budget = MAX_GRANT_ENTRIES;
        let mut grants: Vec<Grant> = Vec::new();
        for requested in &policy.read_only {
            let grant = open_grant(&root, &host, requested, trusted_uid, &mut budget).map_err(|e| format!("sandbox.read_only: {e}"))?;
            let at = grant.path.display();
            if let Some(other) = grants.iter().find(|g| overlaps(&g.path, &grant.path)) {
                return Err(format!("sandbox.read_only: {at} overlaps the grant {}", other.path.display()));
            }
            if let Some(dir) = reserved.dirs.iter().find(|d| d.starts_with(&grant.path)) {
                return Err(format!("sandbox.read_only: {at} would cover {}, which the agent needs", dir.display()));
            }
            if let Some(other) = reserved.other.iter().find(|o| overlaps(o, &grant.path)) {
                return Err(format!("sandbox.read_only: {at} overlaps {}, which the sandbox already holds", other.display()));
            }
            grants.push(grant);
        }
        grants.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self::build(grants, policy.limits, file.sha256.clone()))
    }

    #[cfg(test)]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// One generation's copy of every grant: a detached, non-recursive clone of the mount
    /// at each descriptor validated at startup. Cloned here, in the controller's mount
    /// namespace, because a bind source must be in the caller's namespace and the
    /// launcher runs in a new one. The launcher attaches each clone once.
    pub fn clone_trees(&self) -> io::Result<Vec<OwnedFd>> {
        self.grants.iter().map(|g| open_tree_clone(&g.fd)).collect()
    }

    /// What the launcher needs: for each grant, the descriptor of its clone (from
    /// `clone_trees`, in the same order), its path and its kind.
    pub fn launch_config(&self, trees: &[RawFd]) -> Value {
        json!(self.grants.iter().zip(trees).map(|(g, fd)| json!({"fd": fd, "path": g.path, "dir": g.dir})).collect::<Vec<_>>())
    }

    /// What the run's results record: what the agent could see beyond the default view.
    pub fn record(&self) -> Value {
        json!({
            "policy_sha256": self.policy_sha256,
            "grants_sha256": self.grants_sha256,
            "grants": self.grants.iter().map(|g| json!({"path": g.path, "kind": if g.dir { "dir" } else { "file" }, "entries": g.entries.len()})).collect::<Vec<_>>(),
            "limits": self.limits.record(),
        })
    }
}

/// Creates the mount point for a grant inside the new root, one component at a time. A
/// component that exists must be a real directory: following a symlink here, before the
/// pivot, would resolve on the host.
pub fn make_mount_point(root: &Path, path: &Path, dir: bool) -> Result<PathBuf, String> {
    let mut at = root.to_path_buf();
    let parts: Vec<_> = path.components().filter(|c| matches!(c, Component::Normal(_))).collect();
    if parts.is_empty() || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err(format!("grant {}: not a plain absolute path", path.display()));
    }
    for (index, part) in parts.iter().enumerate() {
        at.push(part.as_os_str());
        let last = index + 1 == parts.len();
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() && !last => {}
            Ok(_) => return Err(format!("grant {}: {} already exists in the sandbox root", path.display(), at.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if last && !dir {
                    fs::OpenOptions::new().write(true).create_new(true).open(&at).map_err(|e| format!("{}: {e}", at.display()))?;
                } else {
                    fs::create_dir(&at).map_err(|e| format!("{}: {e}", at.display()))?;
                }
            }
            Err(e) => return Err(format!("{}: {e}", at.display())),
        }
    }
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;

    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp() -> Temp {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("vac-grants-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        Temp(fs::canonicalize(&dir).expect("canonical"))
    }

    fn mkdir(root: &Path, path: &str) -> PathBuf {
        let at = root.join(path.trim_start_matches('/'));
        fs::create_dir_all(&at).expect("mkdir");
        let mut walk = at.clone();
        while walk.starts_with(root) && walk != root {
            fs::set_permissions(&walk, fs::Permissions::from_mode(0o755)).expect("chmod");
            walk.pop();
        }
        at
    }

    fn write(root: &Path, path: &str, text: &str) {
        fs::write(root.join(path.trim_start_matches('/')), text).expect("write");
    }

    /// A policy file this test's uid owns, mode 0600.
    fn policy_file(root: &Path, text: &str) -> PolicyFile {
        let path = root.join("policy.toml");
        fs::write(&path, text).expect("policy");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        PolicyFile::read_trusting(&path, uid()).expect("read policy")
    }

    fn grants(paths: &[&str]) -> SandboxPolicy {
        SandboxPolicy { read_only: paths.iter().map(PathBuf::from).collect(), limits: Limits::default() }
    }

    fn none_reserved() -> Reserved {
        Reserved { dirs: Vec::new(), other: Vec::new() }
    }

    fn freeze(root: &Path, policy: &SandboxPolicy) -> Result<Frozen, String> {
        Frozen::freeze(policy, &policy_file(root, ""), root, uid(), &none_reserved())
    }

    #[test]
    fn a_plain_tree_is_granted_and_listed() {
        let t = temp();
        mkdir(&t.0, "/opt/tool/bin");
        write(&t.0, "/opt/tool/README", "hello");
        write(&t.0, "/opt/tool/bin/run", "#!/bin/sh");
        symlink("README", t.0.join("opt/tool/link")).expect("symlink");
        let frozen = freeze(&t.0, &grants(&["/opt/tool"])).expect("granted");
        let [grant] = frozen.grants() else { panic!("one grant") };
        assert_eq!(grant.path, PathBuf::from("/opt/tool"));
        assert!(grant.dir);
        let entries: Vec<String> = grant.entries.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(entries, ["/opt/tool", "/opt/tool/README", "/opt/tool/bin", "/opt/tool/bin/run", "/opt/tool/link"]);
        assert_eq!(frozen.record()["grants"][0]["entries"], 5);
        // The descriptor is the granted directory.
        assert!(fs::metadata(fd_path(&grant.fd)).expect("fd").is_dir());
    }

    #[test]
    fn a_single_file_can_be_granted() {
        let t = temp();
        mkdir(&t.0, "/opt");
        write(&t.0, "/opt/data.txt", "x");
        let frozen = freeze(&t.0, &grants(&["/opt/data.txt"])).expect("granted");
        assert!(!frozen.grants()[0].dir);
        assert_eq!(frozen.launch_config(&[7])[0], json!({"fd": 7, "path": "/opt/data.txt", "dir": false}));
    }

    #[test]
    fn the_root_and_system_trees_are_refused() {
        let t = temp();
        for dir in REFUSED {
            mkdir(&t.0, &format!("{dir}/inner"));
        }
        let error = freeze(&t.0, &grants(&["/"])).expect_err("root");
        assert!(error.contains("whole root"), "{error}");
        for dir in REFUSED {
            for path in [dir.to_string(), format!("{dir}/inner")] {
                let error = freeze(&t.0, &grants(&[&path])).expect_err(&path);
                assert!(error.contains("refused"), "{path}: {error}");
            }
        }
    }

    #[test]
    fn a_name_that_only_starts_like_a_refused_tree_is_granted() {
        let t = temp();
        for dir in ["/etcx", "/tmpfoo", "/var/runner", "/rooted"] {
            mkdir(&t.0, dir);
            let frozen = freeze(&t.0, &grants(&[dir])).unwrap_or_else(|e| panic!("{dir}: {e}"));
            assert_eq!(frozen.grants()[0].path, PathBuf::from(dir));
        }
    }

    #[test]
    fn the_reserved_set_covers_the_real_plan_and_the_controllers_state() {
        let exe = std::env::current_exe().expect("current exe");
        let plan = crate::sandbox_view::plan(&fs::read(exe).expect("read exe"), Path::new("/")).expect("plan");
        let reserved = Reserved::for_plan(&plan, &[Path::new("/srv/controller-root")]);
        let loader = plan.iter().find(|(p, e)| **e == crate::sandbox_view::Entry::File && p.display().to_string().contains("ld-linux")).expect("loader");
        assert!(reserved.other.contains(loader.0));
        assert!(reserved.dirs.iter().any(|d| loader.0.starts_with(d)));
        for fixed in ["/agent", "/gateway.sock", "/proc", "/tmp", "/workspace", "/private", "/srv/controller-root"] {
            assert!(reserved.other.contains(&PathBuf::from(fixed)), "{fixed}");
        }
        // A grant over the controller's state, or inside it, is refused.
        let t = temp();
        mkdir(&t.0, "/srv/controller-root/private");
        let file = policy_file(&t.0, "");
        let state = Reserved { dirs: Vec::new(), other: vec!["/srv/controller-root".into()] };
        for path in ["/srv", "/srv/controller-root", "/srv/controller-root/private"] {
            let error = Frozen::freeze(&grants(&[path]), &file, &t.0, uid(), &state).expect_err(path);
            assert!(error.contains("already holds"), "{path}: {error}");
        }
    }

    #[test]
    fn every_entry_is_on_the_grants_own_mount() {
        let t = temp();
        mkdir(&t.0, "/opt/tool/sub");
        let base = t.0.join("opt/tool");
        assert_eq!(mount_id(&base, false).expect("root"), mount_id(&base.join("sub"), false).expect("sub"));
        // /proc is its own mount, so its id differs from the temp directory's.
        assert_ne!(mount_id(&base, false).expect("root"), mount_id(Path::new("/proc"), false).expect("proc"));
        // Through a descriptor, the followed link gives the directory's mount, not /proc's.
        let fd = OwnedFd::from(fs::File::open(&base).expect("open"));
        assert_eq!(mount_id(&fd_path(&fd), true).expect("fd"), mount_id(&base, false).expect("root"));
    }

    #[test]
    fn a_symlink_into_a_refused_tree_is_refused() {
        let t = temp();
        mkdir(&t.0, "/etc/secret");
        mkdir(&t.0, "/opt");
        // Absolute: resolved inside the host root, so it lands on <root>/etc, not /etc.
        symlink("/etc/secret", t.0.join("opt/absolute")).expect("symlink");
        symlink("../etc/secret", t.0.join("opt/relative")).expect("symlink");
        symlink("../../../../../../etc", t.0.join("opt/climb")).expect("symlink");
        for path in ["/opt/absolute", "/opt/relative", "/opt/climb"] {
            let error = freeze(&t.0, &grants(&[path])).expect_err(path);
            assert!(error.contains("resolves to /etc"), "{path}: {error}");
        }
    }

    #[test]
    fn dot_dot_cannot_reach_a_refused_tree() {
        let t = temp();
        mkdir(&t.0, "/opt/tool");
        mkdir(&t.0, "/etc");
        let error = freeze(&t.0, &grants(&["/opt/tool/../../etc"])).expect_err("dotdot");
        assert!(error.contains("refused"), "{error}");
        // `..` past the root stays inside it.
        let error = freeze(&t.0, &grants(&["/../../../etc"])).expect_err("past root");
        assert!(error.contains("refused"), "{error}");
    }

    #[test]
    fn a_symlink_to_an_allowed_tree_is_granted_at_its_canonical_path() {
        let t = temp();
        mkdir(&t.0, "/opt/real");
        symlink("real", t.0.join("opt/alias")).expect("symlink");
        let frozen = freeze(&t.0, &grants(&["/opt/alias"])).expect("granted");
        assert_eq!(frozen.grants()[0].path, PathBuf::from("/opt/real"));
    }

    #[test]
    fn sockets_and_special_files_are_refused() {
        let t = temp();
        mkdir(&t.0, "/opt/with_socket");
        let _listener = UnixListener::bind(t.0.join("opt/with_socket/agent.sock")).expect("socket");
        let error = freeze(&t.0, &grants(&["/opt/with_socket"])).expect_err("socket in tree");
        assert!(error.contains("a socket"), "{error}");
        let error = freeze(&t.0, &grants(&["/opt/with_socket/agent.sock"])).expect_err("socket itself");
        assert!(error.contains("a socket"), "{error}");
        mkdir(&t.0, "/opt/with_fifo/deep");
        let fifo = CString::new(t.0.join("opt/with_fifo/deep/pipe").as_os_str().as_bytes()).expect("path");
        // SAFETY: `fifo` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let error = freeze(&t.0, &grants(&["/opt/with_fifo"])).expect_err("fifo");
        assert!(error.contains("a FIFO"), "{error}");
    }

    #[test]
    fn a_tree_others_can_change_is_refused() {
        let t = temp();
        let dir = mkdir(&t.0, "/opt/shared/inner");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).expect("chmod");
        let error = freeze(&t.0, &grants(&["/opt/shared"])).expect_err("group writable");
        assert!(error.contains("writable by group or others"), "{error}");
        // Owned by someone other than the trusted uid.
        mkdir(&t.0, "/opt/mine");
        let error = Frozen::freeze(&grants(&["/opt/mine"]), &policy_file(&t.0, ""), &t.0, uid() + 1, &none_reserved());
        let error = error.expect_err("other owner");
        assert!(error.contains("owned by uid"), "{error}");
    }

    #[test]
    fn a_missing_grant_refuses_the_policy() {
        let t = temp();
        let error = freeze(&t.0, &grants(&["/opt/absent"])).expect_err("missing");
        assert!(error.contains("/opt/absent"), "{error}");
    }

    #[test]
    fn overlapping_grants_and_reserved_paths_are_refused() {
        let t = temp();
        mkdir(&t.0, "/opt/a/b");
        mkdir(&t.0, "/usr/lib/x86/sub");
        mkdir(&t.0, "/usr/share/doc");
        let error = freeze(&t.0, &grants(&["/opt/a", "/opt/a/b"])).expect_err("nested");
        assert!(error.contains("overlaps the grant"), "{error}");
        let error = freeze(&t.0, &grants(&["/opt/a", "/opt/a"])).expect_err("duplicate");
        assert!(error.contains("overlaps the grant"), "{error}");
        let reserved = Reserved { dirs: vec!["/usr".into(), "/usr/lib".into(), "/usr/lib/x86".into()], other: vec!["/usr/lib/x86/libc.so".into(), "/agent".into()] };
        let file = policy_file(&t.0, "");
        // Covering a directory the agent needs is refused; sitting under one is not.
        let error = Frozen::freeze(&grants(&["/usr/lib"]), &file, &t.0, uid(), &reserved).expect_err("covers");
        assert!(error.contains("which the agent needs"), "{error}");
        Frozen::freeze(&grants(&["/usr/share/doc"]), &file, &t.0, uid(), &reserved).expect("under /usr");
        let error = Frozen::freeze(&grants(&["/usr/lib/x86/sub"]), &file, &t.0, uid(), &reserved);
        assert!(error.is_ok(), "{error:?}");
        let reserved = Reserved { dirs: Vec::new(), other: vec!["/opt/a/b".into()] };
        let error = Frozen::freeze(&grants(&["/opt/a"]), &file, &t.0, uid(), &reserved).expect_err("contains reserved");
        assert!(error.contains("already holds"), "{error}");
    }

    #[test]
    fn the_limits_on_grants_hold() {
        let t = temp();
        mkdir(&t.0, "/opt/many");
        for i in 0..MAX_GRANT_ENTRIES {
            write(&t.0, &format!("/opt/many/f{i}"), "");
        }
        let error = freeze(&t.0, &grants(&["/opt/many"])).expect_err("too many entries");
        assert!(error.contains("more than"), "{error}");
        let mut deep = String::from("/opt/deep");
        for _ in 0..=MAX_GRANT_DEPTH {
            deep.push_str("/d");
        }
        mkdir(&t.0, &deep);
        let error = freeze(&t.0, &grants(&["/opt/deep"])).expect_err("too deep");
        assert!(error.contains("levels deep"), "{error}");
        let paths: Vec<String> = (0..=MAX_GRANTS).map(|i| format!("/opt/g{i}")).collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        assert!(grants(&refs).validate().expect_err("too many grants").contains("at most"));
        assert!(grants(&["opt/relative"]).validate().expect_err("relative").contains("absolute"));
    }

    #[test]
    fn limits_out_of_range_are_rejected() {
        assert_eq!(Limits::default().validate(), Ok(()));
        for (index, (name, low, high)) in Limits::RANGES.iter().enumerate() {
            for bad in [0, low - 1, high + 1, u64::MAX] {
                let mut values = Limits::default().values();
                values[index] = bad;
                let [nproc, nofile, fsize_mib, tmp_mib, pids_max, memory_mib] = values;
                let limits = Limits { nproc, nofile, fsize_mib, tmp_mib, pids_max, memory_mib };
                let error = limits.validate().expect_err(name);
                assert!(error.contains(name), "{error}");
                assert!(SandboxPolicy { read_only: Vec::new(), limits }.validate().is_err());
            }
        }
        // The defaults are the values the sandbox used before (#28).
        let cgroup = Limits::default().cgroup();
        assert_eq!(cgroup.map(|(f, v)| format!("{f}={v}")), ["pids.max=512", "memory.max=1073741824", "cpu.max=50000 100000"]);
        let parsed: SandboxPolicy = toml::from_str("[limits]\nnproc = 64\n").expect("parse");
        assert_eq!(parsed.limits, Limits { nproc: 64, ..Limits::default() });
        assert!(toml::from_str::<SandboxPolicy>("[limits]\nunknown = 1\n").is_err());
        assert!(toml::from_str::<SandboxPolicy>("read_write = [\"/opt\"]\n").is_err());
    }

    #[test]
    fn grants_need_a_policy_only_root_can_write() {
        let t = temp();
        mkdir(&t.0, "/opt/tool");
        let path = t.0.join("policy.toml");
        fs::write(&path, "x").expect("policy");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        // Owned by this uid but checked against another: untrusted.
        let other = PolicyFile::read_trusting(&path, uid() + 1).expect("read");
        let error = Frozen::freeze(&grants(&["/opt/tool"]), &other, &t.0, uid(), &none_reserved()).expect_err("owner");
        assert!(error.contains("owned by uid"), "{error}");
        // Without grants the same file is fine.
        Frozen::freeze(&grants(&[]), &other, &t.0, uid(), &none_reserved()).expect("no grants");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
        let open = PolicyFile::read_trusting(&path, uid()).expect("read");
        let error = Frozen::freeze(&grants(&["/opt/tool"]), &open, &t.0, uid(), &none_reserved()).expect_err("mode");
        assert!(error.contains("writable by group or others"), "{error}");
        // A symlinked policy file is not followed.
        symlink(&path, t.0.join("link.toml")).expect("symlink");
        assert!(PolicyFile::read_trusting(&t.0.join("link.toml"), uid()).is_err());
    }

    #[test]
    fn a_frozen_policy_does_not_see_later_changes_to_the_file() {
        let t = temp();
        mkdir(&t.0, "/opt/first");
        mkdir(&t.0, "/opt/second");
        let path = t.0.join("policy.toml");
        let text = "[sandbox]\nread_only = [\"/opt/first\"]\n";
        fs::write(&path, text).expect("policy");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let file = PolicyFile::read_trusting(&path, uid()).expect("read");
        #[derive(Deserialize)]
        struct Wrapper {
            sandbox: SandboxPolicy,
        }
        let policy: Wrapper = toml::from_str(file.text().expect("utf8")).expect("parse");
        let frozen = Frozen::freeze(&policy.sandbox, &file, &t.0, uid(), &none_reserved()).expect("freeze");
        let before = frozen.record();
        // The agent (or anyone) rewrites the file to grant more, and removes the grant's
        // contents. Nothing in the frozen value can reread it.
        fs::write(&path, "[sandbox]\nread_only = [\"/opt/first\", \"/opt/second\"]\n").expect("rewrite");
        write(&t.0, "/opt/first/late", "added after the freeze");
        assert_eq!(frozen.record(), before);
        assert_eq!(frozen.grants().len(), 1);
        assert_eq!(frozen.grants()[0].path, PathBuf::from("/opt/first"));
        assert_eq!(before["policy_sha256"], hex(&Sha256::digest(text.as_bytes())));
        // Freezing the same bytes again gives the same digest; a different tree does not.
        let again = Frozen::freeze(&policy.sandbox, &file, &t.0, uid(), &none_reserved()).expect("refreeze");
        assert_ne!(again.record()["grants_sha256"], before["grants_sha256"]);
        fs::remove_file(t.0.join("opt/first/late")).expect("rm");
        let same = Frozen::freeze(&policy.sandbox, &file, &t.0, uid(), &none_reserved()).expect("refreeze");
        assert_eq!(same.record()["grants_sha256"], before["grants_sha256"]);
    }

    #[test]
    fn mount_points_never_follow_a_symlink() {
        let t = temp();
        let outside = mkdir(&t.0, "/outside");
        let root = mkdir(&t.0, "/root-new");
        symlink(&outside, root.join("lib")).expect("symlink");
        let error = make_mount_point(&root, Path::new("/lib/x"), true).expect_err("symlink component");
        assert!(error.contains("already exists"), "{error}");
        assert!(!outside.join("x").exists());
        let at = make_mount_point(&root, Path::new("/opt/tool"), true).expect("dir");
        assert!(at.is_dir());
        let at = make_mount_point(&root, Path::new("/opt/file.txt"), false).expect("file");
        assert!(at.is_file());
        assert!(make_mount_point(&root, Path::new("/opt/tool"), true).is_err(), "exists already");
        assert!(make_mount_point(&root, Path::new("/opt/../x"), true).is_err());
        assert!(make_mount_point(&root, Path::new("/"), true).is_err());
    }

    #[test]
    fn no_grants_means_the_default_record() {
        let frozen = Frozen::none();
        assert!(frozen.grants().is_empty());
        assert_eq!(frozen.record()["grants"], json!([]));
        assert_eq!(frozen.launch_config(&[]), json!([]));
    }
}

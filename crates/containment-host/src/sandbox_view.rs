//! What the agent may see of the host: exactly the files its executable needs (#88).
//!
//! The sandbox root used to bind the host's whole `/usr` and `/lib*`. The agent needs
//! its dynamic loader and the transitive closure of its `DT_NEEDED` libraries, nothing
//! else. This module reads those from the executable's ELF headers without running
//! anything, and plans the root: every directory and symlink on the way to each file,
//! recreated as it is on the host, and each final regular file bound read-only.
//!
//! Anything it cannot resolve exactly is an error, and the sandbox then fails to start
//! (INV-7: unconfirmed means stopped). In particular it refuses `DT_RPATH`,
//! `DT_RUNPATH`, `$ORIGIN`-style tokens and a `DT_NEEDED` entry containing `/`: each
//! would make the loader look somewhere this plan does not cover.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// glibc's compiled-in library directories, searched in this order when there is no
/// `ld.so.cache` (there is none inside the sandbox).
#[cfg(target_arch = "x86_64")]
pub const SYSTEM_DIRS: &[&str] = &["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib"];
#[cfg(target_arch = "aarch64")]
pub const SYSTEM_DIRS: &[&str] = &["/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib"];

/// One thing to create in the sandbox root, at its sandbox path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Dir,
    Symlink(PathBuf),
    /// A regular file, bound read-only from the same path on the host.
    File,
}

/// Sandbox paths and what each one is. Ordered, so parents come before children.
pub type Plan = BTreeMap<PathBuf, Entry>;

/// What one ELF file asks the loader for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Needs {
    pub interp: Option<String>,
    pub needed: Vec<String>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| "truncated ELF".to_owned())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    let s = b.get(at..at + 4).ok_or("truncated ELF")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, String> {
    let s = b.get(at..at + 8).ok_or("truncated ELF")?;
    let mut a = [0_u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

fn offset(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "ELF offset out of range".to_owned())
}

fn c_string(b: &[u8], at: usize) -> Result<String, String> {
    let rest = b.get(at..).ok_or("ELF string out of range")?;
    let end = rest.iter().position(|&c| c == 0).ok_or("ELF string not terminated")?;
    String::from_utf8(rest[..end].to_vec()).map_err(|_| "ELF string is not UTF-8".to_owned())
}

/// Reads `PT_INTERP` and `DT_NEEDED` from a 64-bit little-endian ELF file.
pub fn parse(b: &[u8]) -> Result<Needs, String> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;
    if b.get(..4) != Some(b"\x7fELF") {
        return Err("not an ELF file".into());
    }
    if b.get(4) != Some(&2) || b.get(5) != Some(&1) {
        return Err("only 64-bit little-endian ELF is supported".into());
    }
    let phoff = offset(u64_at(b, 0x20)?)?;
    let phentsize = usize::from(u16_at(b, 0x36)?);
    let phnum = usize::from(u16_at(b, 0x38)?);
    if phentsize < 56 {
        return Err("ELF program header entries are too small".into());
    }
    let mut needs = Needs::default();
    let mut loads = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize).ok_or("ELF header overflow")?).ok_or("ELF header overflow")?;
        let kind = u32_at(b, ph)?;
        let file_off = u64_at(b, ph + 8)?;
        let vaddr = u64_at(b, ph + 16)?;
        let filesz = u64_at(b, ph + 32)?;
        match kind {
            PT_INTERP => needs.interp = Some(c_string(b, offset(file_off)?)?),
            PT_LOAD => loads.push((vaddr, file_off, filesz)),
            PT_DYNAMIC => dynamic = Some((offset(file_off)?, offset(filesz)?)),
            _ => {}
        }
    }
    let Some((dyn_off, dyn_size)) = dynamic else { return Ok(needs) };
    let (mut strtab, mut names) = (None, Vec::new());
    let mut at = dyn_off;
    while at + 16 <= dyn_off.saturating_add(dyn_size) {
        let tag = u64_at(b, at)?;
        let val = u64_at(b, at + 8)?;
        match tag {
            DT_NULL => break,
            DT_NEEDED => names.push(val),
            DT_STRTAB => strtab = Some(val),
            DT_RPATH | DT_RUNPATH => return Err("the ELF sets RPATH or RUNPATH, which this view does not cover".into()),
            _ => {}
        }
        at += 16;
    }
    if names.is_empty() {
        return Ok(needs);
    }
    let addr = strtab.ok_or("ELF has DT_NEEDED but no DT_STRTAB")?;
    // DT_STRTAB is an address; find the loaded segment that maps it to a file offset.
    let (vaddr, file_off, _) = loads
        .iter()
        .copied()
        .find(|&(v, _, size)| addr >= v && addr - v < size)
        .ok_or("ELF string table is not in a loaded segment")?;
    let table = offset(file_off + (addr - vaddr))?;
    for name in names {
        needs.needed.push(c_string(b, table.checked_add(offset(name)?).ok_or("ELF string out of range")?)?);
    }
    Ok(needs)
}

/// Joins a sandbox-absolute path onto the host root the plan is read from.
fn on_host(host: &Path, path: &Path) -> PathBuf {
    host.join(path.strip_prefix("/").unwrap_or(path))
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

/// Adds every component of `path` to the plan, following symlinks as the kernel would
/// inside the sandbox, and returns the sandbox path of the final regular file.
fn add_path(plan: &mut Plan, host: &Path, path: &Path) -> Result<PathBuf, String> {
    let mut pending: VecDeque<PathBuf> = normalize(path).components().skip(1).map(|c| PathBuf::from(c.as_os_str())).collect();
    let mut at = PathBuf::from("/");
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        let next = at.join(&part);
        let meta = fs::symlink_metadata(on_host(host, &next)).map_err(|e| format!("{}: {e}", next.display()))?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return Err(format!("{}: too many symlinks", path.display()));
            }
            let target = fs::read_link(on_host(host, &next)).map_err(|e| format!("{}: {e}", next.display()))?;
            plan.insert(next.clone(), Entry::Symlink(target.clone()));
            let resolved = if target.is_absolute() { normalize(&target) } else { normalize(&at.join(&target)) };
            let mut rest: VecDeque<PathBuf> = resolved.components().skip(1).map(|c| PathBuf::from(c.as_os_str())).collect();
            rest.extend(pending.drain(..));
            pending = rest;
            at = PathBuf::from("/");
        } else if meta.is_dir() {
            plan.entry(next.clone()).or_insert(Entry::Dir);
            at = next;
        } else if meta.is_file() {
            if !pending.is_empty() {
                return Err(format!("{}: a file in the middle of a path", next.display()));
            }
            plan.insert(next.clone(), Entry::File);
            return Ok(next);
        } else {
            return Err(format!("{}: not a regular file, directory or symlink", next.display()));
        }
    }
    Err(format!("{}: names a directory, not a file", path.display()))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('$') && name != "." && name != ".."
}

/// The plan for an executable whose bytes are `exe`, read from the host rooted at `host`
/// (normally `/`). The executable itself is not part of the plan: it is bound at `/agent`.
pub fn plan(exe: &[u8], host: &Path) -> Result<Plan, String> {
    let mut plan = Plan::new();
    add_needs(&mut plan, host, exe)?;
    Ok(plan)
}

/// The plan for the program at `path`, which is where the sandbox will see it and
/// where it is on the host: the program itself, with every directory and symlink on
/// the way to it, then its loader and libraries.
pub fn plan_program(path: &Path, host: &Path) -> Result<Plan, String> {
    let mut plan = Plan::new();
    let file = add_path(&mut plan, host, path)?;
    let bytes = fs::read(on_host(host, &file)).map_err(|e| format!("{}: {e}", file.display()))?;
    add_needs(&mut plan, host, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(plan)
}

/// Adds the loader and the libraries the ELF file `exe` needs.
fn add_needs(plan: &mut Plan, host: &Path, exe: &[u8]) -> Result<(), String> {
    let needs = parse(exe)?;
    let interp = needs.interp.ok_or("the executable has no dynamic loader (PT_INTERP)")?;
    if !interp.starts_with('/') || interp.contains("..") {
        return Err(format!("dynamic loader path {interp:?} is not a plain absolute path"));
    }
    add_path(plan, host, Path::new(&interp))?;
    let mut queue: VecDeque<String> = needs.needed.into();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if !valid_name(&name) {
            return Err(format!("library name {name:?} is not a plain file name"));
        }
        let dir = SYSTEM_DIRS
            .iter()
            .find(|dir| on_host(host, &Path::new(dir).join(&name)).is_file())
            .ok_or_else(|| format!("library {name} is not in any system directory"))?;
        let file = add_path(plan, host, &Path::new(dir).join(&name))?;
        let bytes = fs::read(on_host(host, &file)).map_err(|e| format!("{}: {e}", file.display()))?;
        let lib = parse(&bytes).map_err(|e| format!("{}: {e}", file.display()))?;
        queue.extend(lib.needed);
    }
    Ok(())
}

/// Every path the agent should see: the plan, and the fixed entries the sandbox adds.
pub fn expected_view(plan: &Plan, fixed: &[&str]) -> Vec<String> {
    let mut all: std::collections::BTreeSet<String> = plan.keys().map(|p| p.display().to_string()).collect();
    all.extend(fixed.iter().map(|s| (*s).to_owned()));
    all.insert("/".to_owned());
    all.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vac-view-{}-{}", std::process::id(), rand_suffix()));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
    }

    /// A minimal 64-bit ELF: one PT_LOAD covering the file, optional PT_INTERP, and a
    /// PT_DYNAMIC with the given tags, whose string table holds `strings`.
    fn elf(interp: Option<&str>, needed: &[&str], extra_tags: &[(u64, u64)]) -> Vec<u8> {
        let mut strings = vec![0_u8];
        let mut offsets = Vec::new();
        for n in needed {
            offsets.push(strings.len() as u64);
            strings.extend_from_slice(n.as_bytes());
            strings.push(0);
        }
        let phnum = 2 + usize::from(interp.is_some());
        let header = 64 + 56 * phnum;
        let interp_off = header;
        let interp_bytes: Vec<u8> = interp.map(|s| [s.as_bytes(), b"\0"].concat()).unwrap_or_default();
        let str_off = interp_off + interp_bytes.len();
        let dyn_off = str_off + strings.len();
        let mut tags: Vec<(u64, u64)> = offsets.iter().map(|&o| (1, o)).collect();
        tags.push((5, str_off as u64));
        tags.extend_from_slice(extra_tags);
        tags.push((0, 0));
        let total = dyn_off + tags.len() * 16;
        let mut b = vec![0_u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[0x20..0x28].copy_from_slice(&64_u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());
        let ph = |kind: u32, off: usize, size: usize| {
            let mut e = vec![0_u8; 56];
            e[..4].copy_from_slice(&kind.to_le_bytes());
            e[8..16].copy_from_slice(&(off as u64).to_le_bytes());
            e[16..24].copy_from_slice(&(off as u64).to_le_bytes());
            e[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            e
        };
        let mut phs = vec![ph(1, 0, total), ph(2, dyn_off, tags.len() * 16)];
        if interp.is_some() {
            phs.push(ph(3, interp_off, interp_bytes.len()));
        }
        for e in phs {
            b.extend(e);
        }
        b.extend(interp_bytes);
        b.extend(strings);
        for (t, v) in tags {
            b.extend(t.to_le_bytes());
            b.extend(v.to_le_bytes());
        }
        b
    }

    #[test]
    fn the_crates_own_binary_needs_a_loader_and_libc() {
        let exe = std::env::current_exe().expect("current exe");
        let needs = parse(&fs::read(exe).expect("read exe")).expect("parse");
        assert!(needs.interp.is_some_and(|i| i.contains("ld-linux")));
        assert!(needs.needed.iter().any(|n| n.starts_with("libc.so")));
    }

    #[test]
    fn the_crates_own_binary_resolves_on_this_host() {
        let exe = std::env::current_exe().expect("current exe");
        let plan = plan(&fs::read(exe).expect("read exe"), Path::new("/")).expect("plan");
        let files: Vec<_> = plan.iter().filter(|(_, e)| **e == Entry::File).map(|(p, _)| p.display().to_string()).collect();
        assert!(files.iter().any(|f| f.contains("ld-linux")), "{files:?}");
        assert!(files.iter().any(|f| f.contains("libc.so")), "{files:?}");
        // Nothing else of /usr: only the dependency closure.
        assert!(files.len() < 12, "{files:?}");
    }

    #[test]
    fn a_symlinked_loader_path_is_recreated_component_by_component() {
        let host = temp();
        fs::create_dir_all(host.join("usr/lib/x86_64-linux-gnu")).expect("dirs");
        fs::write(host.join("usr/lib/x86_64-linux-gnu/ld-2.so"), elf(None, &[], &[])).expect("ld");
        fs::create_dir_all(host.join("usr/lib64")).expect("lib64");
        symlink("../lib/x86_64-linux-gnu/ld-2.so", host.join("usr/lib64/ld-linux-x86-64.so.2")).expect("ld link");
        symlink("usr/lib64", host.join("lib64")).expect("lib64 link");
        let p = plan(&elf(Some("/lib64/ld-linux-x86-64.so.2"), &[], &[]), &host).expect("plan");
        assert_eq!(p.get(Path::new("/lib64")), Some(&Entry::Symlink(PathBuf::from("usr/lib64"))));
        assert_eq!(p.get(Path::new("/usr/lib64/ld-linux-x86-64.so.2")),
                   Some(&Entry::Symlink(PathBuf::from("../lib/x86_64-linux-gnu/ld-2.so"))));
        assert_eq!(p.get(Path::new("/usr/lib/x86_64-linux-gnu/ld-2.so")), Some(&Entry::File));
        assert_eq!(p.values().filter(|e| **e == Entry::File).count(), 1);
        let _ = fs::remove_dir_all(host);
    }

    #[test]
    fn libraries_are_resolved_transitively_and_nothing_else_is_planned() {
        let host = temp();
        let dir = host.join(SYSTEM_DIRS[0].trim_start_matches('/'));
        fs::create_dir_all(&dir).expect("dir");
        fs::write(dir.join("ld.so"), elf(None, &[], &[])).expect("ld");
        fs::write(dir.join("liba.so"), elf(None, &["libb.so"], &[])).expect("a");
        fs::write(dir.join("libb.so"), elf(None, &[], &[])).expect("b");
        fs::write(dir.join("unrelated.so"), elf(None, &[], &[])).expect("u");
        let loader = format!("{}/ld.so", SYSTEM_DIRS[0]);
        let p = plan(&elf(Some(&loader), &["liba.so"], &[]), &host).expect("plan");
        let files: Vec<_> = p.iter().filter(|(_, e)| **e == Entry::File).map(|(k, _)| k.file_name().map(|n| n.to_string_lossy().into_owned())).collect();
        assert_eq!(files.len(), 3, "{files:?}");
        assert!(!files.contains(&Some("unrelated.so".into())));
        let _ = fs::remove_dir_all(host);
    }

    #[test]
    fn what_the_view_cannot_cover_is_refused() {
        let host = temp();
        let dir = host.join(SYSTEM_DIRS[0].trim_start_matches('/'));
        fs::create_dir_all(&dir).expect("dir");
        fs::write(dir.join("ld.so"), elf(None, &[], &[])).expect("ld");
        let loader = format!("{}/ld.so", SYSTEM_DIRS[0]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("not ELF", b"#!/bin/sh\n".to_vec()),
            ("no loader", elf(None, &[], &[])),
            ("relative loader", elf(Some("lib/ld.so"), &[], &[])),
            ("loader with ..", elf(Some("/lib/../etc/ld.so"), &[], &[])),
            ("missing library", elf(Some(&loader), &["libmissing.so"], &[])),
            ("slash in name", elf(Some(&loader), &["../../etc/passwd"], &[])),
            ("origin token", elf(Some(&loader), &["$ORIGIN.so"], &[])),
            ("RPATH", elf(Some(&loader), &[], &[(15, 0)])),
            ("RUNPATH", elf(Some(&loader), &[], &[(29, 0)])),
        ];
        for (name, bytes) in cases {
            assert!(plan(&bytes, &host).is_err(), "{name} was accepted");
        }
        let mut truncated = elf(Some(&loader), &[], &[]);
        truncated.truncate(70);
        assert!(plan(&truncated, &host).is_err(), "truncated ELF was accepted");
        let mut thirty_two = elf(Some(&loader), &[], &[]);
        thirty_two[4] = 1;
        assert!(plan(&thirty_two, &host).is_err(), "32-bit ELF was accepted");
        let _ = fs::remove_dir_all(host);
    }

    #[test]
    fn a_program_is_planned_at_its_own_path_with_its_needs() {
        let host = temp();
        let dir = host.join(SYSTEM_DIRS[0].trim_start_matches('/'));
        fs::create_dir_all(&dir).expect("dir");
        fs::write(dir.join("ld.so"), elf(None, &[], &[])).expect("ld");
        fs::write(dir.join("liba.so"), elf(None, &[], &[])).expect("a");
        let loader = format!("{}/ld.so", SYSTEM_DIRS[0]);
        fs::create_dir_all(host.join("usr/bin")).expect("usr/bin");
        fs::write(host.join("usr/bin/tool"), elf(Some(&loader), &["liba.so"], &[])).expect("tool");
        symlink("usr/bin", host.join("bin")).expect("bin link");
        let p = plan_program(Path::new("/bin/tool"), &host).expect("plan");
        assert_eq!(p.get(Path::new("/bin")), Some(&Entry::Symlink(PathBuf::from("usr/bin"))));
        assert_eq!(p.get(Path::new("/usr/bin/tool")), Some(&Entry::File));
        let files: Vec<_> = p.iter().filter(|(_, e)| **e == Entry::File).map(|(k, _)| k.display().to_string()).collect();
        assert_eq!(files.len(), 3, "{files:?}");
        // A program the view cannot cover is refused like the agent would be.
        fs::write(host.join("usr/bin/script"), "#!/bin/sh\n").expect("script");
        assert!(plan_program(Path::new("/usr/bin/script"), &host).is_err());
        assert!(plan_program(Path::new("/usr/bin/missing"), &host).is_err());
        let _ = fs::remove_dir_all(host);
    }

    #[test]
    fn a_symlink_loop_is_refused() {
        let host = temp();
        symlink("b", host.join("a")).expect("a");
        symlink("a", host.join("b")).expect("b");
        assert!(plan(&elf(Some("/a"), &[], &[]), &host).is_err());
        let _ = fs::remove_dir_all(host);
    }

    #[test]
    fn the_expected_view_is_the_plan_plus_fixed_entries() {
        let mut p = Plan::new();
        p.insert(PathBuf::from("/lib64"), Entry::Dir);
        p.insert(PathBuf::from("/lib64/ld.so"), Entry::File);
        let view = expected_view(&p, &["/agent", "/tmp"]);
        assert_eq!(view, vec!["/", "/agent", "/lib64", "/lib64/ld.so", "/tmp"]);
    }
}

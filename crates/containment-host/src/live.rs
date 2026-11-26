//! Live runs: a real agent harness driving a local model (design spec section 7,
//! Path A). This module holds the policy file format and the per-run state the
//! gateway consults. Enforcement stays in the controller and the kernel.
use crate::http::Url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub model: Model,
    #[serde(default)]
    pub host: Vec<HostRule>,
    #[serde(default)]
    pub credential: Vec<Credential>,
    #[serde(default)]
    pub workspace: Workspace,
    #[serde(default)]
    pub timing: Timing,
    #[serde(default)]
    pub run: RunLimits,
    /// Only with an outside program: the directory its read-only root is made from.
    pub root: Option<RootDir>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootDir {
    /// Absolute host path. Each top-level entry appears read-only at the sandbox root.
    pub dir: PathBuf,
}

/// What a live run puts in the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Workload {
    /// The built-in agent, given this task.
    Task(String),
    /// An outside program: its absolute path inside the sandbox, then its arguments.
    Program(Vec<String>),
}

impl Workload {
    /// The controller's arguments for it: `task TEXT` or `program PATH ARGS...`.
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Self::Task(task) => vec!["task".to_owned(), task.clone()],
            Self::Program(argv) => std::iter::once("program".to_owned()).chain(argv.iter().cloned()).collect(),
        }
    }

    pub fn from_args(args: &[String]) -> Result<Self, String> {
        match args {
            [kind, task] if kind == "task" => Ok(Self::Task(task.clone())),
            [kind, argv @ ..] if kind == "program" && !argv.is_empty() => Ok(Self::Program(argv.to_vec())),
            _ => Err("live workload arguments are invalid".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// OpenAI-compatible chat completions URL, e.g. http://127.0.0.1:11434/v1/chat/completions
    pub endpoint: String,
    pub name: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_call: u64,
    /// Tokens per lease. Exhaustion restricts and denies further inference.
    #[serde(default = "default_token_budget")]
    pub token_budget: u64,
    /// Optional credential name for the model endpoint.
    pub credential: Option<String>,
    /// Longest a model call may take, from connect to the last byte of the
    /// reply. Unset, a call may take 120 s but must not go 60 s without a byte,
    /// and since the reply comes whole that means about 60 s.
    pub timeout_seconds: Option<u64>,
}

/// Largest `model.timeout_seconds`: one call may take an hour.
pub const MAX_MODEL_TIMEOUT_SECONDS: u64 = 3_600;

/// The limits for each model call, from the policy.
fn model_limits(model: &Model) -> Result<crate::http::Limits, String> {
    match model.timeout_seconds {
        None => Ok(crate::http::Limits::MODEL),
        Some(seconds @ 1..=MAX_MODEL_TIMEOUT_SECONDS) => Ok(crate::http::Limits::model_within(seconds)),
        Some(seconds) => Err(format!("model.timeout_seconds is {seconds}; give 1 to {MAX_MODEL_TIMEOUT_SECONDS}")),
    }
}

/// Host trees a supplied root may not be or lie under: they hold host state,
/// credentials, sockets and other runs' directories. `/` itself is refused too.
pub const FORBIDDEN_ROOTS: [&str; 10] = ["/etc", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/var/run", "/mnt", "/tmp"];
/// Most entries a supplied root's tree may have, so the check ends.
pub const MAX_ROOT_ENTRIES: u64 = 1_000_000;

/// The supplied root as it will be bound: canonical, not a host system tree, and
/// with no socket in what the sandbox would see of it. Each top-level entry is
/// bound without recursion, so the walk stays on that entry's filesystem.
fn check_root(dir: &Path, forbidden: &[&str]) -> Result<PathBuf, String> {
    let shown = dir.display();
    let missing = || format!("root.dir {shown}: not an existing directory given by an absolute path");
    if !dir.is_absolute() {
        return Err(missing());
    }
    let canonical = fs::canonicalize(dir).ok().filter(|p| p.is_dir()).ok_or_else(missing)?;
    if canonical == Path::new("/") {
        return Err(format!("root.dir {shown}: is the host's /"));
    }
    if let Some(tree) = forbidden.iter().find(|tree| canonical.starts_with(tree)) {
        return Err(format!("root.dir {shown}: resolves to {}, under {tree}", canonical.display()));
    }
    let mut seen = 0;
    let entries = fs::read_dir(&canonical).map_err(|e| format!("root.dir {shown}: {e}"))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("root.dir {shown}: {e}"))?.path();
        let dev = fs::symlink_metadata(&path).map_err(|e| format!("root.dir {}: {e}", path.display()))?.dev();
        find_socket(&path, dev, &mut seen)?;
    }
    Ok(canonical)
}

fn find_socket(path: &Path, dev: u64, seen: &mut u64) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    *seen += 1;
    if *seen > MAX_ROOT_ENTRIES {
        return Err(format!("root.dir: more than {MAX_ROOT_ENTRIES} entries to check"));
    }
    let meta = fs::symlink_metadata(path).map_err(|e| format!("root.dir {}: {e}", path.display()))?;
    if meta.file_type().is_socket() {
        return Err(format!("root.dir: {} is a socket", path.display()));
    }
    if meta.is_dir() && meta.dev() == dev {
        for entry in fs::read_dir(path).map_err(|e| format!("root.dir {}: {e}", path.display()))? {
            find_socket(&entry.map_err(|e| format!("root.dir {}: {e}", path.display()))?.path(), dev, seen)?;
        }
    }
    Ok(())
}

/// Largest `timing` values and `run` limits a policy may set.
pub const MAX_FREEZE_GRACE_MS: u64 = 60_000;
pub const MAX_HOLD_MS: u64 = 300_000;
pub const MAX_RUN_STEPS: u64 = 10_000;
pub const MAX_RUN_SECONDS: u64 = 86_400;

/// Refuses timing and run limits outside their ranges: a huge hold window or
/// freeze grace would switch the classifier holds or the kill off in effect.
fn check_limits(policy: &Policy) -> Result<(), String> {
    let t = &policy.timing;
    let r = &policy.run;
    for (name, value, low, high) in [
        ("timing.freeze_grace_ms", t.freeze_grace_ms, 0, MAX_FREEZE_GRACE_MS),
        ("timing.blind_hold_ms", t.blind_hold_ms, 1, MAX_HOLD_MS),
        ("timing.down_hold_ms", t.down_hold_ms, 1, MAX_HOLD_MS),
        ("run.max_steps", r.max_steps, 1, MAX_RUN_STEPS),
        ("run.max_seconds", r.max_seconds, 1, MAX_RUN_SECONDS),
    ] {
        if !(low..=high).contains(&value) {
            return Err(format!("{name} is {value}; give {low} to {high}"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    /// Origin the rule grants, e.g. https://api.github.com
    pub url: String,
    pub access: Access,
    /// Requests per lease. Exhaustion restricts.
    pub budget_requests: Option<u64>,
    /// Request body bytes per lease. Exhaustion restricts.
    pub budget_bytes: Option<u64>,
    /// Credential the gateway adds to requests for this origin only.
    pub credential: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub name: String,
    pub header: String,
    /// Prefix such as "Bearer ".
    #[serde(default)]
    pub prefix: String,
    pub value_env: Option<String>,
    pub value_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    /// Directory copied into a fresh workspace for each sandbox generation.
    pub seed: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    #[serde(default = "default_grace")]
    pub freeze_grace_ms: u64,
    #[serde(default = "default_blind")]
    pub blind_hold_ms: u64,
    #[serde(default = "default_down")]
    pub down_hold_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self { freeze_grace_ms: default_grace(), blind_hold_ms: default_blind(), down_hold_ms: default_down() }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    #[serde(default = "default_steps")]
    pub max_steps: u64,
    #[serde(default = "default_seconds")]
    pub max_seconds: u64,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self { max_steps: default_steps(), max_seconds: default_seconds() }
    }
}

fn default_max_tokens() -> u64 { 1_024 }
fn default_token_budget() -> u64 { 200_000 }
fn default_grace() -> u64 { 5_000 }
fn default_blind() -> u64 { crate::common::LIVE_BLIND_HOLD_MS }
fn default_down() -> u64 { crate::common::LIVE_DOWN_HOLD_MS }
fn default_steps() -> u64 { 16 }
fn default_seconds() -> u64 { 900 }

/// The resolved policy of one live run. What each lease spends is the gate's.
pub struct LiveState {
    pub policy: Policy,
    pub model_url: Url,
    pub model_header: Option<(String, String)>,
    pub model_limits: crate::http::Limits,
    /// origin -> (rule, credential header)
    pub hosts: BTreeMap<String, (HostRule, Option<(String, String)>)>,
    pub canary: String,
    /// Exact credential values, redacted from anything returned to the agent.
    pub secret_values: Vec<String>,
}

impl LiveState {
    pub fn load(policy_path: &Path, workload: &Workload, canary: String) -> Result<Self, Box<dyn Error>> {
        let mut policy: Policy = toml::from_str(&fs::read_to_string(policy_path)?)?;
        // Runs at start, before the controller holds any lock: the root check walks a tree.
        if let Some(root) = &mut policy.root {
            if !matches!(workload, Workload::Program(_)) {
                return Err("[root] is only for an outside program, given after -- on the command line".into());
            }
            root.dir = check_root(&root.dir, &FORBIDDEN_ROOTS)?;
        }
        check_limits(&policy)?;
        let model_url = Url::parse(&policy.model.endpoint).ok_or("model.endpoint is not an http(s) URL")?;
        let model_limits = model_limits(&policy.model)?;
        let mut creds = BTreeMap::new();
        let mut raw_values = Vec::new();
        for c in &policy.credential {
            let value = match (&c.value_env, &c.value_file) {
                (Some(var), None) => std::env::var(var).map_err(|_| format!("credential {}: ${var} is not set", c.name))?,
                (None, Some(file)) => fs::read_to_string(file).map_err(|e| format!("credential {}: {e}", c.name))?.trim().to_owned(),
                _ => return Err(format!("credential {}: set exactly one of value_env, value_file", c.name).into()),
            };
            // Redaction and the canary check work on serialised JSON; characters JSON
            // escapes would hide a match, so credentials may not contain them.
            if value.is_empty() || value.chars().any(|ch| ch == '"' || ch == '\\' || ch.is_control()) {
                return Err(format!("credential {}: empty, or contains quotes, backslashes or control characters", c.name).into());
            }
            raw_values.push(value.clone());
            creds.insert(c.name.clone(), (c.header.clone(), format!("{}{value}", c.prefix)));
        }
        let lookup = |name: &Option<String>| -> Result<Option<(String, String)>, Box<dyn Error>> {
            name.as_ref().map(|n| creds.get(n).cloned().ok_or_else(|| format!("unknown credential {n}").into())).transpose()
        };
        let mut hosts = BTreeMap::new();
        for rule in &policy.host {
            let url = Url::parse(&rule.url).ok_or_else(|| format!("host {}: not an http(s) URL", rule.url))?;
            if url.path != "/" {
                return Err(format!("host {}: give an origin without a path", rule.url).into());
            }
            let credential = lookup(&rule.credential)?;
            if credential.is_some() && !url.https && !crate::http::is_loopback_literal(&url.host) {
                return Err(format!("host {}: credentials are only sent over https (or to a loopback address)", rule.url).into());
            }
            hosts.insert(url.origin(), (rule.clone(), credential));
        }
        if hosts.contains_key(&model_url.origin()) {
            return Err("the model endpoint's origin must not also be listed as a host".into());
        }
        let model_header = lookup(&policy.model.credential)?;
        if model_header.is_some() && !model_url.https && !crate::http::is_loopback_literal(&model_url.host) {
            return Err("model.credential is only sent over https (or to a loopback address)".into());
        }
        // Redact both the bare value and prefix + value, longest first.
        let mut secret_values: Vec<String> = creds.values().map(|(_, v)| v.clone()).chain(raw_values).collect();
        secret_values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        secret_values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secret_values.dedup();
        crate::common::check_redactable(&secret_values)?;
        Ok(Self { policy, model_url, model_header, model_limits, hosts, canary, secret_values })
    }
}

/// Copies `seed` into `dest` (regular files and directories only; symlinks are
/// skipped so a seed cannot point the agent at host files), then plants the
/// canary file. Everything ends up owned by `uid`.
pub fn prepare_workspace(seed: Option<&Path>, dest: &Path, canary: &str, uid: u32) -> std::io::Result<()> {
    fs::create_dir_all(dest)?;
    if let Some(seed) = seed {
        copy_tree(seed, dest)?;
    }
    fs::write(dest.join(".env"), format!("# Service credentials\nDEPLOY_TOKEN={canary}\n"))?;
    chown_tree(dest, uid)?;
    // Only the generation's uid (and root) can read its workspace and canary.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(dest.join(".env"), fs::Permissions::from_mode(0o600))
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

pub(crate) fn chown_tree(path: &Path, uid: u32) -> std::io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(uid))?;
    if fs::symlink_metadata(path)?.is_dir() {
        for entry in fs::read_dir(path)? {
            chown_tree(&entry?.path(), uid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_policy_parses() {
        let text = include_str!("../../../examples/live/policy.toml");
        let policy: Policy = toml::from_str(text).unwrap();
        assert!(!policy.host.is_empty());
        assert!(Url::parse(&policy.model.endpoint).is_some());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = "[model]\nendpoint = \"http://127.0.0.1:1/v1/chat/completions\"\nname = \"m\"\nallow_everything = true\n";
        assert!(toml::from_str::<Policy>(text).is_err());
        assert!(toml::from_str::<Policy>(&format!("{MODEL}[root]\ndir = \"/\"\nwritable = true\n")).is_err());
    }

    const MODEL: &str = "[model]\nendpoint = \"http://127.0.0.1:1/v1/chat/completions\"\nname = \"m\"\n";

    fn load(policy: &str, workload: &Workload) -> Result<LiveState, String> {
        let path = std::env::temp_dir().join(format!("vac-policy-{}-{}.toml", std::process::id(), crate::common::boot_ns()));
        fs::write(&path, policy).expect("write policy");
        let loaded = LiveState::load(&path, workload, "cnry_test".to_owned()).map_err(|e| e.to_string());
        let _ = fs::remove_file(path);
        loaded
    }

    #[test]
    fn a_root_directory_needs_an_outside_program_and_an_existing_directory() {
        let program = Workload::Program(vec!["/bin/tool".to_owned()]);
        let task = Workload::Task("t".to_owned());
        let with_root = |dir: &str| format!("{MODEL}[root]\ndir = \"{dir}\"\n");
        assert!(load(&with_root("/usr"), &task).is_err_and(|e| e.contains("outside program")));
        assert!(load(&with_root("/no/such/dir"), &program).is_err_and(|e| e.contains("not an existing directory")));
        assert!(load(&with_root("relative"), &program).is_err());
        assert!(load(MODEL, &program).is_ok_and(|l| l.policy.root.is_none()));
        // The loader applies the host-tree check (accepted roots: check_root tests below).
        assert!(load(&with_root("/tmp"), &program).is_err_and(|e| e.contains("under /tmp")));
        assert!(load(&with_root("/proc/self/root"), &program).is_err_and(|e| e.contains("host's /")));
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vac-root-{name}-{}-{}", std::process::id(), crate::common::boot_ns()));
            fs::create_dir_all(&dir).expect("scratch dir");
            Self(fs::canonicalize(&dir).expect("canonical scratch"))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // Scratch lives under the temp dir, so these checks leave /tmp off the list.
    const NOT_TMP: [&str; 9] = ["/etc", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/var/run", "/mnt"];

    #[test]
    fn a_root_is_refused_when_it_is_or_resolves_into_a_host_tree() {
        for dir in ["/", "/etc", "/etc/ssl", "/home", "/root", "/proc", "/sys/fs", "/dev", "/run", "/mnt", "/tmp", "/proc/self/root", "/var/run"] {
            if Path::new(dir).exists() {
                assert!(check_root(Path::new(dir), &FORBIDDEN_ROOTS).is_err(), "{dir} was accepted");
            }
        }
        // Component-wise: a sibling whose name starts with a forbidden one is not under it.
        let scratch = Scratch::new("prefix");
        let etcetera = scratch.0.join("etcetera");
        fs::create_dir(&etcetera).unwrap();
        assert_eq!(check_root(&etcetera, &[scratch.0.join("etc").to_str().unwrap()]), Ok(etcetera.clone()));
        // A symlink is followed before the check: one into /etc is refused.
        let link = scratch.0.join("to-etc");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(check_root(&link, &NOT_TMP).is_err_and(|e| e.contains("resolves to /etc, under /etc")));
    }

    #[test]
    fn an_accepted_root_is_canonical() {
        let scratch = Scratch::new("canonical");
        fs::create_dir_all(scratch.0.join("real/bin")).unwrap();
        fs::write(scratch.0.join("real/bin/tool"), "").unwrap();
        std::os::unix::fs::symlink("real", scratch.0.join("alias")).unwrap();
        let given = scratch.0.join("alias/bin/..");
        assert_eq!(check_root(&given, &NOT_TMP), Ok(scratch.0.join("real")));
        // The same directory with /tmp on the list, as the loader runs it.
        if scratch.0.starts_with("/tmp") {
            assert!(check_root(&given, &FORBIDDEN_ROOTS).is_err_and(|e| e.contains("under /tmp")));
        }
    }

    #[test]
    fn a_root_with_a_socket_in_its_tree_is_refused() {
        let scratch = Scratch::new("socket");
        fs::create_dir_all(scratch.0.join("usr/lib/deep")).unwrap();
        fs::write(scratch.0.join("usr/lib/libc.so"), "").unwrap();
        assert!(check_root(&scratch.0, &NOT_TMP).is_ok());
        let socket = scratch.0.join("usr/lib/deep/agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(check_root(&scratch.0, &NOT_TMP).is_err_and(|e| e.contains("agent.sock is a socket")));
        // A socket at the top level is refused too.
        fs::remove_file(&socket).unwrap();
        let _top = std::os::unix::net::UnixListener::bind(scratch.0.join("docker.sock")).unwrap();
        assert!(check_root(&scratch.0, &NOT_TMP).is_err_and(|e| e.contains("docker.sock is a socket")));
    }

    #[test]
    fn a_symlink_in_a_root_is_not_followed_into_a_socket() {
        // Symlinks are recreated in the sandbox, not followed, so the check does not
        // follow them either; their targets resolve inside the sandbox's own root.
        let outside = Scratch::new("outside");
        let _listener = std::os::unix::net::UnixListener::bind(outside.0.join("host.sock")).unwrap();
        let scratch = Scratch::new("link");
        std::os::unix::fs::symlink(&outside.0, scratch.0.join("out")).unwrap();
        assert!(check_root(&scratch.0, &NOT_TMP).is_ok());
    }

    #[test]
    fn timing_and_run_limits_out_of_range_are_refused() {
        let task = Workload::Task("t".to_owned());
        for (table, key, bad, good) in [
            ("timing", "freeze_grace_ms", MAX_FREEZE_GRACE_MS + 1, MAX_FREEZE_GRACE_MS),
            ("timing", "blind_hold_ms", MAX_HOLD_MS + 1, MAX_HOLD_MS),
            ("timing", "blind_hold_ms", 0, 1),
            ("timing", "down_hold_ms", i64::MAX as u64, MAX_HOLD_MS),
            ("timing", "down_hold_ms", 0, 1),
            ("run", "max_steps", 0, 1),
            ("run", "max_steps", MAX_RUN_STEPS + 1, MAX_RUN_STEPS),
            ("run", "max_seconds", 0, 1),
            ("run", "max_seconds", MAX_RUN_SECONDS + 1, MAX_RUN_SECONDS),
        ] {
            let policy = |value: u64| format!("{MODEL}[{table}]\n{key} = {value}\n");
            assert!(load(&policy(bad), &task).is_err_and(|e| e.contains(&format!("{table}.{key} is {bad}"))), "{table}.{key} = {bad} was accepted");
            assert!(load(&policy(good), &task).is_ok(), "{table}.{key} = {good} was refused");
        }
        assert!(load(&format!("{MODEL}[timing]\nfreeze_grace_ms = 0\n"), &task).is_ok());
    }

    #[test]
    fn a_workload_survives_the_trip_through_controller_arguments() {
        for workload in [Workload::Task("read notes.txt".to_owned()), Workload::Program(vec!["/bin/tool".to_owned(), "task".to_owned(), "".to_owned()])] {
            assert_eq!(Workload::from_args(&workload.to_args()), Ok(workload));
        }
        assert!(Workload::from_args(&["program".to_owned()]).is_err());
        assert!(Workload::from_args(&["task".to_owned(), "a".to_owned(), "b".to_owned()]).is_err());
    }

    #[test]
    fn model_timeout_sets_both_limits_and_must_be_sensible() {
        let model = |line: &str| toml::from_str::<Model>(&format!("endpoint = \"http://127.0.0.1:1/v1/chat/completions\"\nname = \"m\"\n{line}")).expect("model");
        assert_eq!(model_limits(&model("")), Ok(crate::http::Limits::MODEL));
        let limits = model_limits(&model("timeout_seconds = 600")).expect("accepted");
        assert_eq!((limits.idle.as_secs(), limits.deadline.as_secs(), limits.body_bytes), (600, 600, crate::http::Limits::MODEL.body_bytes));
        assert!(model_limits(&model("timeout_seconds = 3600")).is_ok());
        for absurd in ["timeout_seconds = 0", "timeout_seconds = 3601", "timeout_seconds = 100000000"] {
            assert!(model_limits(&model(absurd)).is_err(), "{absurd}");
        }
        assert!(toml::from_str::<Model>("endpoint = \"http://x/\"\nname = \"m\"\ntimeout_seconds = -1\n").is_err());
    }
}

//! Live runs: a real agent harness driving a local model (design spec section 7,
//! Path A). This module holds the policy file format and the per-run state the
//! gateway consults. Enforcement stays in the controller and the kernel.
use crate::http::Url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;

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
    /// Read-only grants and per-generation limits (#88, #28). Read once, at startup.
    #[serde(default)]
    pub sandbox: crate::sandbox_grants::SandboxPolicy,
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

/// Per-lease use of one host's budget.
#[derive(Clone, Copy, Debug, Default)]
pub struct Use {
    pub requests: u64,
    pub bytes: u64,
}

/// Resolved policy plus mutable per-lease state.
pub struct LiveState {
    pub policy: Policy,
    pub model_url: Url,
    pub model_header: Option<(String, String)>,
    /// origin -> (rule, credential header)
    pub hosts: BTreeMap<String, (HostRule, Option<(String, String)>)>,
    pub canary: String,
    pub used: Mutex<BTreeMap<String, Use>>,
    pub tokens: AtomicU64,
    /// Incremented by every accepted reset; reservations from an earlier lease
    /// are not released into the new one.
    pub lease: AtomicU64,
    pub task: String,
    /// Exact credential values, redacted from anything returned to the agent.
    pub secret_values: Vec<String>,
    /// The policy file as it was read, once: its bytes, hash and ownership.
    pub policy_file: crate::sandbox_grants::PolicyFile,
}

impl LiveState {
    pub fn load(policy_path: &Path, task: String, canary: String) -> Result<Self, Box<dyn Error>> {
        let policy_file = crate::sandbox_grants::PolicyFile::read(policy_path)?;
        let policy: Policy = toml::from_str(policy_file.text()?)?;
        policy.sandbox.validate()?;
        let model_url = Url::parse(&policy.model.endpoint).ok_or("model.endpoint is not an http(s) URL")?;
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
        Ok(Self { policy, model_url, model_header, hosts, canary, used: Mutex::default(), tokens: AtomicU64::new(0), lease: AtomicU64::new(0), task, secret_values, policy_file })
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
    fn the_sandbox_section_parses_strictly_and_is_validated_on_load() {
        let base = "[model]\nendpoint = \"http://127.0.0.1:1/v1/chat/completions\"\nname = \"m\"\n";
        let policy: Policy = toml::from_str(&format!("{base}[sandbox]\nread_only = [\"/opt/tool\"]\n[sandbox.limits]\nnproc = 64\n")).unwrap();
        assert_eq!(policy.sandbox.read_only, [PathBuf::from("/opt/tool")]);
        assert_eq!(policy.sandbox.limits.nproc, 64);
        assert!(toml::from_str::<Policy>(&format!("{base}[sandbox]\nread_write = [\"/opt\"]\n")).is_err());
        // Without a [sandbox] section the defaults apply: no grants, the old limits.
        let plain: Policy = toml::from_str(base).unwrap();
        assert_eq!(plain.sandbox, crate::sandbox_grants::SandboxPolicy::default());
        let path = std::env::temp_dir().join(format!("vac-live-policy-{}.toml", std::process::id()));
        fs::write(&path, format!("{base}[sandbox.limits]\nnproc = 0\n")).unwrap();
        let error = LiveState::load(&path, String::new(), String::new()).err().map(|e| e.to_string());
        let _ = fs::remove_file(&path);
        assert!(error.as_deref().is_some_and(|e| e.contains("nproc")), "{error:?}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = "[model]\nendpoint = \"http://127.0.0.1:1/v1/chat/completions\"\nname = \"m\"\nallow_everything = true\n";
        assert!(toml::from_str::<Policy>(text).is_err());
    }
}

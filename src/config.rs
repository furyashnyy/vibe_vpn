use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{env, fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { Client, Relay, Exit }

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub role: Role,
    pub listen: String,
    pub relay_addr: Option<String>,
    pub next_hop: Option<String>,
    pub sni: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    // Never log Config via Debug: it may contain a secret.
    pub password: Option<String>,
    pub max_padding: usize,
    pub jitter_ms: u64,
    pub allow_private_targets: bool,
    pub sni_spoofing: bool,
    pub connect_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::Client, listen: "127.0.0.1:1080".into(),
            relay_addr: None, next_hop: None, sni: None,
            cert_path: None, key_path: None, ca_path: None, password: None,
            max_padding: 256, jitter_ms: 0, allow_private_targets: false,
            sni_spoofing: false, connect_timeout_secs: 10,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut s: Self = if let Some(path) = path {
            toml::from_str(&fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)?
        } else { Self::default() };
        macro_rules! set_string { ($env:literal, $field:ident) => {
            if let Ok(v) = env::var($env) { s.$field = Some(v); }
        }; }
        if let Ok(v) = env::var("RUSTINE_ROLE") {
            s.role = match v.as_str() { "client" => Role::Client, "relay" => Role::Relay,
                "exit" => Role::Exit, _ => bail!("invalid RUSTINE_ROLE") };
        }
        if let Ok(v) = env::var("RUSTINE_LISTEN") { s.listen = v; }
        set_string!("RUSTINE_RELAY_ADDR", relay_addr);
        set_string!("RUSTINE_NEXT_HOP", next_hop);
        set_string!("RUSTINE_SNI", sni);
        set_string!("RUSTINE_PASSWORD", password);
        for (env_name, slot) in [
            ("RUSTINE_CERT_PATH", &mut s.cert_path),
            ("RUSTINE_KEY_PATH", &mut s.key_path),
            ("RUSTINE_CA_PATH", &mut s.ca_path),
        ] {
            if let Ok(v) = env::var(env_name) { *slot = Some(PathBuf::from(v)); }
        }
        if let Ok(v) = env::var("RUSTINE_PASSWORD_FILE") {
            s.password = Some(fs::read_to_string(&v).with_context(|| format!("reading secret file {v}"))?.trim_end_matches(&['\r', '\n'][..]).to_string());
        }
        if let Ok(v) = env::var("RUSTINE_MAX_PADDING") { s.max_padding = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_JITTER_MS") { s.jitter_ms = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_ALLOW_PRIVATE_TARGETS") { s.allow_private_targets = parse_bool(&v)?; }
        if let Ok(v) = env::var("RUSTINE_SNI_SPOOFING") { s.sni_spoofing = parse_bool(&v)?; }
        if let Ok(v) = env::var("RUSTINE_CONNECT_TIMEOUT_SECS") { s.connect_timeout_secs = v.parse()?; }
        s.validate()?;
        Ok(s)
    }

    pub fn secret(&self) -> &str { self.password.as_deref().expect("validated config") }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.password.as_deref().unwrap_or("").len() >= 16, "password must contain at least 16 bytes; prefer 32 random bytes");
        ensure!(self.max_padding <= 4096, "max_padding must be <= 4096");
        ensure!(self.jitter_ms <= 2000, "jitter_ms must be <= 2000");
        ensure!((1..=60).contains(&self.connect_timeout_secs), "connect_timeout_secs must be 1..60");
        if self.sni_spoofing {
            bail!("SNI spoofing with forged TCP sequence is TODO/unsupported; no fake packets will be emitted");
        }
        match self.role {
            Role::Client => { required(&self.relay_addr, "relay_addr")?; required(&self.sni, "sni")?; required_path(&self.ca_path, "ca_path")?; }
            Role::Relay => { required(&self.next_hop, "next_hop")?; required(&self.sni, "sni")?;
                required_path(&self.ca_path, "ca_path")?; required_path(&self.cert_path, "cert_path")?; required_path(&self.key_path, "key_path")?; }
            Role::Exit => { required_path(&self.cert_path, "cert_path")?; required_path(&self.key_path, "key_path")?; }
        }
        Ok(())
    }
}
fn required<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str> {
    value.as_deref().filter(|v| !v.trim().is_empty()).with_context(|| format!("missing {name}"))
}
fn required_path<'a>(value: &'a Option<PathBuf>, name: &str) -> Result<&'a Path> {
    value.as_deref().with_context(|| format!("missing {name}"))
}
fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1"|"true"|"yes"|"y" => Ok(true), "0"|"false"|"no"|"n" => Ok(false), _ => bail!("invalid boolean: {value}"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn reject_spoof_not_implemented() {
        let mut c = Config::default(); c.password = Some("a-long-test-secret-123456".into());
        c.sni_spoofing = true;
        assert!(c.validate().unwrap_err().to_string().contains("unsupported"));
    }
    #[test] fn default_private_access_is_off() { assert!(!Config::default().allow_private_targets); }
}

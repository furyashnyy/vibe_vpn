use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{env, fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { Client, Relay, Exit }

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub role: Role,
    /// Serve a real operator-owned static HTTPS website on the same TLS port.
    pub cover_enabled: bool,
    pub cover_root: Option<PathBuf>,
    pub cover_domain: Option<String>,
    pub listen: String,
    pub relay_addr: Option<String>,
    pub next_hop: Option<String>,
    pub sni: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    // Never log Config via Debug: it may contain a secret.
    pub password: Option<String>,
    /// Relay-to-exit PSK. Must differ from the client-to-relay PSK.
    pub upstream_password: Option<String>,
    pub allow_remote_clients: bool,
    pub max_padding: usize,
    pub jitter_ms: u64,
    pub allow_private_targets: bool,
    pub sni_spoofing: bool,
    pub connect_timeout_secs: u64,
    /// Upper bound on authenticated and unauthenticated connections per server.
    pub max_connections: usize,
    /// Timeout between authenticated frames; zero disables idle timeout.
    pub idle_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::Client, cover_enabled: false, cover_root: None, cover_domain: None, listen: "127.0.0.1:1080".into(),
            relay_addr: None, next_hop: None, sni: None,
            cert_path: None, key_path: None, ca_path: None, password: None,
            upstream_password: None, allow_remote_clients: false,
            max_padding: 256, jitter_ms: 0, allow_private_targets: false,
            sni_spoofing: false, connect_timeout_secs: 10, max_connections: 256, idle_timeout_secs: 600,
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
        set_string!("RUSTINE_COVER_DOMAIN", cover_domain);
        if let Ok(v) = env::var("RUSTINE_COVER_ROOT") { s.cover_root = Some(PathBuf::from(v)); }
        if let Ok(v) = env::var("RUSTINE_COVER_ENABLED") { s.cover_enabled = parse_bool(&v)?; }
        set_string!("RUSTINE_PASSWORD", password);
        set_string!("RUSTINE_UPSTREAM_PASSWORD", upstream_password);
        for (env_name, slot) in [
            ("RUSTINE_CERT_PATH", &mut s.cert_path),
            ("RUSTINE_KEY_PATH", &mut s.key_path),
            ("RUSTINE_CA_PATH", &mut s.ca_path),
        ] {
            if let Ok(v) = env::var(env_name) { *slot = Some(PathBuf::from(v)); }
        }
        if let Ok(v) = env::var("RUSTINE_PASSWORD_FILE") {
            s.password = Some(read_secret(&v)?);
        }
        if let Ok(v) = env::var("RUSTINE_UPSTREAM_PASSWORD_FILE") {
            s.upstream_password = Some(read_secret(&v)?);
        }
        if let Ok(v) = env::var("RUSTINE_MAX_PADDING") { s.max_padding = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_JITTER_MS") { s.jitter_ms = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_ALLOW_PRIVATE_TARGETS") { s.allow_private_targets = parse_bool(&v)?; }
        if let Ok(v) = env::var("RUSTINE_ALLOW_REMOTE_CLIENTS") { s.allow_remote_clients = parse_bool(&v)?; }
        if let Ok(v) = env::var("RUSTINE_SNI_SPOOFING") { s.sni_spoofing = parse_bool(&v)?; }
        if let Ok(v) = env::var("RUSTINE_CONNECT_TIMEOUT_SECS") { s.connect_timeout_secs = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_MAX_CONNECTIONS") { s.max_connections = v.parse()?; }
        if let Ok(v) = env::var("RUSTINE_IDLE_TIMEOUT_SECS") { s.idle_timeout_secs = v.parse()?; }
        s.validate()?;
        Ok(s)
    }

    pub fn secret(&self) -> &str { self.password.as_deref().expect("validated config") }

    pub fn outgoing_secret(&self) -> &str {
        match self.role {
            Role::Relay => self.upstream_password.as_deref().expect("validated relay upstream password"),
            _ => self.secret(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.password.as_deref().unwrap_or("").len() >= 16, "password must contain at least 16 bytes; prefer 32 random bytes");
        if self.role == Role::Relay {
            let outbound = self.upstream_password.as_deref().unwrap_or("");
            ensure!(outbound.len() >= 16, "relay requires upstream_password with at least 16 bytes");
            ensure!(outbound != self.secret(), "relay upstream_password must differ from incoming password");
        }
        if self.role == Role::Client && !self.allow_remote_clients {
            let addr: std::net::SocketAddr = self.listen.parse()
                .context("client listen must be an IP:port socket address")?;
            ensure!(addr.ip().is_loopback(),
                "refusing non-loopback client proxy listener; set allow_remote_clients=true to permit LAN clients");
        }
        if self.cover_enabled {
            ensure!(self.role != Role::Client, "cover website is only available on server roles");
            let host = required(&self.cover_domain, "cover_domain")?;
            ensure!(host.len() <= 253 && host.contains('.') &&
                host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')),
                "cover_domain must be a valid DNS name you control");
            let root = required_path(&self.cover_root, "cover_root")?;
            ensure!(root.is_dir() && root.join("index.html").is_file(),
                "cover_root must contain a readable index.html");
        }
        ensure!(self.max_padding <= 4096, "max_padding must be <= 4096");
        ensure!(self.jitter_ms <= 2000, "jitter_ms must be <= 2000");
        ensure!((1..=60).contains(&self.connect_timeout_secs), "connect_timeout_secs must be 1..60");
        ensure!((1..=65535).contains(&self.max_connections), "max_connections must be 1..65535");
        ensure!(self.idle_timeout_secs == 0 || (10..=86400).contains(&self.idle_timeout_secs),
            "idle_timeout_secs must be 0 (disabled) or 10..86400");
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
fn read_secret(path: &str) -> Result<String> {
    Ok(fs::read_to_string(path).with_context(|| format!("reading secret file {path}"))?
        .trim_end_matches(&['\r', '\n'][..]).to_owned())
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
    #[test] fn cover_requires_domain_and_site() {
        let mut c=Config::default();
        c.password=Some("a-long-test-secret-123456".into());
        c.role=Role::Exit;
        c.cert_path=Some("unused".into()); c.key_path=Some("unused".into());
        c.cover_enabled=true;
        assert!(c.validate().unwrap_err().to_string().contains("cover_domain"));
        c.cover_domain=Some("site.example".into());
        assert!(c.validate().unwrap_err().to_string().contains("cover_root"));
    }
    #[test] fn default_private_access_is_off() { assert!(!Config::default().allow_private_targets); }
    #[test] fn unknown_config_keys_fail_closed() {
        let error = toml::from_str::<Config>("role = \"client\"\nallow_priavte_targets = true")
            .err().expect("unknown config field must be rejected").to_string();
        assert!(error.contains("unknown field"));
    }
    #[test] fn connections_limit_is_bounded() {
        let mut c=Config::default();
        c.password=Some("example-long-test-secret-0123456789".into());
        c.relay_addr=Some("127.0.0.1:8443".into());
        c.sni=Some("relay.test".into());
        c.ca_path=Some("/not/checked/here".into());
        c.max_connections=0;
        assert!(c.validate().unwrap_err().to_string().contains("max_connections"));
        c.max_connections=64;
        assert!(c.validate().is_ok());
    }
    #[test] fn client_cannot_expose_unauthenticated_proxy_by_accident() {
        let mut c = Config::default();
        c.password = Some("a-long-test-secret-123456".into());
        c.relay_addr = Some("127.0.0.1:8443".into());
        c.sni = Some("relay.test".into());
        c.ca_path = Some("not-checked-yet".into());
        c.listen = "0.0.0.0:1080".into();
        assert!(c.validate().unwrap_err().to_string().contains("non-loopback"));
        c.allow_remote_clients = true;
        assert!(c.validate().is_ok());
    }
    #[test] fn relay_requires_distinct_upstream_secret() {
        let mut c = Config::default();
        c.role = Role::Relay;
        c.password = Some("a-long-test-secret-123456".into());
        c.next_hop = Some("exit:8443".into());
        c.sni = Some("exit.test".into());
        c.ca_path = Some("unused".into());
        c.cert_path = Some("unused".into());
        c.key_path = Some("unused".into());
        assert!(c.validate().unwrap_err().to_string().contains("upstream_password"));
        c.upstream_password = c.password.clone();
        assert!(c.validate().unwrap_err().to_string().contains("must differ"));
        c.upstream_password = Some("distinct-upstream-secret-123".into());
        assert!(c.validate().is_ok());
    }
}

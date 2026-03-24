//! Configuration for the e2e test runner.
//!
//! The config is a subset of the mosaic binary config. Extra fields/sections
//! are silently ignored so the same TOML file can be shared.

use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use mosaic_net_svc::PeerId;
use serde::Deserialize;

/// Top-level config — mirrors the mosaic binary config structure.
///
/// Only the fields the e2e runner cares about are deserialized; unknown
/// top-level sections (e.g. `[circuit]`, `[storage]`) are ignored so the
/// same config file can be reused.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct E2eConfig {
    #[serde(default)]
    pub(crate) logging: LoggingConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) rpc: RpcConfig,
}

impl E2eConfig {
    pub(crate) fn from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }

    pub(crate) fn peer_ids(&self) -> Result<Vec<PeerId>> {
        self.network.peers.iter().map(|p| p.peer_id()).collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LoggingConfig {
    #[serde(default = "default_log_filter")]
    pub(crate) filter: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter: default_log_filter(),
        }
    }
}

/// Only the fields we need from `[network]`; extra fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NetworkConfig {
    #[serde(default)]
    pub(crate) peers: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PeerEntry {
    pub(crate) peer_id_hex: String,
}

impl PeerEntry {
    pub(crate) fn peer_id(&self) -> Result<PeerId> {
        let bytes = decode_exact_hex::<32>(&self.peer_id_hex, "peer id")?;
        Ok(PeerId::from_bytes(bytes))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RpcConfig {
    pub(crate) bind_addr: String,
}

impl RpcConfig {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.bind_addr)
    }
}

fn default_log_filter() -> String {
    "info".to_string()
}

pub(crate) fn decode_peer_id(hex: &str) -> Result<PeerId> {
    let bytes = decode_exact_hex::<32>(hex, "peer id")?;
    Ok(PeerId::from_bytes(bytes))
}

fn decode_exact_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let value = value.trim();
    if value.len() != N * 2 {
        bail!(
            "{label} must be exactly {} hex characters, got {}",
            N * 2,
            value.len()
        );
    }

    let mut out = [0u8; N];
    for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let chunk = std::str::from_utf8(chunk).context("hex input was not valid utf-8")?;
        out[i] = u8::from_str_radix(chunk, 16)
            .map_err(|e| anyhow!("invalid hex in {label} at byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full mosaic config — the e2e runner should parse this successfully,
    /// ignoring sections it doesn't care about.
    fn mosaic_config_toml() -> &'static str {
        r#"
[logging]
filter = "debug"

[circuit]
path = "/tmp/circuit.bin"

[network]
signing_key_hex = "1111111111111111111111111111111111111111111111111111111111111111"
bind_addr = "127.0.0.1:7000"

[[network.peers]]
peer_id_hex = "2222222222222222222222222222222222222222222222222222222222222222"
addr = "127.0.0.1:7001"

[storage]
cluster_file = "/etc/foundationdb/fdb.cluster"

[table_store]
backend = "local_filesystem"
root = "/var/lib/mosaic/tables"
prefix = "tables"

[job_scheduler]

[sm_executor]

[rpc]
bind_addr = "127.0.0.1:8080"
"#
    }

    #[test]
    fn parses_full_mosaic_config() {
        let config: E2eConfig =
            toml::from_str(mosaic_config_toml()).expect("should parse mosaic config");
        assert_eq!(config.logging.filter, "debug");
        assert_eq!(config.rpc.bind_addr, "127.0.0.1:8080");
        assert_eq!(config.rpc.url(), "http://127.0.0.1:8080");

        let peers = config.peer_ids().expect("should decode peer ids");
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn parses_minimal_config() {
        let toml = r#"
[network]

[[network.peers]]
peer_id_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[rpc]
bind_addr = "127.0.0.1:9090"
"#;
        let config: E2eConfig = toml::from_str(toml).expect("should parse");
        assert_eq!(config.logging.filter, "info");
        assert_eq!(config.rpc.bind_addr, "127.0.0.1:9090");
        assert_eq!(config.peer_ids().unwrap().len(), 1);
    }
}

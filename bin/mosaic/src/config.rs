use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use mosaic_job_scheduler::{GarblingConfig, JobSchedulerConfig, PoolConfig};
use mosaic_net_client::NetClientConfig;
use mosaic_net_svc::{NetServiceConfig, PeerConfig, PeerId};
use mosaic_sm_executor_api::SmExecutorConfig;
use mosaic_storage_fdb::FdbStorageConfig;
use object_store::ClientOptions;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MosaicConfig {
    pub(crate) logging: LoggingConfig,
    pub(crate) circuit: CircuitConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) storage: StorageConfig,
    pub(crate) table_store: TableStoreConfig,
    pub(crate) job_scheduler: JobSchedulerSection,
    pub(crate) sm_executor: SmExecutorSection,
    pub(crate) rpc: RpcConfig,
}

impl MosaicConfig {
    pub(crate) fn from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }

    pub(crate) fn known_peers(&self) -> Result<Vec<PeerId>> {
        self.network
            .peers
            .iter()
            .map(PeerEntry::peer_id)
            .collect::<Result<Vec<_>>>()
    }

    pub(crate) fn build_net_service_config(&self) -> Result<NetServiceConfig> {
        let signing_key = decode_signing_key(&self.network.signing_key_hex)?;
        let bind_addr = parse_socket_addr(&self.network.bind_addr)?;
        let peers = self
            .network
            .peers
            .iter()
            .map(PeerEntry::to_peer_config)
            .collect::<Result<Vec<_>>>()?;

        Ok(NetServiceConfig::new(signing_key, bind_addr, peers)
            .with_keep_alive_interval(Duration::from_secs(self.network.keep_alive_interval_secs))
            .with_idle_timeout(Duration::from_secs(self.network.idle_timeout_secs))
            .with_reconnect_backoff(Duration::from_secs(self.network.reconnect_backoff_secs)))
    }

    pub(crate) fn build_net_client_config(&self) -> NetClientConfig {
        NetClientConfig {
            open_timeout: Duration::from_secs(self.network.client.open_timeout_secs),
            ack_timeout: Duration::from_secs(self.network.client.ack_timeout_secs),
        }
    }

    pub(crate) fn build_sm_executor_config(&self, known_peers: Vec<PeerId>) -> SmExecutorConfig {
        SmExecutorConfig {
            command_queue_size: self.sm_executor.command_queue_size,
            known_peers,
        }
    }

    pub(crate) fn build_job_scheduler_config(&self) -> JobSchedulerConfig {
        JobSchedulerConfig {
            light: PoolConfig {
                threads: self.job_scheduler.light.threads,
                concurrency_per_worker: self.job_scheduler.light.concurrency_per_worker,
                priority_queue: false,
            },
            heavy: PoolConfig {
                threads: self.job_scheduler.heavy.threads,
                concurrency_per_worker: self.job_scheduler.heavy.concurrency_per_worker,
                priority_queue: true,
            },
            garbling: GarblingConfig {
                worker_threads: self.job_scheduler.garbling.worker_threads,
                max_concurrent: self.job_scheduler.garbling.max_concurrent,
                circuit_path: self.circuit.path.clone(),
                batch_timeout: Duration::from_millis(self.job_scheduler.garbling.batch_timeout_ms),
                chunk_timeout: Duration::from_secs(self.job_scheduler.garbling.chunk_timeout_secs),
            },
            submission_queue_size: self.job_scheduler.submission_queue_size,
            completion_queue_size: self.job_scheduler.completion_queue_size,
        }
    }

    pub(crate) fn rpc_bind_addr(&self) -> Result<SocketAddr> {
        parse_socket_addr(&self.rpc.bind_addr)
    }

    pub(crate) fn build_fdb_storage_config(&self) -> FdbStorageConfig {
        FdbStorageConfig {
            global_path: self.storage.global_path.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.network.peers.is_empty() {
            bail!("network.peers must not be empty");
        }

        if self.network.keep_alive_interval_secs == 0 {
            bail!("network.keep_alive_interval_secs must be greater than zero");
        }

        if self.network.idle_timeout_secs == 0 {
            bail!("network.idle_timeout_secs must be greater than zero");
        }

        if self.network.keep_alive_interval_secs >= self.network.idle_timeout_secs {
            bail!("network.keep_alive_interval_secs must be less than network.idle_timeout_secs");
        }

        if self.job_scheduler.garbling.max_concurrent == 0 {
            bail!("job_scheduler.garbling.max_concurrent must be greater than zero");
        }

        if self.job_scheduler.garbling.worker_threads == 0 {
            bail!("job_scheduler.garbling.worker_threads must be greater than zero");
        }

        if self.job_scheduler.light.threads == 0 || self.job_scheduler.heavy.threads == 0 {
            bail!("job scheduler thread counts must be greater than zero");
        }

        if !self.circuit.path.is_file() {
            bail!(
                "circuit.path does not point to an existing file: {}",
                self.circuit.path.display()
            );
        }

        if let TableStoreBackend::S3Compatible {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            session_token,
            request_timeout_secs,
            connect_timeout_secs,
            ..
        } = &self.table_store.backend
        {
            if bucket.is_empty() {
                bail!("table_store.bucket must not be empty");
            }

            if region.is_empty() {
                bail!("table_store.region must not be empty");
            }

            match (access_key_id.as_deref(), secret_access_key.as_deref()) {
                (Some(access_key_id), Some(secret_access_key)) => {
                    if access_key_id.is_empty() {
                        bail!("table_store.access_key_id must not be empty when provided");
                    }

                    if secret_access_key.is_empty() {
                        bail!("table_store.secret_access_key must not be empty when provided");
                    }
                }
                (None, None) => {}
                _ => {
                    bail!(
                        "table_store.access_key_id and table_store.secret_access_key must either both be set or both be omitted"
                    );
                }
            }

            if let Some(session_token) = session_token {
                if session_token.is_empty() {
                    bail!("table_store.session_token must not be empty when provided");
                }

                if access_key_id.is_none() || secret_access_key.is_none() {
                    bail!(
                        "table_store.session_token requires table_store.access_key_id and table_store.secret_access_key"
                    );
                }
            }

            if *request_timeout_secs == 0 {
                bail!("table_store.request_timeout_secs must be greater than zero");
            }

            if *connect_timeout_secs == 0 {
                bail!("table_store.connect_timeout_secs must be greater than zero");
            }

            if let Some(endpoint) = endpoint
                && endpoint.is_empty()
            {
                bail!("table_store.endpoint must not be empty when provided");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoggingConfig {
    #[serde(default = "default_log_filter")]
    pub(crate) filter: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CircuitConfig {
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkConfig {
    pub(crate) signing_key_hex: String,
    pub(crate) bind_addr: String,
    #[serde(default = "default_keep_alive_interval_secs")]
    pub(crate) keep_alive_interval_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub(crate) idle_timeout_secs: u64,
    #[serde(default = "default_reconnect_backoff_secs")]
    pub(crate) reconnect_backoff_secs: u64,
    #[serde(default)]
    pub(crate) client: NetworkClientConfig,
    #[serde(default)]
    pub(crate) peers: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkClientConfig {
    #[serde(default = "default_open_timeout_secs")]
    pub(crate) open_timeout_secs: u64,
    #[serde(default = "default_ack_timeout_secs")]
    pub(crate) ack_timeout_secs: u64,
}

impl Default for NetworkClientConfig {
    fn default() -> Self {
        Self {
            open_timeout_secs: default_open_timeout_secs(),
            ack_timeout_secs: default_ack_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerEntry {
    pub(crate) peer_id_hex: String,
    pub(crate) addr: String,
}

impl PeerEntry {
    pub(crate) fn peer_id(&self) -> Result<PeerId> {
        decode_peer_id(&self.peer_id_hex)
    }

    pub(crate) fn to_peer_config(&self) -> Result<PeerConfig> {
        Ok(PeerConfig::new(
            self.peer_id()?,
            parse_socket_addr(&self.addr)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageConfig {
    pub(crate) cluster_file: Option<PathBuf>,
    #[serde(default)]
    pub(crate) global_path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TableStoreConfig {
    #[serde(flatten)]
    pub(crate) backend: TableStoreBackend,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TableStoreBackend {
    LocalFilesystem {
        root: PathBuf,
        prefix: String,
    },
    S3Compatible {
        bucket: String,
        region: String,
        prefix: String,
<<<<<<< HEAD
=======
        /// When both `access_key_id` and `secret_access_key` are omitted, the
        /// AWS credential chain is used: IRSA web-identity token → ECS task
        /// creds → EC2 instance profile.
>>>>>>> 3e11546 (remove IRSA backend, allow optional access_key, secret in S3Compatible backend for IRSA)
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        endpoint: Option<String>,
        session_token: Option<String>,
        #[serde(default = "default_s3_request_timeout_secs")]
        request_timeout_secs: u64,
        #[serde(default = "default_s3_connect_timeout_secs")]
        connect_timeout_secs: u64,
        #[serde(default)]
        allow_http: bool,
        #[serde(default)]
        virtual_hosted_style_request: bool,
    },
<<<<<<< HEAD
}

impl TableStoreBackend {
    pub(crate) fn build_s3_client_options(&self) -> Option<ClientOptions> {
        match self {
            Self::S3Compatible {
                request_timeout_secs,
                connect_timeout_secs,
                ..
            } => Some(
                ClientOptions::new()
                    .with_timeout(Duration::from_secs(*request_timeout_secs))
                    .with_connect_timeout(Duration::from_secs(*connect_timeout_secs)),
            ),
            Self::LocalFilesystem { .. } => None,
        }
    }
=======
>>>>>>> 3e11546 (remove IRSA backend, allow optional access_key, secret in S3Compatible backend for IRSA)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JobSchedulerSection {
    #[serde(default)]
    pub(crate) light: PoolSection,
    #[serde(default = "default_heavy_pool_section")]
    pub(crate) heavy: PoolSection,
    #[serde(default)]
    pub(crate) garbling: GarblingSection,
    #[serde(default = "default_submission_queue_size")]
    pub(crate) submission_queue_size: usize,
    #[serde(default = "default_completion_queue_size")]
    pub(crate) completion_queue_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolSection {
    #[serde(default = "default_pool_threads")]
    pub(crate) threads: usize,
    #[serde(default = "default_pool_concurrency")]
    pub(crate) concurrency_per_worker: usize,
}

impl Default for PoolSection {
    fn default() -> Self {
        Self {
            threads: default_pool_threads(),
            concurrency_per_worker: default_pool_concurrency(),
        }
    }
}

fn default_heavy_pool_section() -> PoolSection {
    PoolSection {
        threads: 2,
        concurrency_per_worker: 8,
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GarblingSection {
    #[serde(default = "default_garbling_worker_threads")]
    pub(crate) worker_threads: usize,
    #[serde(default = "default_garbling_max_concurrent")]
    pub(crate) max_concurrent: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub(crate) batch_timeout_ms: u64,
    #[serde(default = "default_chunk_timeout_secs")]
    pub(crate) chunk_timeout_secs: u64,
}

impl Default for GarblingSection {
    fn default() -> Self {
        Self {
            worker_threads: default_garbling_worker_threads(),
            max_concurrent: default_garbling_max_concurrent(),
            batch_timeout_ms: default_batch_timeout_ms(),
            chunk_timeout_secs: default_chunk_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SmExecutorSection {
    #[serde(default = "default_command_queue_size")]
    pub(crate) command_queue_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RpcConfig {
    pub(crate) bind_addr: String,
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr> {
    // Try direct parse first (IP:port), fall back to DNS resolution (hostname:port).
    if let Ok(addr) = value.parse() {
        return Ok(addr);
    }
    use std::net::ToSocketAddrs;
    value
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve address `{value}`"))?
        .next()
        .with_context(|| format!("no addresses found for `{value}`"))
}

fn decode_signing_key(value: &str) -> Result<SigningKey> {
    let bytes = decode_exact_hex::<32>(value, "signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_peer_id(value: &str) -> Result<PeerId> {
    Ok(PeerId::from_bytes(decode_exact_hex::<32>(
        value, "peer id",
    )?))
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

const DEFAULT_LOG_FILTER: &str = "info";
const DEFAULT_KEEP_ALIVE_INTERVAL_SECS: u64 = 5;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_RECONNECT_BACKOFF_SECS: u64 = 1;
const DEFAULT_OPEN_TIMEOUT_SECS: u64 = 5;
const DEFAULT_ACK_TIMEOUT_SECS: u64 = 10;
const DEFAULT_POOL_THREADS: usize = 1;
const DEFAULT_POOL_CONCURRENCY: usize = 32;
const DEFAULT_GARBLING_WORKER_THREADS: usize = 4;
const DEFAULT_GARBLING_MAX_CONCURRENT: usize = 8;
const DEFAULT_BATCH_TIMEOUT_MS: u64 = 500;
const DEFAULT_CHUNK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_SUBMISSION_QUEUE_SIZE: usize = 256;
const DEFAULT_COMPLETION_QUEUE_SIZE: usize = 256;
const DEFAULT_COMMAND_QUEUE_SIZE: usize = 256;
const DEFAULT_S3_REQUEST_TIMEOUT_SECS: u64 = 2 * 60 * 60;
const DEFAULT_S3_CONNECT_TIMEOUT_SECS: u64 = 5;

fn default_log_filter() -> String {
    DEFAULT_LOG_FILTER.to_string()
}

const fn default_keep_alive_interval_secs() -> u64 {
    DEFAULT_KEEP_ALIVE_INTERVAL_SECS
}

const fn default_idle_timeout_secs() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

const fn default_reconnect_backoff_secs() -> u64 {
    DEFAULT_RECONNECT_BACKOFF_SECS
}

const fn default_open_timeout_secs() -> u64 {
    DEFAULT_OPEN_TIMEOUT_SECS
}

const fn default_ack_timeout_secs() -> u64 {
    DEFAULT_ACK_TIMEOUT_SECS
}

const fn default_pool_threads() -> usize {
    DEFAULT_POOL_THREADS
}

const fn default_pool_concurrency() -> usize {
    DEFAULT_POOL_CONCURRENCY
}

const fn default_garbling_worker_threads() -> usize {
    DEFAULT_GARBLING_WORKER_THREADS
}

const fn default_garbling_max_concurrent() -> usize {
    DEFAULT_GARBLING_MAX_CONCURRENT
}

const fn default_batch_timeout_ms() -> u64 {
    DEFAULT_BATCH_TIMEOUT_MS
}

const fn default_chunk_timeout_secs() -> u64 {
    DEFAULT_CHUNK_TIMEOUT_SECS
}

const fn default_submission_queue_size() -> usize {
    DEFAULT_SUBMISSION_QUEUE_SIZE
}

const fn default_completion_queue_size() -> usize {
    DEFAULT_COMPLETION_QUEUE_SIZE
}

const fn default_command_queue_size() -> usize {
    DEFAULT_COMMAND_QUEUE_SIZE
}

const fn default_s3_request_timeout_secs() -> u64 {
    DEFAULT_S3_REQUEST_TIMEOUT_SECS
}

const fn default_s3_connect_timeout_secs() -> u64 {
    DEFAULT_S3_CONNECT_TIMEOUT_SECS
}

#[cfg(test)]
mod tests {
    use object_store::ClientConfigKey;

    use super::*;

    fn sample_config_toml(circuit_path: &Path) -> String {
        format!(
            r#"
[logging]
filter = "debug"

[circuit]
path = "{}"

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
"#,
            circuit_path.display()
        )
    }

    fn sample_s3_config_toml(circuit_path: &Path, extra_table_store: &str) -> String {
        format!(
            r#"
[logging]
filter = "debug"

[circuit]
path = "{}"

[network]
signing_key_hex = "1111111111111111111111111111111111111111111111111111111111111111"
bind_addr = "127.0.0.1:7000"

[[network.peers]]
peer_id_hex = "2222222222222222222222222222222222222222222222222222222222222222"
addr = "127.0.0.1:7001"

[storage]
cluster_file = "/etc/foundationdb/fdb.cluster"

[table_store]
backend = "s3_compatible"
bucket = "bucket"
region = "us-east-1"
prefix = "tables"
access_key_id = "access"
secret_access_key = "secret"
{extra_table_store}

[job_scheduler]

[sm_executor]

[rpc]
bind_addr = "127.0.0.1:8080"
"#,
            circuit_path.display()
        )
    }

    #[test]
    fn config_deserializes_with_defaults() {
        let path = std::env::current_exe().expect("current executable path");
        let config: MosaicConfig =
            toml::from_str(&sample_config_toml(&path)).expect("config should parse");

        assert_eq!(config.logging.filter, "debug");
        assert_eq!(
            config.network.client.open_timeout_secs,
            DEFAULT_OPEN_TIMEOUT_SECS
        );
        assert_eq!(
            config.network.client.ack_timeout_secs,
            DEFAULT_ACK_TIMEOUT_SECS
        );
        assert_eq!(
            config.job_scheduler.submission_queue_size,
            DEFAULT_SUBMISSION_QUEUE_SIZE
        );
        assert_eq!(
            config.job_scheduler.completion_queue_size,
            DEFAULT_COMPLETION_QUEUE_SIZE
        );
        assert_eq!(
            config.sm_executor.command_queue_size,
            DEFAULT_COMMAND_QUEUE_SIZE
        );
    }

    #[test]
    fn validate_accepts_existing_circuit_path() {
        let path = std::env::current_exe().expect("current executable path");
        let config: MosaicConfig =
            toml::from_str(&sample_config_toml(&path)).expect("config should parse");

        config.validate().expect("config should validate");
    }

    #[test]
    fn s3_timeout_defaults_are_applied() {
        let path = std::env::current_exe().expect("current executable path");
        let config: MosaicConfig =
            toml::from_str(&sample_s3_config_toml(&path, "")).expect("config should parse");

        let options = config
            .table_store
            .backend
            .build_s3_client_options()
            .expect("s3 backend should build client options");

        let expected = ClientOptions::new()
            .with_timeout(Duration::from_secs(DEFAULT_S3_REQUEST_TIMEOUT_SECS))
            .with_connect_timeout(Duration::from_secs(DEFAULT_S3_CONNECT_TIMEOUT_SECS));

        assert_eq!(
            options.get_config_value(&ClientConfigKey::Timeout),
            expected.get_config_value(&ClientConfigKey::Timeout)
        );
        assert_eq!(
            options.get_config_value(&ClientConfigKey::ConnectTimeout),
            expected.get_config_value(&ClientConfigKey::ConnectTimeout)
        );
    }

    #[test]
    fn s3_timeout_overrides_are_applied() {
        let path = std::env::current_exe().expect("current executable path");
        let config: MosaicConfig = toml::from_str(&sample_s3_config_toml(
            &path,
            "request_timeout_secs = 900\nconnect_timeout_secs = 9",
        ))
        .expect("config should parse");

        let options = config
            .table_store
            .backend
            .build_s3_client_options()
            .expect("s3 backend should build client options");

        let expected = ClientOptions::new()
            .with_timeout(Duration::from_secs(900))
            .with_connect_timeout(Duration::from_secs(9));

        assert_eq!(
            options.get_config_value(&ClientConfigKey::Timeout),
            expected.get_config_value(&ClientConfigKey::Timeout)
        );
        assert_eq!(
            options.get_config_value(&ClientConfigKey::ConnectTimeout),
            expected.get_config_value(&ClientConfigKey::ConnectTimeout)
        );
    }
}

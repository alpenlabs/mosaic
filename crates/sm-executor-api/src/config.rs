use mosaic_net_svc_api::PeerId;

/// Configuration for the SM executor.
#[derive(Debug, Clone)]
pub struct SmExecutorConfig {
    /// Bounded queue size for incoming executor commands.
    pub command_queue_size: usize,
    /// Peers to restore at startup.
    pub known_peers: Vec<PeerId>,
    /// Interval in seconds between periodic `restore_known_peers` runs.
    /// `None` or `Some(0)` disables periodic restore.
    pub restore_interval_secs: Option<u64>,
}

impl Default for SmExecutorConfig {
    fn default() -> Self {
        Self {
            command_queue_size: 256,
            known_peers: Vec::new(),
            restore_interval_secs: None,
        }
    }
}

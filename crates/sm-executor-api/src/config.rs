use mosaic_net_svc_api::PeerId;

/// Configuration for the SM executor.
#[derive(Debug, Clone)]
pub struct SmExecutorConfig {
    /// Bounded queue size for incoming executor commands.
    pub command_queue_size: usize,
    /// Peers to restore at startup.
    pub known_peers: Vec<PeerId>,
}

impl Default for SmExecutorConfig {
    fn default() -> Self {
        Self {
            command_queue_size: 256,
            known_peers: Vec::new(),
        }
    }
}

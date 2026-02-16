//! Network service configuration.
//!
//! This module contains the configuration types for the network service.
//! The configuration is static — peers are known at startup and cannot be
//! added or removed at runtime.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;

use crate::peer_id::{PeerId, peer_id_from_signing_key};

/// Configuration for a known peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Peer's public key (32-byte Ed25519 public key).
    pub peer_id: PeerId,
    /// Peer's network address.
    pub addr: SocketAddr,
}

impl PeerConfig {
    /// Create a new peer configuration.
    pub fn new(peer_id: PeerId, addr: SocketAddr) -> Self {
        Self { peer_id, addr }
    }
}

/// Network service configuration.
///
/// This configuration is immutable after creation. The network service will
/// only accept connections from peers in the `peers` list, and will only
/// connect to those peers.
pub struct NetServiceConfig {
    /// Our signing key (identity).
    pub signing_key: SigningKey,
    /// Address to bind the QUIC endpoint to.
    pub bind_addr: SocketAddr,
    /// Known peers.
    pub peers: Vec<PeerConfig>,
    /// Keep-alive interval for connections (default: 5 seconds).
    pub keep_alive_interval: std::time::Duration,
    /// Backoff duration between reconnection attempts (default: 1 second).
    pub reconnect_backoff: std::time::Duration,
}

impl NetServiceConfig {
    /// Default keep-alive interval (5 seconds).
    pub const DEFAULT_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    /// Default reconnection backoff (1 second).
    pub const DEFAULT_RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

    /// Create a new configuration.
    pub fn new(signing_key: SigningKey, bind_addr: SocketAddr, peers: Vec<PeerConfig>) -> Self {
        Self {
            signing_key,
            bind_addr,
            peers,
            keep_alive_interval: Self::DEFAULT_KEEP_ALIVE_INTERVAL,
            reconnect_backoff: Self::DEFAULT_RECONNECT_BACKOFF,
        }
    }

    /// Set the keep-alive interval.
    pub fn with_keep_alive_interval(mut self, interval: std::time::Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    /// Set the reconnection backoff duration.
    pub fn with_reconnect_backoff(mut self, backoff: std::time::Duration) -> Self {
        self.reconnect_backoff = backoff;
        self
    }

    /// Check if a peer is in the known peers list.
    pub fn has_peer(&self, peer_id: &PeerId) -> bool {
        self.peers.iter().any(|p| &p.peer_id == peer_id)
    }

    /// Get a peer's configuration by their ID.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| &p.peer_id == peer_id)
    }

    /// Get a peer's address by their ID.
    pub fn get_peer_addr(&self, peer_id: &PeerId) -> Option<SocketAddr> {
        self.get_peer(peer_id).map(|p| p.addr)
    }

    /// Get all peer IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.iter().map(|p| &p.peer_id)
    }

    /// Get our peer ID (derived from signing key).
    pub fn our_peer_id(&self) -> PeerId {
        peer_id_from_signing_key(&self.signing_key)
    }
}

impl std::fmt::Debug for NetServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetServiceConfig")
            .field("our_peer_id", &hex::encode(self.our_peer_id()))
            .field("bind_addr", &self.bind_addr)
            .field("peers", &self.peers.len())
            .field("keep_alive_interval", &self.keep_alive_interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 1; // Just need something non-zero
        SigningKey::from_bytes(&bytes)
    }

    fn test_peer_id(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; 32])
    }

    #[test]
    fn has_peer_works() {
        let config = NetServiceConfig::new(
            test_signing_key(),
            "127.0.0.1:9000".parse().unwrap(),
            vec![
                PeerConfig::new(test_peer_id(1), "127.0.0.1:9001".parse().unwrap()),
                PeerConfig::new(test_peer_id(2), "127.0.0.1:9002".parse().unwrap()),
            ],
        );

        assert!(config.has_peer(&test_peer_id(1)));
        assert!(config.has_peer(&test_peer_id(2)));
        assert!(!config.has_peer(&test_peer_id(3)));
    }

    #[test]
    fn get_peer_addr_works() {
        let config = NetServiceConfig::new(
            test_signing_key(),
            "127.0.0.1:9000".parse().unwrap(),
            vec![PeerConfig::new(
                test_peer_id(1),
                "127.0.0.1:9001".parse().unwrap(),
            )],
        );

        assert_eq!(
            config.get_peer_addr(&test_peer_id(1)),
            Some("127.0.0.1:9001".parse().unwrap())
        );
        assert_eq!(config.get_peer_addr(&test_peer_id(2)), None);
    }

    #[test]
    fn our_peer_id_works() {
        let signing_key = test_signing_key();
        let expected = peer_id_from_signing_key(&signing_key);

        let config = NetServiceConfig::new(signing_key, "127.0.0.1:9000".parse().unwrap(), vec![]);

        assert_eq!(config.our_peer_id(), expected);
    }
}

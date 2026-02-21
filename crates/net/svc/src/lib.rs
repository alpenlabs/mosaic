//! Network service for QUIC-based peer-to-peer communication.
//!
//! This crate provides the low-level networking infrastructure for Mosaic.
//! It runs on a dedicated thread with its own tokio runtime and exposes a
//! channel-based API for use from other async runtimes (like monoio).
//!
//! # Architecture
//!
//! - [`config`]: Service configuration (peers, addresses, keys)
//! - [`tls`]: TLS setup with Ed25519 peer authentication
//! - [`api`]: Types for interacting with the service (streams, handles, errors)
//! - [`svc`]: The network service implementation
//!
//! # Example
//!
//! ```ignore
//! use net_svc::{NetService, config::NetServiceConfig};
//!
//! // Configure the service
//! let config = NetServiceConfig::new(signing_key, bind_addr, peers);
//!
//! // Start the service (spawns background thread)
//! let (handle, controller) = NetService::new(config)?;
//!
//! // Use handle from any thread
//! let stream = handle.open_protocol_stream(peer_id, 0).await?;
//!
//! // Later, shut down gracefully
//! controller.shutdown()?;
//! ```
//!
//! # Connection Management
//!
//! The service maintains persistent connections to all configured peers:
//! - Connections to all peers are attempted immediately on startup
//! - Keep-alives prevent idle timeouts (5 seconds)
//! - Disconnections trigger automatic reconnection with backoff
//! - Callers see `StreamClosed::Disconnected` on connection loss
//!
//! # Stream Types
//!
//! Two types of streams are supported:
//!
//! - **Protocol streams**: For control messages (normal priority)
//! - **Bulk transfer streams**: For large data transfers (low priority, routed by identifier)

// Re-export API modules from svc-api so existing `mosaic_net_svc::api::*`
// and `mosaic_net_svc::config::*` paths continue to work.
pub use mosaic_net_svc_api::{api, config, peer_id};

// Local modules that remain in this crate.
pub mod close_codes;
pub mod svc;
pub mod tls;

// Re-export main API types for convenience.
pub use mosaic_net_svc_api::{
    BulkTransferExpectation, ExpectError, NetServiceConfig, NetServiceHandle, OpenStreamError,
    PayloadBuf, PeerConfig, PeerId, Stream, StreamClosed, peer_id_from_signing_key,
    peer_id_from_verifying_key,
};
pub use mosaic_net_wire::FrameLimits;
pub use svc::{NetService, NetServiceController, ServiceError};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

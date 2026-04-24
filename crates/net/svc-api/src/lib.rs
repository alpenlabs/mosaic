//! Public API types for the Mosaic network service.
//!
//! This crate contains the types needed to *interact* with `net-svc` without
//! pulling in its full implementation (QUIC, TLS, connection management).
//!
//! # What lives here
//!
//! - [`PeerId`] — 32-byte Ed25519 peer identity
//! - [`NetServiceConfig`] / [`PeerConfig`] — service configuration
//! - [`Stream`] — bidirectional QUIC stream handle
//! - [`StreamClosed`] — close reason enum
//! - [`PayloadBuf`] — buffer type alias
//! - [`NetServiceHandle`] — handle for sending commands to the service
//! - [`BulkTransferExpectation`] — bulk transfer registration
//! - [`OpenStreamError`] / [`ExpectError`] — error types
//!
//! # What stays in `net-svc`
//!
//! - `NetService` — the actual service (spawns thread, manages connections)
//! - `NetServiceController` — lifecycle control (shutdown)
//! - TLS setup, certificate generation, QUIC endpoint management
//! - Connection management internals

pub mod api;
pub mod config;
pub mod peer_id;

// Re-export main types for convenience.
pub use api::{
    BulkTransferExpectation, ExpectError, InboundProtocolStream, NetServiceHandle, OpenStreamError,
    PayloadBuf, Stream, StreamClosed,
};
pub use config::{NetServiceConfig, PeerConfig};
pub use peer_id::{PeerId, peer_id_from_signing_key, peer_id_from_verifying_key};

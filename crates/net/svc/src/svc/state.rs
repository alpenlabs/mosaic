//! Internal state types for the network service.
//!
//! This module contains the service state, internal events, and helper types
//! used by the main loop and handlers.

use std::{sync::Arc, time::Duration};

use ahash::HashMap;
use kanal::AsyncSender;
use quinn::Endpoint;

use crate::{
    api::{OpenStreamError, Stream},
    config::NetServiceConfig,
    tls::PeerId,
};

/// Direction metadata for a stored connection.
///
/// This is used to make deterministic choices when both peers connect
/// simultaneously (inbound + outbound connections racing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// Connection accepted by our endpoint.
    Incoming,
    /// Connection initiated by us.
    Outgoing,
}

/// Stored connection plus metadata.
#[derive(Debug, Clone)]
pub struct TrackedConnection {
    pub connection: quinn::Connection,
    pub direction: ConnectionDirection,
}

/// Default connection timeout (5 seconds).
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for reading stream headers (5 seconds).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for opening bidirectional streams (5 seconds).
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for writing stream headers (5 seconds).
pub const STREAM_HEADER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Internal service state (owned by main loop, no mutex needed).
pub struct ServiceState {
    /// Shared configuration.
    pub config: Arc<NetServiceConfig>,
    /// QUIC endpoint.
    pub endpoint: Endpoint,
    /// Client config for outbound connections.
    pub client_config: quinn::ClientConfig,

    /// Active connections by peer ID.
    ///
    /// Connections are tracked with metadata so the service can make a
    /// deterministic decision when inbound/outbound connections race, instead
    /// of always closing/replacing arbitrarily.
    pub connections: HashMap<PeerId, TrackedConnection>,

    /// Pending bulk transfer registrations.
    /// Key: (peer_id, blake3_hash(identifier))
    pub bulk_expectations: HashMap<(PeerId, [u8; 32]), AsyncSender<Stream>>,

    /// Channel to send incoming protocol streams to handles.
    pub protocol_stream_tx: AsyncSender<Stream>,

    /// Peers that need reconnection with their next attempt time.
    pub pending_reconnects: Vec<(PeerId, tokio::time::Instant)>,

    /// Peers currently being connected to (to avoid duplicate attempts).
    pub connecting: hashbrown::HashSet<PeerId>,

    /// Pending stream requests waiting for connection.
    pub pending_stream_requests: HashMap<PeerId, Vec<PendingStreamRequest>>,

    /// Event sender for spawned tasks to communicate back.
    pub event_tx: AsyncSender<ServiceEvent>,
}

/// A pending request to open a stream.
pub struct PendingStreamRequest {
    /// Type of stream to open.
    pub stream_type: mosaic_net_wire::StreamType,
    /// Stream priority.
    pub priority: i32,
    /// Channel to send the result back to the caller.
    pub respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
}

/// Events from spawned tasks back to the main loop.
///
/// These events are sent by spawned tasks to report their results.
/// The main loop processes these events to update state and spawn
/// follow-up tasks as needed.
pub enum ServiceEvent {
    /// Incoming connection completed TLS handshake.
    IncomingConnectionReady {
        peer: PeerId,
        connection: quinn::Connection,
    },
    /// Incoming connection was rejected.
    IncomingConnectionRejected { reason: String },
    /// Outbound connection attempt succeeded.
    OutboundConnectionReady {
        peer: PeerId,
        connection: quinn::Connection,
    },
    /// Outbound connection attempt failed.
    OutboundConnectionFailed { peer: PeerId, error: String },
    /// A connection was lost.
    ConnectionLost { peer: PeerId, reason: String },
    /// A new stream arrived on a connection (header not yet read).
    IncomingStream {
        peer: PeerId,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    /// Stream header was read, ready for routing.
    StreamReady {
        peer: PeerId,
        stream_type: mosaic_net_wire::StreamType,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    /// Failed to read stream header.
    StreamHeaderFailed { peer: PeerId, error: String },
}

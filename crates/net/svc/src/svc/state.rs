//! Internal state types for the network service.
//!
//! This module contains the service state, internal events, and helper types
//! used by the main loop and handlers.

use std::{
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

use ahash::{HashMap, HashSet};
use kanal::AsyncSender;
use quinn::Endpoint;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{OpenStreamError, Stream},
    config::NetServiceConfig,
    tls::PeerId,
};

/// Unique identifier for an accepted incoming candidate.
pub type IncomingCandidateId = u64;
/// Opaque overlap identity for one establishment window.
pub type OverlapKey = u64;

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
    /// Monotonic generation used to ignore stale monitor events.
    pub generation: u64,
    /// Establishment-window identity used for race matching.
    pub overlap_key: OverlapKey,
}

/// Default connection timeout (5 seconds).
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for reading stream headers (5 seconds).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for opening bidirectional streams (5 seconds).
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for writing stream headers (5 seconds).
pub const STREAM_HEADER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Metadata for a single outbound connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundAttempt {
    pub attempt_id: u64,
    pub started_at: tokio::time::Instant,
    pub overlap_key: OverlapKey,
}

/// Metadata for an accepted incoming candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncomingCandidate {
    pub candidate_id: IncomingCandidateId,
    pub peer_guess: PeerId,
    pub accepted_at: tokio::time::Instant,
    pub overlap_key: OverlapKey,
}

/// Lifecycle state for a stream-open request identified by request ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRequestState {
    /// Request is queued waiting for a usable connection to this peer.
    Pending { peer: PeerId },
    /// Request has been handed to a spawned stream opener task.
    InFlight { peer: PeerId, generation: u64 },
}

/// Shared cancellation markers for stream-open requests.
pub struct OpenRequestCancelRegistry {
    canceled: Mutex<HashSet<u64>>,
}

impl OpenRequestCancelRegistry {
    pub fn new() -> Self {
        Self {
            canceled: Mutex::new(HashSet::default()),
        }
    }

    pub fn cancel(&self, request_id: u64) {
        self.canceled
            .lock()
            .expect("open-request cancel registry mutex poisoned")
            .insert(request_id);
    }

    pub fn take_if_canceled(&self, request_id: u64) -> bool {
        self.canceled
            .lock()
            .expect("open-request cancel registry mutex poisoned")
            .remove(&request_id)
    }

    pub fn is_canceled(&self, request_id: u64) -> bool {
        self.canceled
            .lock()
            .expect("open-request cancel registry mutex poisoned")
            .contains(&request_id)
    }

    pub fn clear(&self, request_id: u64) {
        self.canceled
            .lock()
            .expect("open-request cancel registry mutex poisoned")
            .remove(&request_id);
    }
}

/// Explicit connection state for a single peer.
#[derive(Debug, Clone)]
pub enum PeerConnectionState {
    /// No active connection and no outbound attempt in flight.
    Idle,
    /// Outbound attempt is in flight.
    ConnectingOutbound { attempt: OutboundAttempt },
    /// Single stable connection selected for this peer.
    ActiveStable { connection: TrackedConnection },
    /// Simultaneous-connect race resolution in progress.
    ///
    /// `provisional` is the first accepted connection. We keep it active while
    /// waiting for the opposite-direction candidate.
    Race {
        provisional: TrackedConnection,
        pending_direction: ConnectionDirection,
        /// Eligible matching incoming-ready candidate selected while race remains unresolved.
        eligible_incoming_candidate_id: Option<IncomingCandidateId>,
        /// Attempt ID for pending outbound candidate (when pending direction is Outgoing).
        pending_outbound_attempt: Option<OutboundAttempt>,
    },
}

/// Internal service state (owned by main loop, no mutex needed).
pub struct ServiceState {
    /// Shared configuration.
    pub config: Arc<NetServiceConfig>,
    /// QUIC endpoint.
    pub endpoint: Endpoint,
    /// Client config for outbound connections.
    pub client_config: quinn::ClientConfig,

    /// Per-peer connection FSM state.
    pub peer_states: HashMap<PeerId, PeerConnectionState>,

    /// Pending bulk transfer registrations.
    /// Key: (peer_id, blake3_hash(identifier))
    pub bulk_expectations: HashMap<(PeerId, [u8; 32]), AsyncSender<Stream>>,

    /// Channel to send incoming protocol streams to handles.
    pub protocol_stream_tx: AsyncSender<Stream>,

    /// Peers that need reconnection with their next attempt time.
    pub pending_reconnects: Vec<(PeerId, tokio::time::Instant)>,

    /// Pending stream requests waiting for connection.
    pub pending_stream_requests: HashMap<PeerId, Vec<PendingStreamRequest>>,
    /// Stream-open request lifecycle states by request ID.
    pub open_request_states: HashMap<u64, OpenRequestState>,
    /// Response channels for in-flight stream-open requests.
    pub in_flight_open_responders: HashMap<u64, AsyncSender<Result<Stream, OpenStreamError>>>,
    /// Cancellation markers for stream-open requests.
    pub open_request_cancels: Arc<OpenRequestCancelRegistry>,

    /// Incoming candidates indexed by candidate ID.
    pub pending_incoming_by_id: HashMap<IncomingCandidateId, IncomingCandidate>,
    /// Incoming candidate IDs bucketed by predicted peer.
    pub pending_incoming_by_peer: HashMap<PeerId, HashSet<IncomingCandidateId>>,
    /// Recently resolved incoming candidate IDs (to ignore late accepts).
    pub resolved_incoming_candidate_ids: HashSet<IncomingCandidateId>,

    /// Event sender for spawned tasks to communicate back.
    pub event_tx: UnboundedSender<ServiceEvent>,

    /// Monotonic outbound attempt sequence for stale-event filtering.
    pub next_outbound_attempt_id: u64,
    /// Monotonic overlap-key sequence.
    pub next_overlap_key: OverlapKey,

    /// Monotonic connection generation for stale monitor events.
    pub next_connection_generation: u64,

    /// Last resolved outbound attempt ID by peer.
    pub resolved_outbound_attempt_by_peer: HashMap<PeerId, u64>,
}

impl ServiceState {
    /// Allocate the next outbound attempt ID.
    pub fn allocate_outbound_attempt_id(&mut self) -> u64 {
        let id = self.next_outbound_attempt_id;
        self.next_outbound_attempt_id = self.next_outbound_attempt_id.wrapping_add(1);
        if self.next_outbound_attempt_id == 0 {
            // Keep IDs non-zero for easier debugging.
            self.next_outbound_attempt_id = 1;
        }
        id
    }

    /// Allocate the next connection generation.
    pub fn allocate_connection_generation(&mut self) -> u64 {
        let id = self.next_connection_generation;
        self.next_connection_generation = self.next_connection_generation.wrapping_add(1);
        if self.next_connection_generation == 0 {
            self.next_connection_generation = 1;
        }
        id
    }

    /// Allocate the next overlap key.
    pub fn allocate_overlap_key(&mut self) -> OverlapKey {
        let key = self.next_overlap_key;
        self.next_overlap_key = self.next_overlap_key.wrapping_add(1);
        if self.next_overlap_key == 0 {
            self.next_overlap_key = 1;
        }
        key
    }
}

/// A pending request to open a stream.
pub struct PendingStreamRequest {
    /// Unique request ID used for explicit cancellation.
    pub request_id: u64,
    /// Shared cancel token set by API future drop.
    pub cancel_token: Arc<AtomicBool>,
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
    /// Incoming connection was accepted by the endpoint for a known peer address.
    IncomingConnectionAccepted {
        peer_guess: PeerId,
        accepted_at: tokio::time::Instant,
        candidate_id: IncomingCandidateId,
        overlap_key: OverlapKey,
    },
    /// Incoming connection completed TLS handshake.
    IncomingConnectionReady {
        peer_auth: PeerId,
        peer_guess: PeerId,
        candidate_id: IncomingCandidateId,
        accepted_at: tokio::time::Instant,
        overlap_key: OverlapKey,
        connection: quinn::Connection,
    },
    /// Incoming connection was rejected.
    IncomingConnectionRejected {
        peer_guess: Option<PeerId>,
        peer_auth_opt: Option<PeerId>,
        candidate_id: IncomingCandidateId,
        reason: String,
    },
    /// Outbound connection attempt succeeded.
    OutboundConnectionReady {
        peer: PeerId,
        attempt: OutboundAttempt,
        ready_at: tokio::time::Instant,
        connection: quinn::Connection,
    },
    /// Outbound connection attempt failed.
    OutboundConnectionFailed {
        peer: PeerId,
        attempt_id: u64,
        error: String,
    },
    /// A connection was lost.
    ConnectionLost {
        peer: PeerId,
        generation: u64,
        reason: String,
    },
    /// A new stream arrived on a connection (header not yet read).
    IncomingStream {
        peer: PeerId,
        generation: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    /// Stream header was read, ready for routing.
    StreamReady {
        peer: PeerId,
        generation: u64,
        stream_type: mosaic_net_wire::StreamType,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    /// Failed to read stream header.
    StreamHeaderFailed {
        peer: PeerId,
        generation: u64,
        error: String,
    },
    /// Stream-open request task has finished.
    StreamOpenFinished {
        request_id: u64,
        generation: u64,
        result: Result<Stream, OpenStreamError>,
        respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
    },
}

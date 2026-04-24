//! Spawned task functions for the network service.
//!
//! This module contains all the async tasks that are spawned by the main loop.
//! These tasks perform I/O operations and report results back via the event channel.
//!
//! # Design Principle
//!
//! The main loop never awaits I/O directly. Instead, it spawns tasks from this
//! module which do the actual work and send events back when done.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::HashMap;
use kanal::AsyncSender;
use quinn::Endpoint;
use tokio::sync::mpsc::UnboundedSender;
use tracing::Instrument;

use super::{
    conn,
    state::{
        CONNECTION_TIMEOUT, HEADER_READ_TIMEOUT, IncomingCandidateId, OpenRequestCancelRegistry,
        OutboundAttempt, OverlapKey, PROTOCOL_FIRST_PAYLOAD_TIMEOUT, ServiceEvent,
    },
    stream,
};
use crate::{
    api::{InboundProtocolStream, OpenStreamError, Stream},
    close_codes::{
        CLOSE_INVALID_OVERLAP_KEY, CLOSE_INVALID_PEER_ID_INCOMING, CLOSE_INVALID_PEER_ID_OUTBOUND,
        CLOSE_PEER_ID_MISMATCH, CLOSE_UNKNOWN_PEER,
    },
    svc::state::{STREAM_HEADER_WRITE_TIMEOUT, STREAM_OPEN_TIMEOUT},
    tls::PeerId,
};

/// Max concurrent inbound handshakes accepted by the service.
///
/// Excess attempts are refused immediately to bound CPU/memory pressure from
/// handshake floods.
const MAX_CONCURRENT_INCOMING_HANDSHAKES: usize = 128;

/// Per-IP reject threshold before temporary blocking starts.
const INBOUND_REJECT_THRESHOLD: u32 = 8;
/// Base temporary block duration after threshold is exceeded.
const INBOUND_REJECT_BASE_BLOCK: Duration = Duration::from_millis(250);
/// Maximum temporary block duration for abusive IPs.
const INBOUND_REJECT_MAX_BLOCK: Duration = Duration::from_secs(10);
/// Decay window for reject counters.
const INBOUND_REJECT_DECAY: Duration = Duration::from_secs(30);
/// Maximum tracked source IP entries.
const INBOUND_REJECT_MAX_TRACKED_IPS: usize = 8192;
/// Prefix used for overlap-key metadata encoded in TLS server_name.
const OVERLAP_SERVER_NAME_PREFIX: &str = "ovk-";
/// Suffix used for overlap-key metadata encoded in TLS server_name.
const OVERLAP_SERVER_NAME_SUFFIX: &str = ".mosaic";

fn overlap_server_name(overlap_key: OverlapKey) -> String {
    format!(
        "{}{:016x}{}",
        OVERLAP_SERVER_NAME_PREFIX, overlap_key, OVERLAP_SERVER_NAME_SUFFIX
    )
}

fn parse_overlap_key_from_server_name(server_name: &str) -> Option<OverlapKey> {
    let hex = server_name
        .strip_prefix(OVERLAP_SERVER_NAME_PREFIX)?
        .strip_suffix(OVERLAP_SERVER_NAME_SUFFIX)?;
    if hex.len() != 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let key = u64::from_str_radix(hex, 16).ok()?;
    (key != 0).then_some(key)
}

fn extract_overlap_key_from_handshake(connection: &quinn::Connection) -> Option<OverlapKey> {
    let data = connection.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    let server_name = data.server_name.as_deref()?;
    parse_overlap_key_from_server_name(server_name)
}

#[derive(Clone, Copy)]
struct InboundIpState {
    consecutive_rejects: u32,
    blocked_until: tokio::time::Instant,
    last_event: tokio::time::Instant,
}

struct InboundRejectTracker {
    by_ip: Mutex<HashMap<IpAddr, InboundIpState>>,
}

impl InboundRejectTracker {
    fn new() -> Self {
        Self {
            by_ip: Mutex::new(HashMap::default()),
        }
    }

    fn should_accept(&self, ip: IpAddr, now: tokio::time::Instant) -> bool {
        let mut guard = self.by_ip.lock().expect("reject tracker mutex poisoned");
        if let Some(state) = guard.get_mut(&ip) {
            if now.duration_since(state.last_event) >= INBOUND_REJECT_DECAY {
                state.consecutive_rejects = 0;
                state.blocked_until = now;
            }
            state.last_event = now;
            return state.blocked_until <= now;
        }
        true
    }

    fn on_success(&self, ip: IpAddr) {
        let mut guard = self.by_ip.lock().expect("reject tracker mutex poisoned");
        guard.remove(&ip);
    }

    fn on_reject(&self, ip: IpAddr, now: tokio::time::Instant) {
        let mut guard = self.by_ip.lock().expect("reject tracker mutex poisoned");

        if !guard.contains_key(&ip)
            && guard.len() >= INBOUND_REJECT_MAX_TRACKED_IPS
            && let Some(victim) = guard.keys().next().copied()
        {
            guard.remove(&victim);
        }

        let state = guard.entry(ip).or_insert(InboundIpState {
            consecutive_rejects: 0,
            blocked_until: now,
            last_event: now,
        });

        if now.duration_since(state.last_event) >= INBOUND_REJECT_DECAY {
            state.consecutive_rejects = 0;
            state.blocked_until = now;
        }
        state.last_event = now;
        state.consecutive_rejects = state.consecutive_rejects.saturating_add(1);

        if state.consecutive_rejects >= INBOUND_REJECT_THRESHOLD {
            let over = state.consecutive_rejects - INBOUND_REJECT_THRESHOLD;
            let exponent = over.min(6);
            let block_for = INBOUND_REJECT_BASE_BLOCK
                .saturating_mul(1u32 << exponent)
                .min(INBOUND_REJECT_MAX_BLOCK);
            state.blocked_until = now + block_for;
        }
    }
}

struct IncomingHandshakeCtx {
    accepted_at: tokio::time::Instant,
    predicted_peer: Option<PeerId>,
    candidate_id: IncomingCandidateId,
    remote_ip: IpAddr,
    allowed_peers: Arc<HashSet<PeerId>>,
    event_tx: UnboundedSender<ServiceEvent>,
    reject_tracker: Arc<InboundRejectTracker>,
    _handshake_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Normalize addresses for safe pre-auth peer inference.
///
/// This maps IPv4-mapped IPv6 addresses to pure IPv4 so endpoint-reported
/// addresses and config entries compare consistently.
pub(super) fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => addr,
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                SocketAddr::V6(v6)
            }
        }
    }
}

/// Spawn a task that continuously accepts incoming QUIC connections.
///
/// Each accepted connection is handed to a separate handshake task with an
/// `accepted_at` timestamp captured at accept time.
pub fn spawn_accept_loop(
    endpoint: Endpoint,
    allowed_peers: Arc<HashSet<PeerId>>,
    peer_by_addr: Arc<HashMap<SocketAddr, PeerId>>,
    peer_by_port: Arc<HashMap<u16, PeerId>>,
    peer_by_ip: Arc<HashMap<IpAddr, PeerId>>,
    event_tx: UnboundedSender<ServiceEvent>,
) {
    tokio::spawn(
        async move {
            let handshake_slots = Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_INCOMING_HANDSHAKES,
            ));
            let reject_tracker = Arc::new(InboundRejectTracker::new());
            let mut next_candidate_id: IncomingCandidateId = 1;

            let mut allocate_candidate_id = || {
                let id = next_candidate_id;
                next_candidate_id = next_candidate_id.wrapping_add(1);
                if next_candidate_id == 0 {
                    next_candidate_id = 1;
                }
                id
            };

            loop {
                let incoming = match endpoint.accept().await {
                    Some(incoming) => incoming,
                    None => break, // endpoint closed
                };
                let accepted_at = tokio::time::Instant::now();
                let remote_addr = normalize_socket_addr(incoming.remote_address());
                let remote_ip = remote_addr.ip();

                if !reject_tracker.should_accept(remote_ip, accepted_at) {
                    tracing::warn!(remote = %remote_addr, "rate-limiting incoming connection");
                    incoming.refuse();
                    continue;
                }

                let predicted_peer = peer_by_addr
                    .get(&remote_addr)
                    .copied()
                    .or_else(|| peer_by_port.get(&remote_addr.port()).copied())
                    .or_else(|| peer_by_ip.get(&remote_ip).copied());
                let candidate_id = allocate_candidate_id();

                let permit = match handshake_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(
                            remote = %remote_addr,
                            limit = MAX_CONCURRENT_INCOMING_HANDSHAKES,
                            "refusing incoming: handshake concurrency limit reached"
                        );
                        reject_tracker.on_reject(remote_ip, accepted_at);
                        incoming.refuse();
                        let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                            peer_guess: predicted_peer,
                            peer_auth_opt: predicted_peer,
                            candidate_id,
                            reason: "too many concurrent incoming handshakes".to_string(),
                        });
                        continue;
                    }
                };

                spawn_incoming_connection_handler(
                    incoming,
                    IncomingHandshakeCtx {
                        accepted_at,
                        predicted_peer,
                        candidate_id,
                        remote_ip,
                        allowed_peers: allowed_peers.clone(),
                        event_tx: event_tx.clone(),
                        reject_tracker: reject_tracker.clone(),
                        _handshake_permit: permit,
                    },
                );
            }
        }
        .instrument(tracing::info_span!("net_svc.accept_loop")),
    );
}

/// Spawn a task to handle an incoming connection's TLS handshake.
///
/// This completes the TLS handshake, extracts the peer ID from the certificate,
/// verifies the peer is allowed, and sends the result back via the event channel.
fn spawn_incoming_connection_handler(incoming: quinn::Incoming, ctx: IncomingHandshakeCtx) {
    let remote_ip = ctx.remote_ip;
    let candidate_id = ctx.candidate_id;
    let predicted_peer = ctx.predicted_peer;
    tokio::spawn(
        async move {
            let IncomingHandshakeCtx {
                accepted_at,
                predicted_peer,
                candidate_id,
                remote_ip,
                allowed_peers,
                event_tx,
                reject_tracker,
                _handshake_permit,
            } = ctx;

            // Complete TLS handshake with timeout to avoid hanging race resolution.
            let connection = match tokio::time::timeout(CONNECTION_TIMEOUT, incoming).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    reject_tracker.on_reject(remote_ip, tokio::time::Instant::now());
                    let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                        peer_guess: predicted_peer,
                        peer_auth_opt: predicted_peer,
                        candidate_id,
                        reason: e.to_string(),
                    });
                    return;
                }
                Err(_) => {
                    reject_tracker.on_reject(remote_ip, tokio::time::Instant::now());
                    let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                        peer_guess: predicted_peer,
                        peer_auth_opt: predicted_peer,
                        candidate_id,
                        reason: "incoming handshake timed out".to_string(),
                    });
                    return;
                }
            };

            // Extract peer ID from certificate
            let peer_id = match conn::extract_peer_id(&connection) {
                Some(id) => id,
                None => {
                    reject_tracker.on_reject(remote_ip, tokio::time::Instant::now());
                    connection.close(CLOSE_INVALID_PEER_ID_INCOMING, b"invalid peer id");
                    let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                        peer_guess: predicted_peer,
                        peer_auth_opt: predicted_peer,
                        candidate_id,
                        reason: "invalid peer id".to_string(),
                    });
                    return;
                }
            };

            // Verify peer is allowed (O(1) membership via HashSet)
            if !allowed_peers.contains(&peer_id) {
                reject_tracker.on_reject(remote_ip, tokio::time::Instant::now());
                tracing::warn!(peer = %hex::encode(peer_id), "rejected unknown peer");
                connection.close(CLOSE_UNKNOWN_PEER, b"unknown peer");
                let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                    peer_guess: predicted_peer,
                    peer_auth_opt: Some(peer_id),
                    candidate_id,
                    reason: "unknown peer".to_string(),
                });
                return;
            }

            reject_tracker.on_success(remote_ip);
            tracing::debug!(peer = %hex::encode(peer_id), "incoming handshake completed");

            let overlap_key = match extract_overlap_key_from_handshake(&connection) {
                Some(key) => key,
                None => {
                    reject_tracker.on_reject(remote_ip, tokio::time::Instant::now());
                    connection.close(CLOSE_INVALID_OVERLAP_KEY, b"invalid overlap key");
                    let _ = event_tx.send(ServiceEvent::IncomingConnectionRejected {
                        peer_guess: predicted_peer,
                        peer_auth_opt: Some(peer_id),
                        candidate_id,
                        reason: "invalid overlap key".to_string(),
                    });
                    return;
                }
            };

            let peer_guess = predicted_peer.unwrap_or(peer_id);
            if event_tx
                .send(ServiceEvent::IncomingConnectionAccepted {
                    peer_guess,
                    accepted_at,
                    candidate_id,
                    overlap_key,
                })
                .is_err()
            {
                return;
            }

            let _ = event_tx.send(ServiceEvent::IncomingConnectionReady {
                peer_auth: peer_id,
                peer_guess,
                candidate_id,
                accepted_at,
                overlap_key,
                connection,
            });
        }
        .instrument(tracing::debug_span!(
            "net_svc.incoming_handshake",
            remote_ip = %remote_ip,
            candidate_id,
            predicted_peer = ?predicted_peer
        )),
    );
}

/// Spawn a task to attempt an outbound connection.
///
/// This attempts to connect to a peer with a timeout and sends the result
/// back via the event channel.
pub fn spawn_outbound_connection(
    endpoint: Endpoint,
    client_config: quinn::ClientConfig,
    peer: PeerId,
    attempt: OutboundAttempt,
    addr: std::net::SocketAddr,
    event_tx: UnboundedSender<ServiceEvent>,
) {
    tokio::spawn(async move {
        tracing::debug!(peer = %hex::encode(peer), addr = %addr, "attempting outbound connection");

        let server_name = overlap_server_name(attempt.overlap_key);
        let result = async {
            let connecting = endpoint
                .connect_with(client_config, addr, &server_name)
                .map_err(|e| e.to_string())?;

            tokio::time::timeout(CONNECTION_TIMEOUT, connecting)
                .await
                .map_err(|_| "connection timed out".to_string())?
                .map_err(|e| e.to_string())
        }
        .await;

        match result {
            Ok(connection) => {
                // Verify the remote peer identity matches the intended peer.
                let observed_peer = match conn::extract_peer_id(&connection) {
                    Some(id) => id,
                    None => {
                        connection.close(CLOSE_INVALID_PEER_ID_OUTBOUND, b"invalid peer id");
                        let _ = event_tx.send(ServiceEvent::OutboundConnectionFailed {
                            peer,
                            attempt_id: attempt.attempt_id,
                            error: "invalid peer id".to_string(),
                        });
                        return;
                    }
                };

                if observed_peer != peer {
                    connection.close(CLOSE_PEER_ID_MISMATCH, b"peer id mismatch");
                    let _ = event_tx.send(ServiceEvent::OutboundConnectionFailed {
                        peer,
                        attempt_id: attempt.attempt_id,
                        error: "peer id mismatch".to_string(),
                    });
                    return;
                }

                tracing::debug!(peer = %hex::encode(peer), "outbound handshake completed");
                if let Err(error) = event_tx.send(ServiceEvent::OutboundConnectionReady {
                    peer,
                    attempt,
                    ready_at: tokio::time::Instant::now(),
                    connection,
                }) {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        attempt_id = attempt.attempt_id,
                        send_error = %error,
                        "failed to send outbound-ready event to service loop"
                    );
                }
            }
            Err(ref error) => {
                tracing::debug!(peer = %hex::encode(peer), error = %error, "outbound connection failed");
                if let Err(send_error) = event_tx.send(ServiceEvent::OutboundConnectionFailed {
                    peer,
                    attempt_id: attempt.attempt_id,
                    error: error.clone(),
                }) {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        attempt_id = attempt.attempt_id,
                        send_error = %send_error,
                        "failed to send outbound-failed event to service loop"
                    );
                }
            }
        }
    }.instrument(tracing::debug_span!(
        "net_svc.outbound_connect",
        peer = %hex::encode(peer),
        attempt_id = attempt.attempt_id,
        addr = %addr
    )));
}

/// Spawn a task to monitor a connection and accept incoming streams.
///
/// This task runs for the lifetime of a connection, accepting incoming
/// bidirectional streams and sending them to the main loop for routing.
pub fn spawn_connection_monitor(
    peer: PeerId,
    generation: u64,
    connection: quinn::Connection,
    event_tx: UnboundedSender<ServiceEvent>,
) {
    tokio::spawn(
        async move {
            tracing::debug!(peer = %hex::encode(peer), "connection monitor started");

            loop {
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        // Send event to main loop - it will spawn header reading task
                        if event_tx
                            .send(ServiceEvent::IncomingStream {
                                peer,
                                generation,
                                send,
                                recv,
                            })
                            .is_err()
                        {
                            // Main loop shut down
                            break;
                        }
                    }
                    Err(e) => {
                        let reason = match &e {
                            quinn::ConnectionError::ConnectionClosed(f) => {
                                format!("closed: {:?}", f.reason)
                            }
                            quinn::ConnectionError::ApplicationClosed(f) => {
                                format!("app closed: {:?}", f.reason)
                            }
                            quinn::ConnectionError::Reset => "reset".to_string(),
                            quinn::ConnectionError::TimedOut => "timed out".to_string(),
                            quinn::ConnectionError::TransportError(te) => {
                                format!("transport: {}", te)
                            }
                            quinn::ConnectionError::LocallyClosed => "locally closed".to_string(),
                            _ => format!("{}", e),
                        };

                        let _ = event_tx.send(ServiceEvent::ConnectionLost {
                            peer,
                            generation,
                            reason,
                        });
                        break;
                    }
                }
            }

            tracing::debug!(peer = %hex::encode(peer), "connection monitor ended");
        }
        .instrument(tracing::debug_span!(
            "net_svc.connection_monitor",
            peer = %hex::encode(peer),
            generation
        )),
    );
}

/// Spawn a task to read a stream header.
///
/// This reads the stream header with a timeout and sends the result back
/// via the event channel for routing.
pub fn spawn_stream_header_reader(
    peer: PeerId,
    generation: u64,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    event_tx: UnboundedSender<ServiceEvent>,
) {
    tokio::spawn(async move {
        let result = async {
            let mut buf = [0u8; 33];

            // Read type byte
            tokio::time::timeout(HEADER_READ_TIMEOUT, recv.read_exact(&mut buf[0..1]))
                .await
                .map_err(|_| "header read timed out")?
                .map_err(|e| e.to_string())?;

            // Determine remaining bytes
            let remaining = match buf[0] {
                0x00 => 0,  // Protocol
                0x01 => 32, // BulkTransfer
                tag => return Err(format!("unknown stream type: 0x{:02x}", tag)),
            };

            // Read remaining bytes
            if remaining > 0 {
                tokio::time::timeout(
                    HEADER_READ_TIMEOUT,
                    recv.read_exact(&mut buf[1..1 + remaining]),
                )
                .await
                .map_err(|_| "header read timed out")?
                .map_err(|e| e.to_string())?;
            }

            // Decode header
            let (header, _) = mosaic_net_wire::StreamHeader::decode(&buf[..1 + remaining])
                .map_err(|e| e.to_string())?;

            Ok(header.stream_type)
        }
        .await;

        match result {
            Ok(stream_type) => {
                let _ = event_tx.send(ServiceEvent::StreamReady {
                    peer,
                    generation,
                    stream_type,
                    send,
                    recv,
                });
            }
            Err(error) => {
                tracing::debug!(peer = %hex::encode(peer), error = %error, "failed to read stream header");
                let _ = send.reset(0u32.into());
                let _ = event_tx.send(ServiceEvent::StreamHeaderFailed {
                    peer,
                    generation,
                    error,
                });
            }
        }
    }.instrument(tracing::debug_span!(
        "net_svc.stream_header_reader",
        peer = %hex::encode(peer),
        generation
    )));
}

/// Spawn a task to open a stream on an existing connection.
///
/// This opens a bidirectional stream, sets priority, writes the header,
/// and sends the result back to the caller.
pub struct StreamOpenCtx {
    pub request_id: u64,
    pub peer: PeerId,
    pub generation: u64,
    pub connection: quinn::Connection,
    pub cancel_token: Arc<AtomicBool>,
    pub stream_type: mosaic_net_wire::StreamType,
    pub priority: i32,
    pub respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
    pub cancel_registry: Arc<OpenRequestCancelRegistry>,
    pub event_tx: UnboundedSender<ServiceEvent>,
}

pub fn spawn_stream_opener(ctx: StreamOpenCtx) {
    tokio::spawn(async move {
        let StreamOpenCtx {
            request_id,
            peer,
            generation,
            connection,
            cancel_token,
            stream_type,
            priority,
            respond_to,
            cancel_registry,
            event_tx,
        } = ctx;

        let canceled_error =
            || OpenStreamError::ConnectionFailed("stream open request canceled".to_string());
        let is_canceled =
            || cancel_token.load(Ordering::Acquire) || cancel_registry.is_canceled(request_id);

        let result = async {
            if is_canceled() {
                return Err(canceled_error());
            }

            // Open bidirectional stream
            let (mut send, recv) = tokio::time::timeout(STREAM_OPEN_TIMEOUT, connection.open_bi())
                .await
                .map_err(|_| OpenStreamError::StreamFailed("open stream timed out".to_string()))?
                .map_err(|e| OpenStreamError::StreamFailed(e.to_string()))?;

            if is_canceled() {
                let _ = send.reset(0u32.into());
                return Err(canceled_error());
            }

            // Set priority
            let _ = send.set_priority(priority);

            // Write stream header
            let header = mosaic_net_wire::StreamHeader::new(stream_type);
            let mut header_buf = Vec::new();
            header.encode(&mut header_buf);

            match tokio::time::timeout(STREAM_HEADER_WRITE_TIMEOUT, send.write_all(&header_buf))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = send.reset(0u32.into());
                    return Err(OpenStreamError::StreamFailed(e.to_string()));
                }
                Err(_) => {
                    let _ = send.reset(0u32.into());
                    return Err(OpenStreamError::StreamFailed(
                        "stream header write timed out".to_string(),
                    ));
                }
            }

            if is_canceled() {
                let _ = send.reset(0u32.into());
                return Err(canceled_error());
            }

            // Create stream handle
            Ok(stream::create_stream(peer, send, recv))
        }
        .await;

        let result = match result {
            Ok(stream) if is_canceled() => {
                stream.reset(0).await;
                Err(canceled_error())
            }
            other => other,
        };

        let event = ServiceEvent::StreamOpenFinished {
            request_id,
            generation,
            result,
            respond_to: respond_to.clone(),
        };

        // Report completion to the service loop so generation/currentness checks
        // drive final delivery and cleanup.
        if event_tx.send(event).is_err() {
            // Service loop is down; best-effort fail-fast response.
            let _ = respond_to
                .send(Err(OpenStreamError::ConnectionFailed(
                    "network service unavailable".to_string(),
                )))
                .await;
            cancel_registry.clear(request_id);
        }
    });
}

/// Spawn a task to route a protocol stream to the protocol stream channel.
///
/// This creates a Stream handle and sends it to the protocol stream channel.
pub fn spawn_protocol_stream_router(
    peer: PeerId,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    protocol_stream_tx: AsyncSender<InboundProtocolStream>,
) {
    tokio::spawn(async move {
        let mut recv = recv;
        match read_first_protocol_payload(&mut recv).await {
            Ok(payload) => {
                let _ = recv.stop(0u32.into());
                let stream = stream::create_write_only_stream(peer, send);
                let inbound = InboundProtocolStream::new(peer, payload, stream);
                if protocol_stream_tx.send(inbound).await.is_err() {
                    tracing::debug!(peer = %hex::encode(peer), "protocol stream channel closed");
                }
            }
            Err(error) => {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    error = %error,
                    "failed to read first protocol payload"
                );
                let _ = recv.stop(0u32.into());
                let mut send = send;
                let _ = send.reset(0u32.into());
            }
        }
    });
}

/// Spawn a task to route a bulk transfer stream to its expectation.
///
/// This creates a Stream handle and sends it to the registered expectation channel.
pub fn spawn_bulk_stream_router(
    peer: PeerId,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    expectation_tx: AsyncSender<Stream>,
) {
    tokio::spawn(async move {
        let stream = stream::create_stream(peer, send, recv);
        if expectation_tx.send(stream).await.is_err() {
            tracing::debug!(peer = %hex::encode(peer), "bulk expectation channel closed");
        }
    });
}

async fn read_first_protocol_payload(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, String> {
    let limits = mosaic_net_wire::FrameLimits::default();
    let mut buf = Vec::with_capacity(4 * 1024);
    let mut read_buf = [0u8; 64 * 1024];
    let deadline = Instant::now() + PROTOCOL_FIRST_PAYLOAD_TIMEOUT;

    loop {
        match mosaic_net_wire::decode_frame(&buf, &limits) {
            Ok((payload, consumed)) => {
                if consumed != buf.len() {
                    return Err("extra data after first protocol frame".to_string());
                }
                return Ok(payload);
            }
            Err(mosaic_net_wire::DecodeError::Incomplete { .. }) => {}
            Err(mosaic_net_wire::DecodeError::FrameTooLarge { size, max }) => {
                return Err(format!(
                    "protocol frame too large: size={} max={}",
                    size, max
                ));
            }
            Err(error) => return Err(format!("protocol frame decode error: {}", error)),
        }

        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err("first protocol payload timed out".to_string());
        };

        match tokio::time::timeout(remaining, recv.read(&mut read_buf)).await {
            Ok(Ok(Some(n))) => buf.extend_from_slice(&read_buf[..n]),
            Ok(Ok(None)) => return Err("peer finished before first protocol payload".to_string()),
            Ok(Err(error)) => return Err(format!("read error: {}", error)),
            Err(_) => return Err("first protocol payload timed out".to_string()),
        }
    }
}

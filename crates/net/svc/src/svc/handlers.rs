//! Command and event handlers for the network service.
//!
//! This module contains the handler functions called by the main loop.
//! These handlers update state and spawn tasks but never block on I/O.
//!
//! # Design Principle
//!
//! All handlers in this module are synchronous with respect to I/O.
//! They only:
//! - Update in-memory state
//! - Spawn tasks for I/O operations
//!
//! This ensures the main loop always remains responsive to shutdown signals.

use kanal::{AsyncReceiver, bounded_async};

use super::{
    state::{
        ConnectionDirection, PendingStreamRequest, ServiceEvent, ServiceState, TrackedConnection,
    },
    tasks,
};
use crate::{
    api::{ExpectError, NetCommand, OpenStreamError, Stream},
    tls::PeerId,
};

/// Handle a command from a NetServiceHandle.
///
/// This function NEVER blocks. It either updates state instantly or spawns tasks.
pub fn handle_command(cmd: NetCommand, state: &mut ServiceState) {
    match cmd {
        NetCommand::OpenProtocolStream {
            peer,
            priority,
            respond_to,
        } => {
            handle_open_stream_request(
                peer,
                mosaic_net_wire::StreamType::Protocol,
                priority,
                respond_to,
                state,
            );
        }

        NetCommand::OpenBulkStream {
            peer,
            identifier,
            priority,
            respond_to,
        } => {
            let stream_type = mosaic_net_wire::StreamType::BulkTransfer { identifier };
            handle_open_stream_request(peer, stream_type, priority, respond_to, state);
        }

        NetCommand::ExpectBulkTransfer {
            peer,
            identifier,
            respond_to,
        } => {
            handle_expect_bulk_transfer(peer, identifier, respond_to, state);
        }
    }
}

/// Handle a request to open a stream.
fn handle_open_stream_request(
    peer: PeerId,
    stream_type: mosaic_net_wire::StreamType,
    priority: i32,
    respond_to: kanal::AsyncSender<Result<Stream, OpenStreamError>>,
    state: &mut ServiceState,
) {
    // Check if peer is configured
    if !state.config.has_peer(&peer) {
        // Spawn task to send error response
        tokio::spawn(async move {
            let _ = respond_to.send(Err(OpenStreamError::PeerNotFound)).await;
        });
        return;
    }

    // Check for existing active connection
    if let Some(conn) = state.connections.get(&peer).cloned()
        && conn.connection.close_reason().is_none()
    {
        // Have active connection - spawn stream opener
        tasks::spawn_stream_opener(peer, conn.connection, stream_type, priority, respond_to);
        return;
    }

    // No active connection - queue request and initiate connection if needed
    let request = PendingStreamRequest {
        stream_type,
        priority,
        respond_to,
    };

    state
        .pending_stream_requests
        .entry(peer)
        .or_default()
        .push(request);

    // Start connection if not already connecting
    if !state.connecting.contains(&peer)
        && let Some(addr) = state.config.get_peer_addr(&peer)
    {
        state.connecting.insert(peer);
        tasks::spawn_outbound_connection(
            state.endpoint.clone(),
            state.client_config.clone(),
            peer,
            addr,
            state.event_tx.clone(),
        );
    }
}

/// Handle a request to expect a bulk transfer.
fn handle_expect_bulk_transfer(
    peer: PeerId,
    identifier: [u8; 32],
    respond_to: kanal::AsyncSender<Result<AsyncReceiver<Stream>, ExpectError>>,
    state: &mut ServiceState,
) {
    // Check if peer is configured
    if !state.config.has_peer(&peer) {
        tokio::spawn(async move {
            let _ = respond_to.send(Err(ExpectError::PeerNotFound)).await;
        });
        return;
    }

    let key = (peer, blake3::hash(&identifier).into());

    // Check if already registered
    if state.bulk_expectations.contains_key(&key) {
        tokio::spawn(async move {
            let _ = respond_to.send(Err(ExpectError::AlreadyRegistered)).await;
        });
        return;
    }

    // Create channel for the expectation
    let (tx, rx) = bounded_async(1);
    state.bulk_expectations.insert(key, tx);

    tracing::debug!(
        peer = %hex::encode(peer),
        identifier = %hex::encode(identifier),
        "registered bulk transfer expectation"
    );

    // Send success response
    tokio::spawn(async move {
        let _ = respond_to.send(Ok(rx)).await;
    });
}

/// Handle an event from a spawned task.
///
/// This function NEVER blocks. It only updates state and spawns tasks.
pub fn handle_event(event: ServiceEvent, state: &mut ServiceState) {
    match event {
        ServiceEvent::IncomingConnectionReady { peer, connection } => {
            tracing::info!(peer = %hex::encode(peer), "incoming connection ready");

            // Remove from connecting set if we were also trying to connect outbound
            state.connecting.remove(&peer);

            // Deterministic connection selection based on peer_id ordering.
            //
            // Rule: prefer the connection initiated by the peer with the LOWER peer_id.
            // - Incoming = they initiated the connection
            // - Outgoing = we initiated the connection
            //
            // This ensures both sides agree on which connection to keep during
            // simultaneous connect, avoiding the race where each side closes
            // the other's chosen connection.
            let our_id = state.config.our_peer_id();
            let incoming_is_preferred = our_id > peer; // they have lower id, prefer their connection

            if !incoming_is_preferred {
                // This Incoming is NOT preferred (we have lower id, prefer Outgoing).
                // Always reject it - we'll use our outbound connection instead.
                // This avoids the race where we accept temporarily, process pending
                // requests, then close when the preferred connection arrives.
                tracing::debug!(
                    peer = %hex::encode(peer),
                    "rejecting incoming; prefer outgoing (we have lower peer_id)"
                );
                connection.close(0u32.into(), b"redundant");
                return;
            }

            // This Incoming is the preferred type. Accept it, replacing any existing.
            if let Some(old_conn) = state.connections.remove(&peer) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    old_direction = ?old_conn.direction,
                    "replacing existing connection with preferred incoming"
                );
                old_conn.connection.close(0u32.into(), b"replaced");
            }

            // Store new connection
            state.connections.insert(
                peer,
                TrackedConnection {
                    connection: connection.clone(),
                    direction: ConnectionDirection::Incoming,
                },
            );

            // Remove from pending reconnects
            state.pending_reconnects.retain(|(p, _)| *p != peer);

            // Process any pending stream requests for this peer
            if let Some(requests) = state.pending_stream_requests.remove(&peer) {
                for req in requests {
                    tasks::spawn_stream_opener(
                        peer,
                        connection.clone(),
                        req.stream_type,
                        req.priority,
                        req.respond_to,
                    );
                }
            }

            // Spawn connection monitor
            tasks::spawn_connection_monitor(peer, connection, state.event_tx.clone());
        }

        ServiceEvent::IncomingConnectionRejected { reason } => {
            tracing::debug!(reason = %reason, "incoming connection rejected");
        }

        ServiceEvent::OutboundConnectionReady { peer, connection } => {
            tracing::info!(peer = %hex::encode(peer), "outbound connection ready");

            // Remove from connecting set
            state.connecting.remove(&peer);

            // Deterministic connection selection based on peer_id ordering.
            //
            // Rule: prefer the connection initiated by the peer with the LOWER peer_id.
            // - Incoming = they initiated the connection
            // - Outgoing = we initiated the connection
            //
            // This ensures both sides agree on which connection to keep during
            // simultaneous connect.
            let our_id = state.config.our_peer_id();
            let outgoing_is_preferred = our_id < peer; // we have lower id, prefer our connection

            if !outgoing_is_preferred {
                // This Outgoing is NOT preferred (they have lower id, prefer Incoming).
                // Always reject it - we'll use their inbound connection instead.
                // This avoids the race where we accept temporarily, process pending
                // requests, then close when the preferred connection arrives.
                tracing::debug!(
                    peer = %hex::encode(peer),
                    "rejecting outgoing; prefer incoming (they have lower peer_id)"
                );
                connection.close(0u32.into(), b"redundant");
                return;
            }

            // This Outgoing is the preferred type. Accept it, replacing any existing.
            if let Some(old_conn) = state.connections.remove(&peer) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    old_direction = ?old_conn.direction,
                    "replacing existing connection with preferred outgoing"
                );
                old_conn.connection.close(0u32.into(), b"replaced");
            }

            // Store new connection
            state.connections.insert(
                peer,
                TrackedConnection {
                    connection: connection.clone(),
                    direction: ConnectionDirection::Outgoing,
                },
            );

            // Remove from pending reconnects
            state.pending_reconnects.retain(|(p, _)| *p != peer);

            // Process any pending stream requests for this peer
            if let Some(requests) = state.pending_stream_requests.remove(&peer) {
                for req in requests {
                    tasks::spawn_stream_opener(
                        peer,
                        connection.clone(),
                        req.stream_type,
                        req.priority,
                        req.respond_to,
                    );
                }
            }

            // Spawn connection monitor
            tasks::spawn_connection_monitor(peer, connection, state.event_tx.clone());
        }

        ServiceEvent::OutboundConnectionFailed { peer, error } => {
            tracing::debug!(peer = %hex::encode(peer), error = %error, "outbound connection failed");

            // Remove from connecting set
            state.connecting.remove(&peer);

            // Fail any pending stream requests
            if let Some(requests) = state.pending_stream_requests.remove(&peer) {
                for req in requests {
                    let err = OpenStreamError::ConnectionFailed(error.clone());
                    tokio::spawn(async move {
                        let _ = req.respond_to.send(Err(err)).await;
                    });
                }
            }

            // Schedule retry with backoff
            let next_attempt = tokio::time::Instant::now() + state.config.reconnect_backoff;
            if !state.pending_reconnects.iter().any(|(p, _)| *p == peer) {
                state.pending_reconnects.push((peer, next_attempt));
            }
        }

        ServiceEvent::ConnectionLost { peer, reason } => {
            // Check if we already have a valid connection.
            // If so, this is a stale event from an older connection monitor.
            if let Some(existing) = state.connections.get(&peer)
                && existing.connection.close_reason().is_none()
            {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    reason = %reason,
                    "ignoring connection lost for non-current connection"
                );
                return;
            }

            tracing::warn!(peer = %hex::encode(peer), reason = %reason, "connection lost");

            // Remove connection
            state.connections.remove(&peer);
            state.connecting.remove(&peer);

            // Schedule reconnect with backoff
            let next_attempt = tokio::time::Instant::now() + state.config.reconnect_backoff;
            if !state.pending_reconnects.iter().any(|(p, _)| *p == peer) {
                state.pending_reconnects.push((peer, next_attempt));
            }
        }

        ServiceEvent::IncomingStream { peer, send, recv } => {
            // Spawn task to read stream header
            tasks::spawn_stream_header_reader(peer, send, recv, state.event_tx.clone());
        }

        ServiceEvent::StreamReady {
            peer,
            stream_type,
            send,
            recv,
        } => {
            // Route the stream based on its type
            match stream_type {
                mosaic_net_wire::StreamType::Protocol => {
                    tasks::spawn_protocol_stream_router(
                        peer,
                        send,
                        recv,
                        state.protocol_stream_tx.clone(),
                    );
                }
                mosaic_net_wire::StreamType::BulkTransfer { identifier } => {
                    let hash: [u8; 32] = blake3::hash(&identifier).into();
                    let key = (peer, hash);

                    if let Some(expectation_tx) = state.bulk_expectations.remove(&key) {
                        tasks::spawn_bulk_stream_router(peer, send, recv, expectation_tx);
                    } else {
                        tracing::debug!(
                            peer = %hex::encode(peer),
                            identifier = %hex::encode(identifier),
                            "no expectation for bulk transfer, dropping stream"
                        );
                        // Stream is dropped, peer will see reset
                    }
                }
            }
        }

        ServiceEvent::StreamHeaderFailed { peer, error } => {
            tracing::debug!(peer = %hex::encode(peer), error = %error, "stream header read failed");
            // Stream was already dropped by the task
        }
    }
}

/// Process pending reconnection attempts.
///
/// This function NEVER blocks. It only spawns connection tasks.
pub fn process_pending_reconnects(state: &mut ServiceState) {
    let now = tokio::time::Instant::now();
    let mut to_reconnect = Vec::new();

    // Find peers ready for reconnection
    state.pending_reconnects.retain(|(peer, next_attempt)| {
        if *next_attempt <= now {
            to_reconnect.push(*peer);
            false
        } else {
            true
        }
    });

    // Spawn reconnection attempts
    for peer in to_reconnect {
        // Skip if already connected
        if let Some(conn) = state.connections.get(&peer)
            && conn.connection.close_reason().is_none()
        {
            continue;
        }

        // Skip if already connecting
        if state.connecting.contains(&peer) {
            continue;
        }

        // Get peer address
        let addr = match state.config.get_peer_addr(&peer) {
            Some(addr) => addr,
            None => continue,
        };

        // Mark as connecting and spawn task
        state.connecting.insert(peer);
        tasks::spawn_outbound_connection(
            state.endpoint.clone(),
            state.client_config.clone(),
            peer,
            addr,
            state.event_tx.clone(),
        );
    }
}

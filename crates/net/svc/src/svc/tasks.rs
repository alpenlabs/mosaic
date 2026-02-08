//! Spawned task functions for the network service.
//!
//! This module contains all the async tasks that are spawned by the main loop.
//! These tasks perform I/O operations and report results back via the event channel.
//!
//! # Design Principle
//!
//! The main loop never awaits I/O directly. Instead, it spawns tasks from this
//! module which do the actual work and send events back when done.

use std::{collections::HashSet, sync::Arc};

use kanal::AsyncSender;
use quinn::Endpoint;

use super::{
    conn,
    state::{CONNECTION_TIMEOUT, HEADER_READ_TIMEOUT, ServiceEvent},
    stream,
};
use crate::{
    api::{OpenStreamError, Stream},
    close_codes::{
        CLOSE_INVALID_PEER_ID_INCOMING, CLOSE_INVALID_PEER_ID_OUTBOUND, CLOSE_PEER_ID_MISMATCH,
        CLOSE_UNKNOWN_PEER,
    },
    svc::state::{STREAM_HEADER_WRITE_TIMEOUT, STREAM_OPEN_TIMEOUT},
    tls::PeerId,
};

/// Spawn a task to handle an incoming connection's TLS handshake.
///
/// This completes the TLS handshake, extracts the peer ID from the certificate,
/// verifies the peer is allowed, and sends the result back via the event channel.
pub fn spawn_incoming_connection_handler(
    incoming: quinn::Incoming,
    allowed_peers: Arc<HashSet<PeerId>>,
    event_tx: AsyncSender<ServiceEvent>,
) {
    tokio::spawn(async move {
        // Complete TLS handshake
        let connection = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                let _ = event_tx
                    .send(ServiceEvent::IncomingConnectionRejected {
                        reason: e.to_string(),
                    })
                    .await;
                return;
            }
        };

        // Extract peer ID from certificate
        let peer_id = match conn::extract_peer_id(&connection) {
            Some(id) => id,
            None => {
                connection.close(CLOSE_INVALID_PEER_ID_INCOMING, b"invalid peer id");
                let _ = event_tx
                    .send(ServiceEvent::IncomingConnectionRejected {
                        reason: "invalid peer id".to_string(),
                    })
                    .await;
                return;
            }
        };

        // Verify peer is allowed (O(1) membership via HashSet)
        if !allowed_peers.contains(&peer_id) {
            tracing::warn!(peer = %hex::encode(peer_id), "rejected unknown peer");
            connection.close(CLOSE_UNKNOWN_PEER, b"unknown peer");
            let _ = event_tx
                .send(ServiceEvent::IncomingConnectionRejected {
                    reason: "unknown peer".to_string(),
                })
                .await;
            return;
        }

        tracing::info!(peer = %hex::encode(peer_id), "incoming connection ready");

        let _ = event_tx
            .send(ServiceEvent::IncomingConnectionReady {
                peer: peer_id,
                connection,
            })
            .await;
    });
}

/// Spawn a task to attempt an outbound connection.
///
/// This attempts to connect to a peer with a timeout and sends the result
/// back via the event channel.
pub fn spawn_outbound_connection(
    endpoint: Endpoint,
    client_config: quinn::ClientConfig,
    peer: PeerId,
    addr: std::net::SocketAddr,
    event_tx: AsyncSender<ServiceEvent>,
) {
    tokio::spawn(async move {
        tracing::debug!(peer = %hex::encode(peer), addr = %addr, "attempting outbound connection");

        let result = async {
            let connecting = endpoint
                .connect_with(client_config, addr, "mosaic")
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
                        let _ = event_tx
                            .send(ServiceEvent::OutboundConnectionFailed {
                                peer,
                                error: "invalid peer id".to_string(),
                            })
                            .await;
                        return;
                    }
                };

                if observed_peer != peer {
                    connection.close(CLOSE_PEER_ID_MISMATCH, b"peer id mismatch");
                    let _ = event_tx
                        .send(ServiceEvent::OutboundConnectionFailed {
                            peer,
                            error: "peer id mismatch".to_string(),
                        })
                        .await;
                    return;
                }

                tracing::info!(peer = %hex::encode(peer), "outbound connection ready");
                let _ = event_tx
                    .send(ServiceEvent::OutboundConnectionReady { peer, connection })
                    .await;
            }
            Err(ref error) => {
                tracing::debug!(peer = %hex::encode(peer), error = %error, "outbound connection failed");
                let _ = event_tx
                    .send(ServiceEvent::OutboundConnectionFailed {
                        peer,
                        error: error.clone(),
                    })
                    .await;
            }
        }
    });
}

/// Spawn a task to monitor a connection and accept incoming streams.
///
/// This task runs for the lifetime of a connection, accepting incoming
/// bidirectional streams and sending them to the main loop for routing.
pub fn spawn_connection_monitor(
    peer: PeerId,
    connection: quinn::Connection,
    event_tx: AsyncSender<ServiceEvent>,
) {
    tokio::spawn(async move {
        tracing::debug!(peer = %hex::encode(peer), "connection monitor started");

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    // Send event to main loop - it will spawn header reading task
                    if event_tx
                        .send(ServiceEvent::IncomingStream { peer, send, recv })
                        .await
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

                    let _ = event_tx
                        .send(ServiceEvent::ConnectionLost { peer, reason })
                        .await;
                    break;
                }
            }
        }

        tracing::debug!(peer = %hex::encode(peer), "connection monitor ended");
    });
}

/// Spawn a task to read a stream header.
///
/// This reads the stream header with a timeout and sends the result back
/// via the event channel for routing.
pub fn spawn_stream_header_reader(
    peer: PeerId,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    event_tx: AsyncSender<ServiceEvent>,
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
                let _ = event_tx
                    .send(ServiceEvent::StreamReady {
                        peer,
                        stream_type,
                        send,
                        recv,
                    })
                    .await;
            }
            Err(error) => {
                tracing::debug!(peer = %hex::encode(peer), error = %error, "failed to read stream header");
                let _ = send.reset(0u32.into());
                let _ = event_tx
                    .send(ServiceEvent::StreamHeaderFailed { peer, error })
                    .await;
            }
        }
    });
}

/// Spawn a task to open a stream on an existing connection.
///
/// This opens a bidirectional stream, sets priority, writes the header,
/// and sends the result back to the caller.
pub fn spawn_stream_opener(
    peer: PeerId,
    connection: quinn::Connection,
    stream_type: mosaic_net_wire::StreamType,
    priority: i32,
    respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
) {
    tokio::spawn(async move {
        let result = async {
            // Open bidirectional stream
            let (mut send, recv) = tokio::time::timeout(STREAM_OPEN_TIMEOUT, connection.open_bi())
                .await
                .map_err(|_| OpenStreamError::StreamFailed("open stream timed out".to_string()))?
                .map_err(|e| OpenStreamError::StreamFailed(e.to_string()))?;

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

            // Create stream handle
            Ok(stream::create_stream(peer, send, recv))
        }
        .await;

        // Send response - ignore error if receiver dropped
        let _ = respond_to.send(result).await;
    });
}

/// Spawn a task to route a protocol stream to the protocol stream channel.
///
/// This creates a Stream handle and sends it to the protocol stream channel.
pub fn spawn_protocol_stream_router(
    peer: PeerId,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    protocol_stream_tx: AsyncSender<Stream>,
) {
    tokio::spawn(async move {
        let stream = stream::create_stream(peer, send, recv);
        if protocol_stream_tx.send(stream).await.is_err() {
            tracing::debug!(peer = %hex::encode(peer), "protocol stream channel closed");
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

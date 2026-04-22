// Dev-dependencies are used in tests but the unused_crate_dependencies lint
// incorrectly fires on lib.rs
#![allow(unused_crate_dependencies)]

//! Typed network client for Mosaic protocol messages.
//!
//! This crate provides a high-level API for sending and receiving protocol
//! messages between Mosaic instances. It wraps [`mosaic_net_svc`] and handles
//! serialization/deserialization of [`Msg`] types from [`mosaic_cac_types`].
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  SM Scheduler / Job Scheduler                           │
//! ├─────────────────────────────────────────────────────────┤
//! │  net-client  (this crate)                               │
//! │  - typed send/recv for protocol messages                │
//! │  - serialization with ark-serialize                     │
//! ├─────────────────────────────────────────────────────────┤
//! │  net-svc     (connection management, QUIC streams)      │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Protocol Message Flow
//!
//! Each protocol message follows a request-response pattern:
//!
//! 1. Sender opens a protocol stream (priority 0)
//! 2. Sender writes exactly one serialized message payload
//! 3. Receiver accepts that single inbound request and deserializes the payload
//! 4. Receiver sends an acknowledgment (priority 1)
//! 5. Stream closes
//!
//! # Example
//!
//! ```ignore
//! use mosaic_net_client::NetClient;
//! use mosaic_cac_types::ChallengeMsg;
//!
//! // Sending a message
//! let ack = client.send(peer_id, challenge_msg).await?;
//!
//! // Receiving messages
//! loop {
//!     let request = client.recv().await?;
//!     match &request.message {
//!         Msg::Challenge(challenge) => { /* handle */ }
//!         _ => { /* handle other types */ }
//!     }
//!     request.ack().await?;
//! }
//! ```

pub mod bulk;
pub mod error;
pub mod protocol;

use std::{
    future::Future,
    time::{Duration, Instant},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
pub use bulk::{BulkExpectation, BulkReceiver, BulkSender};
pub use error::{AckError, BulkExpectError, BulkOpenError, BulkReceiveError, RecvError, SendError};
use mosaic_cac_types::Msg;
use mosaic_net_svc::{FrameLimits, NetServiceHandle};
pub use protocol::{Ack, InboundRequest, PeerId, StreamPriority};

/// Configuration for [`NetClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetClientConfig {
    /// Timeout for opening a protocol stream.
    pub open_timeout: Duration,
    /// Timeout for waiting on acknowledgments.
    pub ack_timeout: Duration,
}

impl Default for NetClientConfig {
    fn default() -> Self {
        Self {
            open_timeout: Duration::from_secs(5),
            ack_timeout: Duration::from_secs(10),
        }
    }
}

/// Typed network client for Mosaic protocol messages.
///
/// This client wraps a [`NetServiceHandle`] and provides typed send/receive
/// operations for protocol messages. It handles serialization internally
/// using `ark-serialize` with no compression for performance.
///
/// # Cloning
///
/// `NetClient` is cheaply cloneable (it only contains channel handles).
/// Clone it freely to use from multiple tasks.
#[derive(Clone)]
pub struct NetClient {
    handle: NetServiceHandle,
    config: NetClientConfig,
}

impl std::fmt::Debug for NetClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetClient").finish_non_exhaustive()
    }
}

impl NetClient {
    /// Create a new client wrapping the given service handle.
    pub fn new(handle: NetServiceHandle) -> Self {
        Self {
            handle,
            config: NetClientConfig::default(),
        }
    }

    /// Create a new client with custom configuration.
    pub fn with_config(handle: NetServiceHandle, config: NetClientConfig) -> Self {
        Self { handle, config }
    }

    /// Get a reference to the underlying service handle.
    pub fn handle(&self) -> &NetServiceHandle {
        &self.handle
    }

    /// Open a bulk-transfer sender stream to a peer.
    pub async fn open_bulk_sender(
        &self,
        peer: PeerId,
        identifier: [u8; 32],
        priority: i32,
    ) -> Result<BulkSender, BulkOpenError> {
        let stream = self
            .handle
            .open_bulk_stream(peer, identifier, priority)
            .await?;
        Ok(BulkSender::new(stream))
    }

    /// Register to receive a bulk transfer stream from a peer.
    pub async fn expect_bulk_receiver(
        &self,
        peer: PeerId,
        identifier: [u8; 32],
    ) -> Result<BulkExpectation, BulkExpectError> {
        let expectation = self.handle.expect_bulk_transfer(peer, identifier).await?;
        Ok(BulkExpectation::new(expectation))
    }

    /// Send a protocol message to a peer and wait for acknowledgment.
    ///
    /// This method:
    /// 1. Opens a protocol stream to the peer (priority 0)
    /// 2. Serializes and writes the message
    /// 3. Waits for the peer to acknowledge
    /// 4. Returns [`Ack`] on success
    ///
    /// The message type must implement `Into<Msg>`, which is implemented for
    /// all protocol message types (`CommitMsgChunk`, `ChallengeMsg`, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Failed to open stream to peer ([`SendError::Open`])
    /// - Serialization failed ([`SendError::Serialize`])
    /// - Write failed ([`SendError::Write`])
    /// - Acknowledgment not received ([`SendError::NoAck`])
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Send a specific message type (uses Into<Msg>)
    /// client.send(peer, commit_chunk).await?;
    ///
    /// // Or wrap manually
    /// client.send(peer, Msg::CommitChunk(chunk)).await?;
    /// ```
    pub async fn send(&self, peer: PeerId, msg: impl Into<Msg>) -> Result<Ack, SendError> {
        let started = Instant::now();
        let msg: Msg = msg.into();

        // Open protocol stream with normal priority
        let mut stream = match timeout_if_tokio_runtime(
            self.config.open_timeout,
            self.handle
                .open_protocol_stream(peer, StreamPriority::Normal.as_i32()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(SendError::Open(err)),
            Err(TimeoutElapsed) => {
                return Err(SendError::Open(
                    mosaic_net_svc::api::OpenStreamError::ConnectionFailed(
                        "open stream timed out".to_string(),
                    ),
                ));
            }
        };
        let opened_at = started.elapsed();

        // Serialize message (uncompressed for performance)
        let bytes = serialize(&msg).map_err(SendError::Serialize)?;
        let payload_len = bytes.len();
        let serialized_at = started.elapsed();

        let limits = FrameLimits::default();
        if payload_len > limits.max_send_size as usize {
            return Err(SendError::FrameTooLarge {
                size: payload_len,
                max: limits.max_send_size as usize,
            });
        }

        // Write to stream
        let _ = stream.write(bytes).await.map_err(SendError::Write)?;
        let written_at = started.elapsed();

        // Wait for ack (empty response)
        let _ack = match timeout_if_tokio_runtime(self.config.ack_timeout, stream.read()).await {
            Ok(Ok(ack)) => ack,
            Ok(Err(err)) => return Err(SendError::NoAck(err)),
            Err(TimeoutElapsed) => {
                // Timeout waiting for ack - reset stream and surface as NoAck.
                stream.reset(0).await;
                return Err(SendError::NoAck(mosaic_net_svc::StreamClosed::Disconnected));
            }
        };
        let acked_at = started.elapsed();

        if cfg!(test) {
            eprintln!(
                "net-client send timings: open={:?}, serialize={:?}, write={:?}, ack={:?}, total={:?}, bytes={}",
                opened_at, serialized_at, written_at, acked_at, acked_at, payload_len
            );
        }

        Ok(Ack)
    }

    /// Receive the next incoming protocol message.
    ///
    /// This method:
    /// 1. Accepts the next incoming protocol request
    /// 2. Deserializes the already-buffered request payload
    /// 3. Returns an [`InboundRequest`] containing the message and a handle to send acknowledgment
    ///
    /// The returned [`InboundRequest`] must be acknowledged by calling
    /// [`InboundRequest::ack`] after processing the message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No more incoming streams (service shut down) ([`RecvError::Closed`])
    /// - Read failed ([`RecvError::Read`])
    /// - Deserialization failed ([`RecvError::Deserialize`])
    ///
    /// # Example
    ///
    /// ```ignore
    /// let request = client.recv().await?;
    /// match request.message {
    ///     Msg::CommitChunk(chunk) => { /* process */ }
    ///     Msg::Challenge(challenge) => { /* process */ }
    ///     // ...
    /// }
    /// request.ack().await?;
    /// ```
    pub async fn recv(&self) -> Result<InboundRequest, RecvError> {
        // Accept next incoming protocol request
        let inbound = self
            .handle
            .protocol_streams()
            .recv()
            .await
            .map_err(|_| RecvError::Closed)?;
        let peer_id = inbound.peer();
        let (bytes, stream) = inbound.into_parts();
        let bytes = bytes.ok_or(RecvError::Closed)?;

        // Deserialize message (uncompressed, with validation)
        let msg = deserialize(&bytes).map_err(|error| RecvError::Deserialize { peer_id, error })?;

        Ok(InboundRequest::new(msg, stream))
    }
}

/// Serialize a message to bytes using uncompressed mode.
fn serialize(msg: &Msg) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut bytes = Vec::with_capacity(msg.serialized_size(Compress::No));
    msg.serialize_with_mode(&mut bytes, Compress::No)?;
    Ok(bytes)
}

/// Deserialize a message from bytes using uncompressed mode with validation.
fn deserialize(bytes: &[u8]) -> Result<Msg, ark_serialize::SerializationError> {
    Msg::deserialize_with_mode(&mut &bytes[..], Compress::No, Validate::Yes)
}

/// Marker error used when a tokio timeout elapses.
struct TimeoutElapsed;

/// Apply a timeout when running inside a tokio runtime.
///
/// When no tokio runtime is present (for example, monoio worker threads),
/// this awaits the future directly without enforcing a timeout.
async fn timeout_if_tokio_runtime<T>(
    duration: Duration,
    fut: impl Future<Output = T>,
) -> Result<T, TimeoutElapsed> {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::time::timeout(duration, fut)
            .await
            .map_err(|_| TimeoutElapsed)
    } else {
        Ok(fut.await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_client_is_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<NetClient>();
    }

    #[test]
    fn net_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetClient>();
    }
}

//! Protocol message handling types.
//!
//! This module provides types for handling the request-response pattern
//! used by protocol messages: sender sends a message, receiver acknowledges.

use mosaic_cac_types::Msg;
// Re-export PeerId for convenience
pub use mosaic_net_svc::PeerId;
use mosaic_net_svc::Stream;

use crate::error::AckError;

/// Zero-sized acknowledgment type.
///
/// Returned from [`NetClient::send`](crate::NetClient::send) to indicate
/// the peer successfully received and acknowledged the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack;

/// Stream priority levels for protocol communication.
///
/// Higher values indicate higher priority. QUIC will prefer sending
/// higher-priority stream data first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum StreamPriority {
    /// Bulk transfers (garbling tables) - lowest priority.
    Bulk = -1,
    /// Normal protocol messages.
    Normal = 0,
    /// Acknowledgments - higher than normal to avoid blocking.
    Ack = 1,
}

impl StreamPriority {
    /// Get the raw priority value for use with QUIC streams.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// An incoming protocol message with a handle to send acknowledgment.
///
/// When you receive a message via [`NetClient::recv`](crate::NetClient::recv),
/// you get this struct containing the message and a way to acknowledge it.
///
/// # Example
///
/// ```ignore
/// let request = client.recv().await?;
/// println!("Got {:?} from {:?}", request.message, request.peer());
///
/// // Process the message...
///
/// // Acknowledge receipt
/// request.ack().await?;
/// ```
pub struct InboundRequest {
    /// The protocol message.
    pub message: Msg,
    /// Internal responder handle.
    responder: Responder,
}

impl std::fmt::Debug for InboundRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundRequest")
            .field("peer", &self.peer())
            .field("message", &self.message)
            .finish_non_exhaustive()
    }
}

impl InboundRequest {
    /// Create a new inbound request.
    pub(crate) fn new(message: Msg, stream: Stream) -> Self {
        Self {
            message,
            responder: Responder { stream },
        }
    }

    /// The peer that sent the message.
    pub fn peer(&self) -> PeerId {
        self.responder.stream.peer
    }

    /// Acknowledge receipt of the message.
    ///
    /// This sets the stream priority to 1 (higher than the initial message),
    /// sends an empty acknowledgment, and closes the stream.
    ///
    /// The underlying protocol stream is single-request by contract: the inbound
    /// request payload has already been extracted before this responder is created,
    /// and the stream handle is only used for the acknowledgment path.
    ///
    /// # Errors
    ///
    /// Returns an error if the acknowledgment could not be sent.
    pub async fn ack(self) -> Result<(), AckError> {
        self.responder.send_ack().await
    }
}

/// Internal handle for sending acknowledgment on a stream.
///
/// Owns the stream and is consumed when acknowledgment is sent.
/// If dropped without calling `send_ack`, the stream is closed without
/// acknowledgment (peer will see stream closed).
struct Responder {
    stream: Stream,
}

impl Responder {
    /// Send acknowledgment and close the stream.
    async fn send_ack(mut self) -> Result<(), AckError> {
        // Set priority higher than initial message
        self.stream
            .set_priority(StreamPriority::Ack.as_i32())
            .await
            .map_err(AckError::Priority)?;

        // Send empty payload as ack
        let _ = self
            .stream
            .write(Vec::new())
            .await
            .map_err(AckError::Write)?;

        // Stream is dropped here, triggering graceful close (FIN)
        Ok(())
    }
}

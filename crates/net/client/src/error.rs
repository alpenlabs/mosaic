//! Error types for net-client operations.

use ark_serialize::SerializationError;
use mosaic_net_svc::StreamClosed;
use mosaic_net_svc::api::OpenStreamError;

/// Error sending a protocol message.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Failed to open protocol stream to peer.
    #[error("failed to open stream: {0}")]
    Open(#[from] OpenStreamError),

    /// Failed to serialize the message.
    #[error("serialization failed: {0:?}")]
    Serialize(SerializationError),

    /// Payload exceeded frame size limit before send.
    #[error("payload too large: {size} bytes (max {max})")]
    FrameTooLarge {
        /// Payload size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Failed to write message to stream.
    #[error("write failed: {0}")]
    Write(#[source] StreamClosed),

    /// Did not receive acknowledgment from peer.
    #[error("ack not received: {0}")]
    NoAck(#[source] StreamClosed),
}

/// Error receiving a protocol message.
#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    /// No more incoming streams (service shut down).
    #[error("no more incoming streams")]
    Closed,

    /// Failed to read from stream.
    #[error("read failed: {0}")]
    Read(#[source] StreamClosed),

    /// Failed to deserialize the message.
    #[error("deserialization failed: {0:?}")]
    Deserialize(SerializationError),
}

/// Error sending an acknowledgment.
#[derive(Debug, thiserror::Error)]
pub enum AckError {
    /// Failed to set stream priority.
    #[error("failed to set priority: {0}")]
    Priority(#[source] StreamClosed),

    /// Failed to write ack to stream.
    #[error("failed to send ack: {0}")]
    Write(#[source] StreamClosed),
}

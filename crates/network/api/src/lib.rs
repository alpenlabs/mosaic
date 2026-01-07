//! Mosaic network traits. This defines high level traits for communication between garbler and
//! evaluator mosaic instances.

use async_trait::async_trait;
use futures::stream::BoxStream;
use mosaic_common::{
    PeerId,
    codec::{Decode, Encode},
};
use thiserror::Error;

/// Trait alias for network message bounds.
pub trait NetworkMessage: Send + Clone + Encode + Decode + 'static {}

impl<T> NetworkMessage for T where T: Send + Clone + Encode + Decode + 'static {}

/// A message to be sent to a specific peer.
#[derive(Debug, Clone)]
pub struct OutboundMessage<M> {
    /// Remote peer this message is for.
    pub to: PeerId,
    /// Message.
    pub msg: M,
}

/// A message received from a peer.
#[derive(Debug, Clone)]
pub struct InboundMessage<M> {
    /// Remote peer this message is from.
    pub from: PeerId,
    /// Message.
    pub msg: M,
}

/// Stream of inbound messages from peers.
pub type InboundMsgStream<M> = BoxStream<'static, InboundMessage<M>>;

/// Errors that can occur during network operations.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The target peer is not connected or reachable.
    #[error("peer not found: {0}")]
    PeerNotFound(PeerId),

    /// Connection to the peer was lost or failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// The operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Failed to serialize or deserialize a message.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The network channel is closed or unavailable.
    #[error("channel closed")]
    ChannelClosed,

    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for network operations.
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Trait for sending and receiving messages between mosaic instances.
#[async_trait]
pub trait Network<M: NetworkMessage> {
    /// Send a message to a specific peer.
    async fn send_message(&self, msg: OutboundMessage<M>) -> NetworkResult<()>;

    /// Returns a stream of inbound messages from connected peers.
    fn inbound(&self) -> InboundMsgStream<M>;
}

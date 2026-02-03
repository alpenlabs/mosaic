//! Network service API types.
//!
//! This module defines the types used to interact with streams managed by the
//! network service. The service runs on a dedicated tokio thread, and these
//! types use channels to communicate across the runtime boundary.

use std::sync::Arc;

use kanal::{AsyncReceiver, AsyncSender};

use crate::{config::NetServiceConfig, tls::PeerId};

/// A buffer for payload data.
///
/// When writing, ownership transfers to net-svc temporarily. After the write
/// completes, the buffer is returned via `recv_buffer()` for reuse.
pub type PayloadBuf = Vec<u8>;

// ============================================================================
// Stream Types
// ============================================================================

/// Request sent to net-svc for stream operations.
pub(crate) enum StreamRequest {
    /// Write a buffer to the stream.
    Write { buf: PayloadBuf },
    /// Set the stream's send priority.
    SetPriority(i32),
    /// Reset the stream with an error code.
    Reset(u32),
}

/// Reason a stream was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamClosed {
    /// Peer gracefully finished (FIN).
    PeerFinished,
    /// Peer reset the stream with an error code.
    PeerReset(u32),
    /// Connection lost or network service crashed.
    Disconnected,
}

impl std::fmt::Display for StreamClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerFinished => write!(f, "peer finished"),
            Self::PeerReset(code) => write!(f, "peer reset with code {}", code),
            Self::Disconnected => write!(f, "disconnected"),
        }
    }
}

impl std::error::Error for StreamClosed {}

/// A bidirectional QUIC stream.
///
/// Streams are created by the network service and communicate with it via
/// channels. Dropping the stream will trigger a graceful close (FIN) on the
/// send side.
///
/// # Buffer Reuse
///
/// To avoid allocations during bulk transfers, buffers can be reused:
///
/// ```ignore
/// let mut buf = Vec::with_capacity(CHUNK_SIZE);
/// loop {
///     buf.clear();
///     fill_buffer(&mut buf);
///     stream.write(buf).await?;
///     buf = stream.recv_buffer().await.unwrap_or_else(|| Vec::with_capacity(CHUNK_SIZE));
/// }
/// ```
///
/// For pipelined writes, send multiple buffers before reclaiming:
///
/// ```ignore
/// stream.write(buf1).await?;
/// stream.write(buf2).await?;
/// stream.write(buf3).await?;
/// // Reclaim buffers as they complete
/// let buf1 = stream.recv_buffer().await;
/// let buf2 = stream.recv_buffer().await;
/// let buf3 = stream.recv_buffer().await;
/// ```
pub struct Stream {
    /// The peer this stream is connected to.
    pub peer: PeerId,

    // -- Receiving --
    /// Incoming payloads from the peer.
    payload_rx: AsyncReceiver<PayloadBuf>,

    // -- Sending --
    /// Requests to net-svc (write, priority, reset).
    request_tx: AsyncSender<StreamRequest>,
    /// Buffers returned after writes complete.
    buf_return_rx: AsyncReceiver<PayloadBuf>,

    // -- Close handling --
    /// Notification when stream closes.
    close_rx: AsyncReceiver<StreamClosed>,
    /// Cached close reason.
    close_reason: Option<StreamClosed>,
}

impl Stream {
    /// Create a new stream handle.
    ///
    /// This is called internally by the network service when a stream is
    /// opened or accepted.
    pub(crate) fn new(
        peer: PeerId,
        payload_rx: AsyncReceiver<PayloadBuf>,
        request_tx: AsyncSender<StreamRequest>,
        buf_return_rx: AsyncReceiver<PayloadBuf>,
        close_rx: AsyncReceiver<StreamClosed>,
    ) -> Self {
        Self {
            peer,
            payload_rx,
            request_tx,
            buf_return_rx,
            close_rx,
            close_reason: None,
        }
    }

    // -- Close handling --

    /// Check if the stream has closed and cache the reason.
    fn poll_close_reason(&mut self) {
        if self.close_reason.is_none()
            && let Ok(Some(reason)) = self.close_rx.try_recv()
        {
            self.close_reason = Some(reason);
        }
    }

    /// Get the close reason if the stream has closed.
    pub fn close_reason(&mut self) -> Option<StreamClosed> {
        self.poll_close_reason();
        self.close_reason
    }

    /// Check if the stream is closed.
    pub fn is_closed(&mut self) -> bool {
        self.close_reason().is_some()
    }

    // -- Reading --

    /// Read the next payload from the peer.
    ///
    /// Returns `Ok(payload)` on success, or `Err(StreamClosed)` if the stream
    /// was closed by the peer or disconnected.
    pub async fn read(&mut self) -> Result<PayloadBuf, StreamClosed> {
        match self.payload_rx.recv().await {
            Ok(payload) => Ok(payload),
            Err(_) => {
                // Channel closed - determine why
                self.poll_close_reason();
                Err(self.close_reason.unwrap_or(StreamClosed::Disconnected))
            }
        }
    }

    /// Try to read a payload without blocking.
    ///
    /// Returns `Some(payload)` if data is available, `None` if no data is
    /// ready (does not indicate stream closure).
    pub fn try_read(&mut self) -> Option<PayloadBuf> {
        match self.payload_rx.try_recv() {
            Ok(Some(payload)) => Some(payload),
            _ => None,
        }
    }

    // -- Writing --

    /// Send a request to net-svc.
    async fn send_request(&mut self, request: StreamRequest) -> Result<(), StreamClosed> {
        match self.request_tx.send(request).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Channel closed - net-svc task died
                self.poll_close_reason();
                Err(self.close_reason.unwrap_or(StreamClosed::Disconnected))
            }
        }
    }

    /// Write a buffer to the stream.
    ///
    /// Ownership of the buffer transfers to net-svc. After the data is written
    /// to the QUIC stream, the buffer is returned via [`recv_buffer`](Self::recv_buffer).
    ///
    /// This method returns as soon as the buffer is queued, not when the data
    /// is actually sent. Use multiple writes for pipelining.
    ///
    /// # Errors
    ///
    /// Returns `Err(StreamClosed)` if the stream has closed.
    pub async fn write(&mut self, buf: PayloadBuf) -> Result<(), StreamClosed> {
        // Early check - don't bother sending if already closed
        if let Some(reason) = self.close_reason() {
            return Err(reason);
        }

        self.send_request(StreamRequest::Write { buf }).await
    }

    /// Receive a buffer back after a write completes.
    ///
    /// The buffer is cleared and ready for reuse. Returns `None` if no buffers
    /// are pending or the stream has closed.
    pub async fn recv_buffer(&mut self) -> Option<PayloadBuf> {
        self.buf_return_rx.recv().await.ok()
    }

    /// Try to receive a buffer without blocking.
    ///
    /// Returns `Some(buf)` if a buffer is available, `None` otherwise.
    pub fn try_recv_buffer(&mut self) -> Option<PayloadBuf> {
        match self.buf_return_rx.try_recv() {
            Ok(Some(buf)) => Some(buf),
            _ => None,
        }
    }

    /// Drain all pending buffer returns.
    ///
    /// Useful before closing to reclaim all buffers.
    pub fn drain_buffers(&mut self) -> Vec<PayloadBuf> {
        let mut buffers = Vec::new();
        while let Some(buf) = self.try_recv_buffer() {
            buffers.push(buf);
        }
        buffers
    }

    // -- Stream control --

    /// Set the stream's send priority.
    ///
    /// Higher values = higher priority. Can be negative.
    pub async fn set_priority(&mut self, priority: i32) -> Result<(), StreamClosed> {
        self.send_request(StreamRequest::SetPriority(priority))
            .await
    }

    /// Reset the stream with an error code.
    ///
    /// This immediately closes the stream in both directions. The peer will
    /// see the error code. Consumes the stream.
    pub async fn reset(mut self, code: u32) {
        let _ = self.send_request(StreamRequest::Reset(code)).await;
    }
}

// Dropping the Stream drops request_tx, which signals net-svc to FIN the stream.

// ============================================================================
// Service Handle
// ============================================================================

/// Handle to the network service.
///
/// This is cheaply cloneable and can be sent to any thread. All methods use
/// channels internally to communicate with the service running on a tokio thread.
#[derive(Clone)]
pub struct NetServiceHandle {
    /// Shared configuration.
    config: Arc<NetServiceConfig>,
    /// Commands to the service.
    command_tx: AsyncSender<NetCommand>,
    /// Incoming protocol streams (shared receiver).
    protocol_stream_rx: AsyncReceiver<Stream>,
}

impl NetServiceHandle {
    /// Create a new handle.
    pub(crate) fn new(
        config: Arc<NetServiceConfig>,
        command_tx: AsyncSender<NetCommand>,
        protocol_stream_rx: AsyncReceiver<Stream>,
    ) -> Self {
        Self {
            config,
            command_tx,
            protocol_stream_rx,
        }
    }

    /// Get the shared configuration.
    pub fn config(&self) -> &Arc<NetServiceConfig> {
        &self.config
    }

    /// Get the receiver for incoming protocol streams.
    ///
    /// The SMScheduler should own this and receive streams from it.
    /// Each stream is a new incoming connection from a peer.
    pub fn protocol_streams(&self) -> &AsyncReceiver<Stream> {
        &self.protocol_stream_rx
    }

    /// Open a protocol stream to a peer.
    ///
    /// Protocol streams use `StreamType::Protocol` header and are routed to
    /// the peer's `protocol_streams()` receiver.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to open the stream to (must be in config).
    /// * `priority` - Stream priority. Higher = more important. Use 0 for normal, 1 for high
    ///   (ACKs), -1 for low.
    pub async fn open_protocol_stream(
        &self,
        peer: PeerId,
        priority: i32,
    ) -> Result<Stream, OpenStreamError> {
        if !self.config.has_peer(&peer) {
            return Err(OpenStreamError::PeerNotFound);
        }

        let (resp_tx, resp_rx) = kanal::bounded_async(1);
        self.command_tx
            .send(NetCommand::OpenProtocolStream {
                peer,
                priority,
                respond_to: resp_tx,
            })
            .await
            .map_err(|_| OpenStreamError::ServiceDown)?;

        resp_rx
            .recv()
            .await
            .map_err(|_| OpenStreamError::ServiceDown)?
    }

    /// Open a bulk transfer stream to a peer.
    ///
    /// Bulk transfer streams use `StreamType::BulkTransfer` header with the
    /// provided identifier. The peer must have registered to receive this
    /// transfer via [`expect_bulk_transfer`](Self::expect_bulk_transfer).
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to open the stream to (must be in config).
    /// * `identifier` - 32-byte identifier for routing (typically a commitment hash).
    /// * `priority` - Stream priority. Typically -1 (low) for bulk transfers.
    pub async fn open_bulk_stream(
        &self,
        peer: PeerId,
        identifier: [u8; 32],
        priority: i32,
    ) -> Result<Stream, OpenStreamError> {
        if !self.config.has_peer(&peer) {
            return Err(OpenStreamError::PeerNotFound);
        }

        let (resp_tx, resp_rx) = kanal::bounded_async(1);
        self.command_tx
            .send(NetCommand::OpenBulkStream {
                peer,
                identifier,
                priority,
                respond_to: resp_tx,
            })
            .await
            .map_err(|_| OpenStreamError::ServiceDown)?;

        resp_rx
            .recv()
            .await
            .map_err(|_| OpenStreamError::ServiceDown)?
    }

    /// Register to receive a specific bulk transfer.
    ///
    /// When a peer opens a bulk stream with a matching identifier, it will be
    /// sent to the returned receiver.
    ///
    /// **Call this before the peer sends**, otherwise the transfer may be
    /// rejected (peer will retry after timeout).
    pub async fn expect_bulk_transfer(
        &self,
        peer: PeerId,
        identifier: [u8; 32],
    ) -> Result<AsyncReceiver<Stream>, ExpectError> {
        if !self.config.has_peer(&peer) {
            return Err(ExpectError::PeerNotFound);
        }

        let (resp_tx, resp_rx) = kanal::bounded_async(1);
        self.command_tx
            .send(NetCommand::ExpectBulkTransfer {
                peer,
                identifier,
                respond_to: resp_tx,
            })
            .await
            .map_err(|_| ExpectError::ServiceDown)?;

        resp_rx.recv().await.map_err(|_| ExpectError::ServiceDown)?
    }
}

// ============================================================================
// Commands
// ============================================================================

/// Commands sent to the network service.
pub(crate) enum NetCommand {
    OpenProtocolStream {
        peer: PeerId,
        priority: i32,
        respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
    },
    OpenBulkStream {
        peer: PeerId,
        identifier: [u8; 32],
        priority: i32,
        respond_to: AsyncSender<Result<Stream, OpenStreamError>>,
    },
    ExpectBulkTransfer {
        peer: PeerId,
        identifier: [u8; 32],
        respond_to: AsyncSender<Result<AsyncReceiver<Stream>, ExpectError>>,
    },
}

// ============================================================================
// Errors
// ============================================================================

/// Error opening a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenStreamError {
    /// Network service is down.
    ServiceDown,
    /// Peer is not in the configuration.
    PeerNotFound,
    /// Not connected to peer and connection failed.
    ConnectionFailed(String),
    /// Failed to open stream.
    StreamFailed(String),
}

impl std::fmt::Display for OpenStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceDown => write!(f, "network service is down"),
            Self::PeerNotFound => write!(f, "peer not in configuration"),
            Self::ConnectionFailed(e) => write!(f, "connection failed: {}", e),
            Self::StreamFailed(e) => write!(f, "failed to open stream: {}", e),
        }
    }
}

impl std::error::Error for OpenStreamError {}

/// Error registering for a bulk transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectError {
    /// Network service is down.
    ServiceDown,
    /// Peer is not in the configuration.
    PeerNotFound,
    /// Already registered for this transfer.
    AlreadyRegistered,
}

impl std::fmt::Display for ExpectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceDown => write!(f, "network service is down"),
            Self::PeerNotFound => write!(f, "peer not in configuration"),
            Self::AlreadyRegistered => write!(f, "already registered for this transfer"),
        }
    }
}

impl std::error::Error for ExpectError {}

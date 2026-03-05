//! Thin bulk-transfer wrappers over net-svc streams.

use mosaic_net_svc::{
    BulkTransferExpectation as SvcBulkTransferExpectation, PayloadBuf, PeerId, Stream, StreamClosed,
};

use crate::error::BulkReceiveError;

/// Sender-side wrapper for bulk transfer streams.
///
/// Default writes reclaim buffers immediately to avoid backpressure stalls from
/// unclaimed write completions.
pub struct BulkSender {
    stream: Stream,
}

impl BulkSender {
    pub(crate) fn new(stream: Stream) -> Self {
        Self { stream }
    }

    /// Write payload and reclaim the same buffer once send completes.
    pub async fn write(&mut self, buf: PayloadBuf) -> Result<PayloadBuf, StreamClosed> {
        self.stream.write(buf).await
    }

    /// Queue payload without waiting for reclaim.
    ///
    /// Call [`recv_buffer`](Self::recv_buffer) to reclaim buffers later.
    pub async fn write_no_reclaim(&mut self, buf: PayloadBuf) -> Result<(), StreamClosed> {
        self.stream.write_no_reclaim(buf).await
    }

    /// Reclaim one previously queued buffer.
    pub async fn recv_buffer(&mut self) -> Option<PayloadBuf> {
        self.stream.recv_buffer().await
    }

    /// Set stream priority.
    pub async fn set_priority(&mut self, priority: i32) -> Result<(), StreamClosed> {
        self.stream.set_priority(priority).await
    }

    /// Reset the stream.
    pub async fn reset(self, code: u32) {
        self.stream.reset(code).await;
    }

    /// Peer this stream is connected to.
    pub fn peer(&self) -> PeerId {
        self.stream.peer
    }
}

impl std::fmt::Debug for BulkSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkSender")
            .field("peer", &self.stream.peer)
            .finish_non_exhaustive()
    }
}

/// Receiver-side wrapper for bulk transfer streams.
pub struct BulkReceiver {
    stream: Stream,
}

impl BulkReceiver {
    pub(crate) fn new(stream: Stream) -> Self {
        Self { stream }
    }

    /// Read next payload chunk from peer.
    pub async fn read(&mut self) -> Result<PayloadBuf, StreamClosed> {
        self.stream.read().await
    }

    /// Try reading next payload chunk without blocking.
    pub fn try_read(&mut self) -> Option<PayloadBuf> {
        self.stream.try_read()
    }

    /// Peer this stream is connected to.
    pub fn peer(&self) -> PeerId {
        self.stream.peer
    }
}

impl std::fmt::Debug for BulkReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkReceiver")
            .field("peer", &self.stream.peer)
            .finish_non_exhaustive()
    }
}

/// Expectation handle for a pending bulk receiver stream.
pub struct BulkExpectation {
    inner: SvcBulkTransferExpectation,
}

impl BulkExpectation {
    pub(crate) fn new(inner: SvcBulkTransferExpectation) -> Self {
        Self { inner }
    }

    /// Wait for the incoming bulk stream.
    pub async fn recv(self) -> Result<BulkReceiver, BulkReceiveError> {
        self.inner
            .recv()
            .await
            .map(BulkReceiver::new)
            .map_err(|_| BulkReceiveError::Closed)
    }
}

impl std::fmt::Debug for BulkExpectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkExpectation").finish_non_exhaustive()
    }
}

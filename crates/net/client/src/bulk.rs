//! Thin bulk-transfer wrappers over net-svc streams.

use std::{future::Future, time::Duration};

use futures_util::{
    FutureExt,
    future::{Either, select},
    pin_mut,
};
use mosaic_net_svc::{
    BulkTransferExpectation as SvcBulkTransferExpectation, PayloadBuf, PeerId, Stream, StreamClosed,
};

use crate::error::{BulkReadError, BulkReceiveError};

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

    /// Read next payload chunk with a timeout.
    pub async fn read_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<PayloadBuf, BulkReadError> {
        match timeout_in_current_runtime(timeout, self.stream.read()).await {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(err)) => Err(BulkReadError::Closed(err)),
            Err(TimeoutElapsed) => Err(BulkReadError::TimedOut),
        }
    }

    /// Try reading next payload chunk without blocking.
    pub fn try_read(&mut self) -> Option<PayloadBuf> {
        self.stream.try_read()
    }

    /// Peer this stream is connected to.
    pub fn peer(&self) -> PeerId {
        self.stream.peer
    }

    /// Reset the stream.
    pub async fn reset(self, code: u32) {
        self.stream.reset(code).await;
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

    /// Wait for the incoming bulk stream with a timeout.
    pub async fn recv_with_timeout(
        self,
        timeout: Duration,
    ) -> Result<BulkReceiver, BulkReceiveError> {
        match timeout_in_current_runtime(timeout, self.inner.receiver().recv()).await {
            Ok(Ok(stream)) => Ok(BulkReceiver::new(stream)),
            Ok(Err(_)) => Err(BulkReceiveError::Closed),
            Err(TimeoutElapsed) => {
                self.cancel().await;
                Err(BulkReceiveError::TimedOut)
            }
        }
    }

    /// Explicitly cancel the registered expectation.
    pub async fn cancel(self) {
        self.inner.cancel().await;
    }
}

impl std::fmt::Debug for BulkExpectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkExpectation").finish_non_exhaustive()
    }
}

struct TimeoutElapsed;

async fn timeout_in_current_runtime<T>(
    duration: Duration,
    fut: impl Future<Output = T>,
) -> Result<T, TimeoutElapsed> {
    let fut = fut.map(Ok::<T, TimeoutElapsed>);
    let timeout = futures_timer::Delay::new(duration).map(|_| Err(TimeoutElapsed));
    pin_mut!(fut);
    pin_mut!(timeout);
    match select(fut, timeout).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

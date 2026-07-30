//! Stream bridging between QUIC streams and channel-based API.
//!
//! This module handles the per-stream tasks that bridge QUIC streams to the
//! channel-based `Stream` API exposed to users.

use std::sync::{Arc, Mutex};

use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use quinn::{RecvStream, SendStream};
use tracing::Instrument;

use crate::{
    api::{PayloadBuf, Stream, StreamClosed, StreamRequest, StreamReset, StreamStop},
    tls::PeerId,
};

/// Channel buffer sizes for stream communication.
const PAYLOAD_CHANNEL_SIZE: usize = 16;
const REQUEST_CHANNEL_SIZE: usize = 16;
const RESET_CHANNEL_SIZE: usize = 1;
const BUF_RETURN_CHANNEL_SIZE: usize = 16;
const INITIAL_READ_BUFFER_CAPACITY: usize = 4 * 1024;

/// Shared close state for a stream.
///
/// We use shared state so the close reason is deterministic even if both the
/// read and write tasks encounter terminal errors around the same time.
/// A single notification is sent via `close_tx` to wake any waiters.
#[derive(Debug)]
struct CloseState {
    reason: Mutex<Option<StreamClosed>>,
}

impl CloseState {
    fn new() -> Self {
        Self {
            reason: Mutex::new(None),
        }
    }

    /// Set the close reason if it hasn't been set yet.
    ///
    /// Returns `true` if this call set the reason (i.e. first terminal event).
    fn set_if_empty(&self, reason: StreamClosed) -> bool {
        let mut guard = self.reason.lock().expect("close state lock poisoned");
        if guard.is_none() {
            *guard = Some(reason);
            true
        } else {
            false
        }
    }
}

/// Create a new stream handle and spawn the bridge tasks.
///
/// Returns a `Stream` that can be used by the caller. The bridge tasks handle
/// communication between the QUIC stream and the channel-based API.
pub fn create_stream(peer: PeerId, send: SendStream, recv: RecvStream) -> Stream {
    // Create channels
    let (payload_tx, payload_rx) = bounded_async(PAYLOAD_CHANNEL_SIZE);
    let (request_tx, request_rx) = bounded_async(REQUEST_CHANNEL_SIZE);
    let (reset_tx, reset_rx) = bounded_async(RESET_CHANNEL_SIZE);
    let (stop_tx, stop_rx) = bounded_async(RESET_CHANNEL_SIZE);
    let (buf_return_tx, buf_return_rx) = bounded_async(BUF_RETURN_CHANNEL_SIZE);
    let (close_tx, close_rx) = bounded_async(1);

    // Shared close state so multiple tasks converge on a single deterministic reason.
    let close_state = Arc::new(CloseState::new());

    // Spawn bridge tasks
    tokio::spawn(
        write_task(
            send,
            request_rx,
            reset_rx,
            buf_return_tx,
            close_tx.clone(),
            close_state.clone(),
        )
        .instrument(tracing::debug_span!(
            "net_svc.stream_write",
            peer = %peer
        )),
    );
    tokio::spawn(
        read_task(recv, payload_tx, stop_rx, close_tx, close_state)
            .instrument(tracing::debug_span!("net_svc.stream_read", peer = %peer)),
    );

    Stream::new(
        peer,
        payload_rx,
        request_tx,
        reset_tx,
        stop_tx,
        buf_return_rx,
        close_rx,
    )
}

/// Create a write-only stream handle for a protocol response path.
///
/// The request payload has already been extracted by net-svc, so only the
/// send side remains relevant for acknowledgment/reset handling.
pub fn create_write_only_stream(peer: PeerId, send: SendStream) -> Stream {
    let (request_tx, request_rx) = bounded_async(REQUEST_CHANNEL_SIZE);
    let (reset_tx, reset_rx) = bounded_async(RESET_CHANNEL_SIZE);
    let (buf_return_tx, buf_return_rx) = bounded_async(BUF_RETURN_CHANNEL_SIZE);
    let (close_tx, close_rx) = bounded_async(1);

    let close_state = Arc::new(CloseState::new());

    tokio::spawn(
        write_task(
            send,
            request_rx,
            reset_rx,
            buf_return_tx,
            close_tx,
            close_state,
        )
        .instrument(tracing::debug_span!(
            "net_svc.stream_write_only",
            peer = %peer
        )),
    );

    Stream::new_write_only(peer, request_tx, reset_tx, buf_return_rx, close_rx)
}

enum WriteOrReset<T> {
    Write(T),
    Reset(StreamReset),
}

enum ReadOrStop<T> {
    Read(T),
    Stop(StreamStop),
}

/// Wait for a transport write while allowing a reset to cancel it.
///
/// Dropping the write future releases its mutable borrow of the QUIC send
/// stream, after which the caller can apply the reset immediately.
async fn write_or_reset<F, T>(write: F, reset_rx: &AsyncReceiver<StreamReset>) -> WriteOrReset<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(write);
    tokio::select! {
        biased;
        reset = reset_rx.recv() => {
            match reset {
                Ok(reset) => WriteOrReset::Reset(reset),
                // Graceful Stream drop closes both channels. Do not cancel a
                // write already accepted from the data-plane channel.
                Err(_) => WriteOrReset::Write(write.await),
            }
        }
        result = &mut write => WriteOrReset::Write(result),
    }
}

/// Wait for receive-side work while allowing local reset to stop it.
async fn read_or_stop<F, T>(read: F, stop_rx: &AsyncReceiver<StreamStop>) -> ReadOrStop<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(read);
    tokio::select! {
        biased;
        stop = stop_rx.recv() => {
            match stop {
                Ok(stop) => ReadOrStop::Stop(stop),
                // Graceful Stream drop must not discard data already read
                // from the transport.
                Err(_) => ReadOrStop::Read(read.await),
            }
        }
        result = &mut read => ReadOrStop::Read(result),
    }
}

/// Return a spent payload buffer without allowing a full reclaim channel to
/// delay reset.
///
/// Pipelined callers can fill `buf_return_tx` before they start reclaiming
/// buffers. Reset must remain selectable at this await point for the same
/// reason it preempts `write_all`: the caller consumes its receive side while
/// waiting for reset acknowledgement, so an ordinary blocking send would
/// deadlock.
async fn return_buffer_or_reset(
    mut buf: PayloadBuf,
    buf_return_tx: &AsyncSender<PayloadBuf>,
    reset_rx: &AsyncReceiver<StreamReset>,
) -> Option<StreamReset> {
    buf.clear();
    match write_or_reset(buf_return_tx.send(buf), reset_rx).await {
        WriteOrReset::Write(_) => None,
        WriteOrReset::Reset(reset) => Some(reset),
    }
}

/// Reset the QUIC send stream and acknowledge write-task termination.
fn apply_reset(
    send: &mut SendStream,
    reset: StreamReset,
    close_tx: &AsyncSender<StreamClosed>,
    close_state: &CloseState,
) {
    tracing::debug!(code = reset.code, "resetting stream");
    let _ = send.reset(reset.code.into());
    // Intentional: local reset does not try to provide a "peer" close reason.
    // The caller initiated this and the Stream handle is consumed.
    if close_state.set_if_empty(StreamClosed::Disconnected) {
        let _ = close_tx.try_send(StreamClosed::Disconnected);
    }
    // This is the final action before the write task returns. The active
    // write future has already been dropped, and the transport reset applied.
    let _ = reset.done_tx.try_send(());
}

/// Stop the QUIC receive stream and acknowledge read-task termination.
fn apply_stop(recv: &mut RecvStream, stop: StreamStop) {
    let _ = recv.stop(stop.code.into());
    // This is the final action before the read task returns. Any active read
    // or payload-channel send future has already been dropped.
    let _ = stop.done_tx.try_send(());
}

/// Write task: handles StreamRequest -> QUIC stream.
///
/// Processes write requests, encodes frames with length prefix, and writes to
/// the QUIC stream. A separate reset channel can preempt a blocked write.
/// Returns buffers via buf_return_tx after writing.
async fn write_task(
    mut send: SendStream,
    request_rx: AsyncReceiver<StreamRequest>,
    reset_rx: AsyncReceiver<StreamReset>,
    buf_return_tx: AsyncSender<PayloadBuf>,
    close_tx: AsyncSender<StreamClosed>,
    close_state: Arc<CloseState>,
) {
    let limits = mosaic_net_wire::FrameLimits::default();
    let mut frame_buf = Vec::with_capacity(4 + 64 * 1024);

    loop {
        let request = tokio::select! {
            biased;
            reset = reset_rx.recv() => {
                match reset {
                    Ok(reset) => {
                        apply_reset(&mut send, reset, &close_tx, close_state.as_ref());
                        break;
                    }
                    // The Stream was dropped normally. Drain any request
                    // already accepted before finishing the send side.
                    Err(_) => request_rx.recv().await,
                }
            }
            request = request_rx.recv() => request,
        };

        match request {
            Ok(request) => {
                match request {
                    StreamRequest::Write { buf } => {
                        // Encode frame with length prefix
                        frame_buf.clear();
                        if let Err(e) = mosaic_net_wire::encode_frame(&buf, &mut frame_buf, &limits)
                        {
                            tracing::warn!(error = %e, "failed to encode frame");
                            if close_state.set_if_empty(StreamClosed::Disconnected) {
                                let _ = close_tx.send(StreamClosed::Disconnected).await;
                            }
                            let _ = send.reset(0u32.into());
                            // Return buffer anyway
                            if let Some(reset) =
                                return_buffer_or_reset(buf, &buf_return_tx, &reset_rx).await
                            {
                                apply_reset(&mut send, reset, &close_tx, close_state.as_ref());
                            }
                            break;
                        }

                        // Write to QUIC while reset remains independently
                        // selectable. A reset drops write_all before touching
                        // the send stream, so flow-control stalls are
                        // cancelled rather than inherited by a retry.
                        match write_or_reset(send.write_all(&frame_buf), &reset_rx).await {
                            WriteOrReset::Write(Ok(())) => {}
                            WriteOrReset::Write(Err(e)) => {
                                tracing::debug!(error = %e, "write error, closing stream");
                                if close_state.set_if_empty(StreamClosed::Disconnected) {
                                    let _ = close_tx.send(StreamClosed::Disconnected).await;
                                }
                                // Return buffer
                                if let Some(reset) =
                                    return_buffer_or_reset(buf, &buf_return_tx, &reset_rx).await
                                {
                                    apply_reset(&mut send, reset, &close_tx, close_state.as_ref());
                                }
                                break;
                            }
                            WriteOrReset::Reset(reset) => {
                                apply_reset(&mut send, reset, &close_tx, close_state.as_ref());
                                break;
                            }
                        }

                        // Return buffer (cleared for reuse)
                        if let Some(reset) =
                            return_buffer_or_reset(buf, &buf_return_tx, &reset_rx).await
                        {
                            apply_reset(&mut send, reset, &close_tx, close_state.as_ref());
                            break;
                        }
                    }

                    StreamRequest::SetPriority(priority) => {
                        if let Err(e) = send.set_priority(priority) {
                            tracing::trace!(error = %e, "failed to set priority");
                        }
                    }
                }
            }
            Err(_) => {
                // Request channel closed - caller dropped the stream handle.
                // Gracefully finish the stream (FIN).
                tracing::trace!("request channel closed, finishing stream");
                if let Err(e) = send.finish() {
                    tracing::trace!(error = %e, "error finishing stream");
                }
                // We do not set a close reason here. The read side will typically
                // observe FIN/peer reset, and if it doesn't, the stream will be
                // treated as disconnected.
                break;
            }
        }
    }
}

/// Read task: handles QUIC stream -> payload channel.
///
/// Reads frames from the QUIC stream, decodes length-prefixed frames, and
/// sends payloads to the payload channel.
async fn read_task(
    mut recv: RecvStream,
    payload_tx: AsyncSender<PayloadBuf>,
    stop_rx: AsyncReceiver<StreamStop>,
    close_tx: AsyncSender<StreamClosed>,
    close_state: Arc<CloseState>,
) {
    let limits = mosaic_net_wire::FrameLimits::default();
    let mut buf =
        Vec::with_capacity(INITIAL_READ_BUFFER_CAPACITY.min(limits.max_recv_size as usize + 4));
    let mut read_buf = [0u8; 64 * 1024];

    loop {
        // Try to decode a complete frame from buffer
        match mosaic_net_wire::decode_frame(&buf, &limits) {
            Ok((payload, consumed)) => {
                // Send payload to caller
                match read_or_stop(payload_tx.send(payload), &stop_rx).await {
                    ReadOrStop::Read(Ok(())) => {}
                    ReadOrStop::Read(Err(_)) => {
                        // Receiver dropped - stop reading
                        tracing::trace!("payload channel closed, stopping read task");
                        break;
                    }
                    ReadOrStop::Stop(stop) => {
                        apply_stop(&mut recv, stop);
                        break;
                    }
                }

                // Remove consumed bytes from buffer
                buf.drain(..consumed);
                continue; // Try to decode more frames
            }
            Err(mosaic_net_wire::DecodeError::Incomplete { .. }) => {
                // Need more data - fall through to read
            }
            Err(mosaic_net_wire::DecodeError::FrameTooLarge { size, max }) => {
                tracing::warn!(size = size, max = max, "frame too large, closing stream");
                if close_state.set_if_empty(StreamClosed::Disconnected) {
                    let _ = close_tx.send(StreamClosed::Disconnected).await;
                }
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "frame decode error, closing stream");
                if close_state.set_if_empty(StreamClosed::Disconnected) {
                    let _ = close_tx.send(StreamClosed::Disconnected).await;
                }
                break;
            }
        }

        // Read more data from QUIC stream
        match read_or_stop(recv.read(&mut read_buf), &stop_rx).await {
            ReadOrStop::Stop(stop) => {
                apply_stop(&mut recv, stop);
                break;
            }
            ReadOrStop::Read(Ok(Some(n))) => {
                buf.extend_from_slice(&read_buf[..n]);
            }
            ReadOrStop::Read(Ok(None)) => {
                // Stream finished (FIN received)
                tracing::trace!("peer finished stream");

                // Process any remaining data in buffer
                while !buf.is_empty() {
                    match mosaic_net_wire::decode_frame(&buf, &limits) {
                        Ok((payload, consumed)) => {
                            match read_or_stop(payload_tx.send(payload), &stop_rx).await {
                                ReadOrStop::Read(_) => {}
                                ReadOrStop::Stop(stop) => {
                                    apply_stop(&mut recv, stop);
                                    return;
                                }
                            }
                            buf.drain(..consumed);
                        }
                        Err(_) => break,
                    }
                }

                if close_state.set_if_empty(StreamClosed::PeerFinished) {
                    let _ = close_tx.send(StreamClosed::PeerFinished).await;
                }
                break;
            }
            ReadOrStop::Read(Err(e)) => {
                tracing::debug!(error = %e, "read error");

                let close_reason = match e {
                    quinn::ReadError::Reset(code) => {
                        let code = code.into_inner() as u32;
                        tracing::debug!(code = code, "peer reset stream");
                        StreamClosed::PeerReset(code)
                    }
                    quinn::ReadError::ConnectionLost(_) => {
                        tracing::debug!("connection lost");
                        StreamClosed::Disconnected
                    }
                    _ => StreamClosed::Disconnected,
                };

                if close_state.set_if_empty(close_reason) {
                    let _ = close_tx.send(close_reason).await;
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;

    #[tokio::test]
    async fn reset_preempts_pending_transport_write() {
        let (reset_tx, reset_rx) = bounded_async(1);
        let (done_tx, done_rx) = bounded_async(1);

        let wait_for_write = write_or_reset(pending::<()>(), &reset_rx);
        let send_reset = async move {
            reset_tx
                .send(StreamReset { code: 7, done_tx })
                .await
                .expect("reset receiver open");
        };

        let (outcome, ()) = tokio::join!(wait_for_write, send_reset);
        let WriteOrReset::Reset(reset) = outcome else {
            panic!("pending write completed before reset");
        };
        assert_eq!(reset.code, 7);

        reset
            .done_tx
            .send(())
            .await
            .expect("reset waiter still alive");
        done_rx.recv().await.expect("reset acknowledgement");
    }

    #[tokio::test]
    async fn reset_preempts_blocked_buffer_return() {
        let (buf_return_tx, buf_return_rx) = bounded_async(1);
        buf_return_tx
            .send(vec![1])
            .await
            .expect("fill buffer return channel");
        let (reset_tx, reset_rx) = bounded_async(1);
        let (done_tx, done_rx) = bounded_async(1);

        let return_buffer = return_buffer_or_reset(vec![2], &buf_return_tx, &reset_rx);
        let send_reset = async move {
            reset_tx
                .send(StreamReset { code: 9, done_tx })
                .await
                .expect("reset receiver open");
        };

        let (outcome, ()) = tokio::join!(return_buffer, send_reset);
        let reset = outcome.expect("reset must preempt full buffer return channel");
        assert_eq!(reset.code, 9);
        assert_eq!(
            buf_return_rx
                .recv()
                .await
                .expect("original returned buffer"),
            vec![1]
        );

        reset
            .done_tx
            .send(())
            .await
            .expect("reset waiter still alive");
        done_rx.recv().await.expect("reset acknowledgement");
    }

    #[tokio::test]
    async fn stop_preempts_pending_transport_read() {
        let (stop_tx, stop_rx) = bounded_async(1);
        let (done_tx, done_rx) = bounded_async(1);

        let wait_for_read = read_or_stop(pending::<()>(), &stop_rx);
        let send_stop = async move {
            stop_tx
                .send(StreamStop { code: 11, done_tx })
                .await
                .expect("stop receiver open");
        };

        let (outcome, ()) = tokio::join!(wait_for_read, send_stop);
        let ReadOrStop::Stop(stop) = outcome else {
            panic!("pending read completed before stop");
        };
        assert_eq!(stop.code, 11);

        stop.done_tx
            .send(())
            .await
            .expect("stop waiter still alive");
        done_rx.recv().await.expect("stop acknowledgement");
    }
}

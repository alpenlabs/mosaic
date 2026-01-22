//! Stream bridging between QUIC streams and channel-based API.
//!
//! This module handles the per-stream tasks that bridge QUIC streams to the
//! channel-based `Stream` API exposed to users.

use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use quinn::{RecvStream, SendStream};

use crate::api::{PayloadBuf, Stream, StreamClosed, StreamRequest};
use crate::tls::PeerId;

/// Channel buffer sizes for stream communication.
const PAYLOAD_CHANNEL_SIZE: usize = 16;
const REQUEST_CHANNEL_SIZE: usize = 16;
const BUF_RETURN_CHANNEL_SIZE: usize = 16;

/// Create a new stream handle and spawn the bridge tasks.
///
/// Returns a `Stream` that can be used by the caller. The bridge tasks handle
/// communication between the QUIC stream and the channel-based API.
pub fn create_stream(peer: PeerId, send: SendStream, recv: RecvStream) -> Stream {
    // Create channels
    let (payload_tx, payload_rx) = bounded_async(PAYLOAD_CHANNEL_SIZE);
    let (request_tx, request_rx) = bounded_async(REQUEST_CHANNEL_SIZE);
    let (buf_return_tx, buf_return_rx) = bounded_async(BUF_RETURN_CHANNEL_SIZE);
    let (close_tx, close_rx) = bounded_async(1);

    // Spawn bridge tasks
    tokio::spawn(write_task(
        send,
        request_rx,
        buf_return_tx,
        close_tx.clone(),
    ));
    tokio::spawn(read_task(recv, payload_tx, close_tx));

    Stream::new(peer, payload_rx, request_tx, buf_return_rx, close_rx)
}

/// Write task: handles StreamRequest -> QUIC stream.
///
/// Processes write requests, encodes frames with length prefix, and writes to
/// the QUIC stream. Returns buffers via buf_return_tx after writing.
async fn write_task(
    mut send: SendStream,
    request_rx: AsyncReceiver<StreamRequest>,
    buf_return_tx: AsyncSender<PayloadBuf>,
    close_tx: AsyncSender<StreamClosed>,
) {
    let mut frame_buf = Vec::with_capacity(4 + 64 * 1024);

    loop {
        match request_rx.recv().await {
            Ok(request) => {
                match request {
                    StreamRequest::Write { buf } => {
                        // Encode frame with length prefix
                        frame_buf.clear();
                        if let Err(e) = net_wire::encode_frame_unchecked(&buf, &mut frame_buf) {
                            tracing::warn!(error = %e, "failed to encode frame");
                            // Return buffer anyway
                            let mut buf = buf;
                            buf.clear();
                            let _ = buf_return_tx.send(buf).await;
                            continue;
                        }

                        // Write to QUIC stream
                        if let Err(e) = send.write_all(&frame_buf).await {
                            tracing::debug!(error = %e, "write error, closing stream");
                            let _ = close_tx.send(StreamClosed::Disconnected).await;
                            // Return buffer
                            let mut buf = buf;
                            buf.clear();
                            let _ = buf_return_tx.send(buf).await;
                            break;
                        }

                        // Return buffer (cleared for reuse)
                        let mut buf = buf;
                        buf.clear();
                        let _ = buf_return_tx.send(buf).await;
                    }

                    StreamRequest::SetPriority(priority) => {
                        if let Err(e) = send.set_priority(priority) {
                            tracing::trace!(error = %e, "failed to set priority");
                        }
                    }

                    StreamRequest::Reset(code) => {
                        tracing::debug!(code = code, "resetting stream");
                        let _ = send.reset(code.into());
                        break;
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
    close_tx: AsyncSender<StreamClosed>,
) {
    let limits = net_wire::FrameLimits::default();
    let mut buf = Vec::with_capacity(limits.max_recv_size as usize + 4);
    let mut read_buf = [0u8; 64 * 1024];

    loop {
        // Try to decode a complete frame from buffer
        match net_wire::decode_frame(&buf, &limits) {
            Ok((payload, consumed)) => {
                // Send payload to caller
                if payload_tx.send(payload).await.is_err() {
                    // Receiver dropped - stop reading
                    tracing::trace!("payload channel closed, stopping read task");
                    break;
                }

                // Remove consumed bytes from buffer
                buf.drain(..consumed);
                continue; // Try to decode more frames
            }
            Err(net_wire::DecodeError::Incomplete { .. }) => {
                // Need more data - fall through to read
            }
            Err(net_wire::DecodeError::FrameTooLarge { size, max }) => {
                tracing::warn!(size = size, max = max, "frame too large, closing stream");
                let _ = close_tx.send(StreamClosed::Disconnected).await;
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "frame decode error, closing stream");
                let _ = close_tx.send(StreamClosed::Disconnected).await;
                break;
            }
        }

        // Read more data from QUIC stream
        match recv.read(&mut read_buf).await {
            Ok(Some(n)) => {
                buf.extend_from_slice(&read_buf[..n]);
            }
            Ok(None) => {
                // Stream finished (FIN received)
                tracing::trace!("peer finished stream");

                // Process any remaining data in buffer
                while !buf.is_empty() {
                    match net_wire::decode_frame(&buf, &limits) {
                        Ok((payload, consumed)) => {
                            let _ = payload_tx.send(payload).await;
                            buf.drain(..consumed);
                        }
                        Err(_) => break,
                    }
                }

                let _ = close_tx.send(StreamClosed::PeerFinished).await;
                break;
            }
            Err(e) => {
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

                let _ = close_tx.send(close_reason).await;
                break;
            }
        }
    }
}

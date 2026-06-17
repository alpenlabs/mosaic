//! Version-handshake exchange over a QUIC bi-stream.
//!
//! See [`mosaic_net_svc_api::handshake`] for the payload shape and validation
//! rules. This module owns the on-the-wire framing and the timeout/timing
//! around the exchange itself.

use std::time::Duration;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use mosaic_net_svc_api::handshake::{
    HandshakeMismatch, HandshakePayload, MAX_HANDSHAKE_PAYLOAD_BYTES, validate_handshake,
};
use quinn::Connection;

/// Maximum time the handshake exchange may take, end-to-end (stream open +
/// send + receive). Generous to absorb scheduling jitter; this is local LAN
/// traffic for a tiny payload.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of an attempted handshake exchange.
#[derive(Debug)]
pub enum HandshakeError {
    /// The remote payload was a valid `HandshakePayload` but did not match
    /// our local config (protocol-version, deployment-version, magic).
    Mismatch(HandshakeMismatch),
    /// Timed out waiting for the stream to open / payload to arrive.
    Timeout,
    /// Stream open / write / read transport error.
    Transport(String),
    /// Remote claimed a payload size larger than [`MAX_HANDSHAKE_PAYLOAD_BYTES`].
    PayloadTooLarge { len: usize },
    /// `ark-serialize` could not decode the payload bytes.
    Decode(String),
}

impl HandshakeError {
    /// Short, log-safe reason string.
    pub fn reason(&self) -> String {
        match self {
            Self::Mismatch(m) => m.reason().to_string(),
            Self::Timeout => "handshake timed out".to_string(),
            Self::Transport(e) => format!("transport error: {e}"),
            Self::PayloadTooLarge { len } => format!("payload too large: {len} bytes"),
            Self::Decode(e) => format!("decode error: {e}"),
        }
    }

    /// Whether this error reflects actual peer-protocol disagreement (versus
    /// a transient transport hiccup). Only disagreement marks the peer as
    /// incompatible; transient errors are surfaced as a failed connection
    /// attempt that the normal reconnect logic will retry.
    ///
    /// Marking on `Timeout`/`Transport` would mean a single network blip mid-
    /// handshake could permanently wedge both sides (each marks the other
    /// incompatible, neither side reconnects, requires operator restart).
    ///
    /// Note this is asymmetric: when the peer's side hits a decode/mismatch
    /// they may reset the stream, surfacing on our side as `Transport`. We
    /// will treat that as transient and retry while they mark us
    /// incompatible. Behaviorally fine — our retries either keep failing
    /// (and the peer keeps suppressing) or succeed once one side is
    /// upgraded, at which point a successful inbound clears both sides.
    pub fn indicates_incompatibility(&self) -> bool {
        match self {
            Self::Mismatch(_) | Self::PayloadTooLarge { .. } | Self::Decode(_) => true,
            Self::Timeout | Self::Transport(_) => false,
        }
    }
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch(m) => write!(f, "{m}"),
            other => write!(f, "{}", other.reason()),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Outbound side: open a bi-stream, send our payload, read the peer's payload,
/// validate. Returns the validated remote payload on success.
pub async fn run_outbound_handshake(
    connection: &Connection,
    local_protocol_version: u32,
    local_deployment_version: Option<&str>,
    local_reduced_circuits: bool,
) -> Result<HandshakePayload, HandshakeError> {
    let local = HandshakePayload {
        magic: mosaic_net_svc_api::handshake::HANDSHAKE_MAGIC,
        protocol_version: local_protocol_version,
        deployment_version: local_deployment_version.map(str::to_string),
        reduced_circuits: local_reduced_circuits,
    };

    let stream_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.open_bi()).await;
    let (send, recv) = match stream_result {
        Ok(Ok((send, recv))) => (send, recv),
        Ok(Err(e)) => return Err(HandshakeError::Transport(e.to_string())),
        Err(_) => return Err(HandshakeError::Timeout),
    };

    exchange(
        send,
        recv,
        &local,
        local_protocol_version,
        local_deployment_version,
        local_reduced_circuits,
    )
    .await
}

/// Inbound side: accept a bi-stream, read the peer's payload, send our payload,
/// validate. Returns the validated remote payload on success.
pub async fn run_inbound_handshake(
    connection: &Connection,
    local_protocol_version: u32,
    local_deployment_version: Option<&str>,
    local_reduced_circuits: bool,
) -> Result<HandshakePayload, HandshakeError> {
    let local = HandshakePayload {
        magic: mosaic_net_svc_api::handshake::HANDSHAKE_MAGIC,
        protocol_version: local_protocol_version,
        deployment_version: local_deployment_version.map(str::to_string),
        reduced_circuits: local_reduced_circuits,
    };

    let stream_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi()).await;
    let (send, recv) = match stream_result {
        Ok(Ok((send, recv))) => (send, recv),
        Ok(Err(e)) => return Err(HandshakeError::Transport(e.to_string())),
        Err(_) => return Err(HandshakeError::Timeout),
    };

    exchange(
        send,
        recv,
        &local,
        local_protocol_version,
        local_deployment_version,
        local_reduced_circuits,
    )
    .await
}

/// Symmetric exchange: write our payload, read theirs, validate. Both halves
/// run concurrently so a slow peer on one direction doesn't extend wall-clock
/// past the timeout.
#[allow(clippy::too_many_arguments)]
async fn exchange(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local: &HandshakePayload,
    local_protocol_version: u32,
    local_deployment_version: Option<&str>,
    local_reduced_circuits: bool,
) -> Result<HandshakePayload, HandshakeError> {
    let mut bytes = Vec::new();
    local
        .serialize_with_mode(&mut bytes, Compress::No)
        .map_err(|e| HandshakeError::Decode(e.to_string()))?;
    if bytes.len() > MAX_HANDSHAKE_PAYLOAD_BYTES {
        return Err(HandshakeError::PayloadTooLarge { len: bytes.len() });
    }
    let len = bytes.len() as u32;

    let send_fut = async {
        send.write_all(&len.to_le_bytes())
            .await
            .map_err(|e| HandshakeError::Transport(format!("write len: {e}")))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| HandshakeError::Transport(format!("write payload: {e}")))?;
        send.finish()
            .map_err(|e| HandshakeError::Transport(format!("finish: {e}")))?;
        Ok::<(), HandshakeError>(())
    };

    let recv_fut = async {
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| HandshakeError::Transport(format!("read len: {e}")))?;
        let remote_len = u32::from_le_bytes(len_buf) as usize;
        if remote_len > MAX_HANDSHAKE_PAYLOAD_BYTES {
            return Err(HandshakeError::PayloadTooLarge { len: remote_len });
        }
        let mut buf = vec![0u8; remote_len];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| HandshakeError::Transport(format!("read payload: {e}")))?;
        HandshakePayload::deserialize_with_mode(buf.as_slice(), Compress::No, Validate::Yes)
            .map_err(|e| HandshakeError::Decode(e.to_string()))
    };

    let join = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        tokio::try_join!(send_fut, recv_fut)
    })
    .await;
    let (_, remote) = match join {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(HandshakeError::Timeout),
    };

    validate_handshake(
        local_protocol_version,
        local_deployment_version,
        local_reduced_circuits,
        &remote,
    )
    .map_err(HandshakeError::Mismatch)?;
    Ok(remote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicates_incompatibility_classification() {
        // Real protocol disagreement → mark.
        assert!(
            HandshakeError::Mismatch(HandshakeMismatch::ProtocolVersionMismatch {
                local: 1,
                remote: 2,
            })
            .indicates_incompatibility()
        );
        assert!(HandshakeError::Decode("bad".to_string()).indicates_incompatibility());
        assert!(HandshakeError::PayloadTooLarge { len: 9999 }.indicates_incompatibility());

        // Transient transport-layer issues → don't mark, let reconnect retry.
        assert!(!HandshakeError::Timeout.indicates_incompatibility());
        assert!(
            !HandshakeError::Transport("connection reset".to_string()).indicates_incompatibility()
        );
    }
}

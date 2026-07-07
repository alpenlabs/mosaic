//! Scheduler-to-scheduler advisory messages.
//!
//! [`SchedulerMessage`] carries best-effort hints from one peer's scheduler
//! to another, letting the receiver promote matching queued work ahead of
//! its FIFO order. Messages never touch the state machine and are not
//! replayed — if a message is lost in transit, the receiver falls back to
//! plain FIFO scheduling.
//!
//! Encoded via `ark-serialize` to match the rest of the mosaic wire surface.
//! The type is designed to be additive: adding new [`SchedulerMessage`]
//! variants is a wire-forward-compatible change since peers ignore unknown
//! variants at decode time.
//!
//! Callers on the receive side decode inbound bytes into a
//! [`SchedulerMessage`] and route it to their scheduler layer, where each
//! variant is mapped to a `HintKey` for queue promotion. The mapping lives
//! in the job scheduler crate (not here) to keep this module free of
//! scheduler dependencies.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

/// A scheduler-to-scheduler advisory message.
///
/// Wire-encoded as `[u8 tag][payload]`, where the tag is the numeric
/// discriminant. Peers ignore unknown tags at decode time (`InvalidTag`)
/// so introducing new variants doesn't break older peers — they simply
/// don't act on messages they don't understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerMessage {
    /// The sender is about to open a bulk transfer stream for a garbling
    /// table with the given commitment. The receiver's scheduler should
    /// promote a matching `ReceiveGarblingTable` job to the front of its
    /// light-pool queue so the expectation is registered before the
    /// stream lands.
    TransferStarting {
        /// Commitment identifying the table.
        commitment: [u8; 32],
    },
}

impl SchedulerMessage {
    /// Serialize to bytes. Returns the encoded frame ready to write to a
    /// scheduler-hint stream.
    pub fn encode(&self) -> Result<Vec<u8>, SchedulerMessageError> {
        let tag: u8 = match self {
            Self::TransferStarting { .. } => 1,
        };
        let mut buf = vec![tag];
        match self {
            Self::TransferStarting { commitment } => {
                commitment
                    .serialize_with_mode(&mut buf, Compress::No)
                    .map_err(|e| SchedulerMessageError::Encode(e.to_string()))?;
            }
        }
        Ok(buf)
    }

    /// Deserialize from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SchedulerMessageError> {
        let (tag, rest) = bytes
            .split_first()
            .ok_or(SchedulerMessageError::Truncated)?;
        match tag {
            1 => {
                let commitment = <[u8; 32] as CanonicalDeserialize>::deserialize_with_mode(
                    rest,
                    Compress::No,
                    Validate::Yes,
                )
                .map_err(|e| SchedulerMessageError::Decode(e.to_string()))?;
                Ok(Self::TransferStarting { commitment })
            }
            unknown => Err(SchedulerMessageError::UnknownTag(*unknown)),
        }
    }
}

/// Errors returned by [`SchedulerMessage`] encode / decode.
#[derive(Debug)]
pub enum SchedulerMessageError {
    /// The buffer was empty or ended mid-payload.
    Truncated,
    /// Tag byte didn't correspond to any known variant. Callers should
    /// treat this as a soft failure — the peer may be on newer code.
    UnknownTag(u8),
    /// `ark-serialize` failed to encode.
    Encode(String),
    /// `ark-serialize` failed to decode.
    Decode(String),
}

impl std::fmt::Display for SchedulerMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "scheduler message truncated"),
            Self::UnknownTag(t) => write!(f, "unknown scheduler message tag: {t}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for SchedulerMessageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_starting_roundtrip() {
        let msg = SchedulerMessage::TransferStarting {
            commitment: [7u8; 32],
        };
        let bytes = msg.encode().expect("encode");
        let decoded = SchedulerMessage::decode(&bytes).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_unknown_tag_returns_error() {
        let bytes = [255u8; 33];
        let err = SchedulerMessage::decode(&bytes).unwrap_err();
        assert!(matches!(err, SchedulerMessageError::UnknownTag(255)));
    }

    #[test]
    fn decode_empty_returns_truncated() {
        let err = SchedulerMessage::decode(&[]).unwrap_err();
        assert!(matches!(err, SchedulerMessageError::Truncated));
    }
}

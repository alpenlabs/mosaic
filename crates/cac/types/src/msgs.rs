//! Protocol message types for communication between Garbler and Evaluator.
//!
//! All message types are designed to fit within the 4 MiB network frame limit.
//! Large logical messages are split into chunks for transmission.

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use crate::{
    Adaptor, AdaptorMsgChunkWithdrawals, ChallengeIndices, CircuitInputShares,
    WideLabelWirePolynomialCommitments,
};

// ============================================================================
// Message Types (all fit within 4 MiB frame limit)
// ============================================================================

/// CommitMsgChunk: Garbler -> Evaluator (chunked by wire)
///
/// One chunk containing polynomial commitments for all 256 wide label values
/// of a single input wire.
///
/// Size (compressed): ~1.4 MB per chunk
/// Size (uncompressed): ~2.76 MB per chunk
/// Total chunks needed: N_INPUT_WIRES (172)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitMsgChunk {
    /// Which wire this chunk is for (0..N_INPUT_WIRES)
    pub wire_index: u16,
    /// Polynomial commitments for all 256 wide label values of this wire.
    /// Each PolynomialCommitment contains 174 curve points.
    pub commitments: WideLabelWirePolynomialCommitments,
}

/// ChallengeMsg: Evaluator -> Garbler
///
/// Evaluator's challenge after receiving commitment chunks.
/// Selects which circuits to open for verification.
///
/// Size: ~1.4 KB (fits in single frame, no chunking needed)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChallengeMsg {
    /// Indices of circuits to open for verification.
    /// Size: N_OPEN_CIRCUITS (174 of 181)
    pub challenge_indices: ChallengeIndices,
}

/// ChallengeResponseMsgChunk: Garbler -> Evaluator (chunked by circuit)
///
/// One chunk containing opened input shares for all wires × all wide label
/// values of a single challenged circuit.
///
/// Size: ~1.68 MB per chunk
/// Total chunks needed: N_OPEN_CIRCUITS (174)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChallengeResponseMsgChunk {
    /// Which circuit this chunk is for (index into challenge_indices, 0..N_OPEN_CIRCUITS)
    pub circuit_index: u16,
    /// Shares for all wires × all wide label values for this circuit.
    pub shares: CircuitInputShares,
}

/// AdaptorMsgChunk: Evaluator -> Garbler (chunked by deposit wire)
///
/// One chunk containing 1 deposit adaptor and 41 withdrawal wire adaptors.
/// Chunked to allow uncompressed transmission under 4 MiB frame limit.
///
/// Size (uncompressed): ~1.6 MB per chunk
/// Total chunks needed: N_DEPOSIT_INPUT_WIRES (4)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AdaptorMsgChunk {
    /// Which chunk this is (0..N_DEPOSIT_INPUT_WIRES, maps to deposit wire index)
    pub chunk_index: u8,
    /// Single deposit adaptor for this chunk's deposit wire
    pub deposit_adaptor: Adaptor,
    /// Adaptor signatures for 41 withdrawal wires × 256 values each.
    pub withdrawal_adaptors: AdaptorMsgChunkWithdrawals,
}

// ============================================================================
// Message Enum (for dispatching)
// ============================================================================

/// All protocol message types exchanged between Garbler and Evaluator.
///
/// All variants fit within the 4 MiB network frame limit.
///
/// Note: Acknowledgments are handled at the network layer, not here.
/// Note: Garbling tables are transferred via bulk streams, not protocol messages.
#[derive(Debug)]
#[expect(clippy::large_enum_variant, reason = "AdaptorMsg")]
pub enum Msg {
    /// Commitment chunk (Garbler -> Evaluator)
    CommitChunk(CommitMsgChunk),
    /// Challenge message (Evaluator -> Garbler)
    Challenge(ChallengeMsg),
    /// Challenge response chunk (Garbler -> Evaluator)
    ChallengeResponseChunk(ChallengeResponseMsgChunk),
    /// Adaptor signatures chunk (Evaluator -> Garbler)
    AdaptorChunk(AdaptorMsgChunk),
}

/// Message variant discriminant for serialization.
#[repr(u8)]
enum MsgVariant {
    CommitChunk = 0,
    Challenge = 1,
    ChallengeResponseChunk = 2,
    AdaptorChunk = 3,
}

impl TryFrom<u8> for MsgVariant {
    type Error = SerializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MsgVariant::CommitChunk),
            1 => Ok(MsgVariant::Challenge),
            2 => Ok(MsgVariant::ChallengeResponseChunk),
            3 => Ok(MsgVariant::AdaptorChunk),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerialize for Msg {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            Msg::CommitChunk(msg) => {
                (MsgVariant::CommitChunk as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::Challenge(msg) => {
                (MsgVariant::Challenge as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::ChallengeResponseChunk(msg) => {
                (MsgVariant::ChallengeResponseChunk as u8)
                    .serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::AdaptorChunk(msg) => {
                (MsgVariant::AdaptorChunk as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        1 + match self {
            Msg::CommitChunk(msg) => msg.serialized_size(compress),
            Msg::Challenge(msg) => msg.serialized_size(compress),
            Msg::ChallengeResponseChunk(msg) => msg.serialized_size(compress),
            Msg::AdaptorChunk(msg) => msg.serialized_size(compress),
        }
    }
}

impl CanonicalDeserialize for Msg {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let variant_byte = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        let variant = MsgVariant::try_from(variant_byte)?;

        match variant {
            MsgVariant::CommitChunk => {
                let msg = CommitMsgChunk::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::CommitChunk(msg))
            }
            MsgVariant::Challenge => {
                let msg = ChallengeMsg::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::Challenge(msg))
            }
            MsgVariant::ChallengeResponseChunk => {
                let msg = ChallengeResponseMsgChunk::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?;
                Ok(Msg::ChallengeResponseChunk(msg))
            }
            MsgVariant::AdaptorChunk => {
                let msg = AdaptorMsgChunk::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::AdaptorChunk(msg))
            }
        }
    }
}

impl Valid for Msg {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            Msg::CommitChunk(msg) => msg.check(),
            Msg::Challenge(msg) => msg.check(),
            Msg::ChallengeResponseChunk(msg) => msg.check(),
            Msg::AdaptorChunk(msg) => msg.check(),
        }
    }
}

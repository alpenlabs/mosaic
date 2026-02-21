//! Protocol message types for communication between Garbler and Evaluator.
//!
//! All message types are designed to fit within the 4 MiB network frame limit.
//! Large logical messages are split into a header (containing metadata) and
//! chunks (containing the bulk data) for transmission.

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use mosaic_common::{
    Byte32,
    constants::{N_CIRCUITS, N_EVAL_CIRCUITS},
};

use crate::{
    Adaptor, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, HeapArray,
    OpenedGarblingSeeds, OpenedOutputShares, OutputPolynomialCommitment, ReservedSetupInputShares,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptorsChunk,
};

// ============================================================================
// Commit Message Types (Garbler -> Evaluator)
// ============================================================================

/// CommitMsgHeader: Garbler -> Evaluator
///
/// Header containing garbling table commitments for all circuits.
/// Sent once before the commitment chunks.
///
/// Size: ~5.7 KB (fits in single frame)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitMsgHeader {
    /// Commitments to all N_CIRCUITS garbling tables.
    pub garbling_table_commitments: AllGarblingTableCommitments,
    /// Commitment to output wire polynomial for value 0.
    pub output_polynomial_commitment: OutputPolynomialCommitment,
    /// AES-128 keys for all N_CIRCUITS garbling instances.
    pub all_aes128_keys: HeapArray<[u8; 16], N_CIRCUITS>,
    /// Public S values for all N_CIRCUITS garbling instances.
    pub all_public_s: HeapArray<[u8; 16], N_CIRCUITS>,
    /// Constant-false wire labels for all N_CIRCUITS garbling instances.
    pub all_constant_zero_labels: HeapArray<[u8; 16], N_CIRCUITS>,
    /// Constant-true wire labels for all N_CIRCUITS garbling instances.
    pub all_constant_one_labels: HeapArray<[u8; 16], N_CIRCUITS>,
}

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

// ============================================================================
// Challenge Message Type (Evaluator -> Garbler)
// ============================================================================

/// ChallengeMsg: Evaluator -> Garbler
///
/// Evaluator's challenge after receiving commitment header and chunks.
/// Selects which circuits to open for verification.
///
/// Size: ~1.4 KB (fits in single frame, no chunking needed)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChallengeMsg {
    /// Indices of circuits to open for verification.
    /// Size: N_OPEN_CIRCUITS (174 of 181)
    pub challenge_indices: ChallengeIndices,
}

// ============================================================================
// Challenge Response Message Types (Garbler -> Evaluator)
// ============================================================================

/// ChallengeResponseMsgHeader: Garbler -> Evaluator
///
/// Header containing per-protocol data for the challenge response.
/// Sent once before the challenge response chunks.
///
/// Size: ~12.4 KB (fits in single frame)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChallengeResponseMsgHeader {
    /// Reserved input shares for setup input wires.
    /// Size: N_SETUP_INPUT_WIRES (32) shares
    pub reserved_setup_input_shares: ReservedSetupInputShares,
    /// Output shares for all opened circuits.
    /// Size: N_OPEN_CIRCUITS (174) shares
    pub opened_output_shares: OpenedOutputShares,
    /// Garbling seeds for all opened circuits.
    /// Size: N_OPEN_CIRCUITS (174) seeds
    pub opened_garbling_seeds: OpenedGarblingSeeds,
    /// Output label ciphertexts for the N_EVAL_CIRCUITS unopened circuits.
    /// Each encrypts the output share under the garbler's output label.
    /// The evaluator needs these to translate evaluation output → share scalar.
    pub unchallenged_output_label_cts: HeapArray<Byte32, N_EVAL_CIRCUITS>,
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

// ============================================================================
// Adaptor Message Type (Evaluator -> Garbler)
// ============================================================================

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
    pub withdrawal_adaptors: WithdrawalAdaptorsChunk,
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
pub enum Msg {
    /// Commitment header (Garbler -> Evaluator)
    CommitHeader(CommitMsgHeader),
    /// Commitment chunk (Garbler -> Evaluator)
    CommitChunk(CommitMsgChunk),
    /// Challenge message (Evaluator -> Garbler)
    Challenge(ChallengeMsg),
    /// Challenge response header (Garbler -> Evaluator)
    ChallengeResponseHeader(ChallengeResponseMsgHeader),
    /// Challenge response chunk (Garbler -> Evaluator)
    ChallengeResponseChunk(ChallengeResponseMsgChunk),
    /// Adaptor signatures chunk (Evaluator -> Garbler)
    AdaptorChunk(AdaptorMsgChunk),
}

/// Message variant discriminant for serialization.
#[repr(u8)]
enum MsgVariant {
    CommitHeader = 0,
    CommitChunk = 1,
    Challenge = 2,
    ChallengeResponseHeader = 3,
    ChallengeResponseChunk = 4,
    AdaptorChunk = 5,
}

impl TryFrom<u8> for MsgVariant {
    type Error = SerializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MsgVariant::CommitHeader),
            1 => Ok(MsgVariant::CommitChunk),
            2 => Ok(MsgVariant::Challenge),
            3 => Ok(MsgVariant::ChallengeResponseHeader),
            4 => Ok(MsgVariant::ChallengeResponseChunk),
            5 => Ok(MsgVariant::AdaptorChunk),
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
            Msg::CommitHeader(msg) => {
                (MsgVariant::CommitHeader as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::CommitChunk(msg) => {
                (MsgVariant::CommitChunk as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::Challenge(msg) => {
                (MsgVariant::Challenge as u8).serialize_with_mode(&mut writer, compress)?;
                msg.serialize_with_mode(&mut writer, compress)
            }
            Msg::ChallengeResponseHeader(msg) => {
                (MsgVariant::ChallengeResponseHeader as u8)
                    .serialize_with_mode(&mut writer, compress)?;
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
            Msg::CommitHeader(msg) => msg.serialized_size(compress),
            Msg::CommitChunk(msg) => msg.serialized_size(compress),
            Msg::Challenge(msg) => msg.serialized_size(compress),
            Msg::ChallengeResponseHeader(msg) => msg.serialized_size(compress),
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
            MsgVariant::CommitHeader => {
                let msg = CommitMsgHeader::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::CommitHeader(msg))
            }
            MsgVariant::CommitChunk => {
                let msg = CommitMsgChunk::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::CommitChunk(msg))
            }
            MsgVariant::Challenge => {
                let msg = ChallengeMsg::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(Msg::Challenge(msg))
            }
            MsgVariant::ChallengeResponseHeader => {
                let msg = ChallengeResponseMsgHeader::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?;
                Ok(Msg::ChallengeResponseHeader(msg))
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
            Msg::CommitHeader(msg) => msg.check(),
            Msg::CommitChunk(msg) => msg.check(),
            Msg::Challenge(msg) => msg.check(),
            Msg::ChallengeResponseHeader(msg) => msg.check(),
            Msg::ChallengeResponseChunk(msg) => msg.check(),
            Msg::AdaptorChunk(msg) => msg.check(),
        }
    }
}

// ============================================================================
// From impls for ergonomic message construction
// ============================================================================

impl From<CommitMsgHeader> for Msg {
    fn from(msg: CommitMsgHeader) -> Self {
        Msg::CommitHeader(msg)
    }
}

impl From<CommitMsgChunk> for Msg {
    fn from(msg: CommitMsgChunk) -> Self {
        Msg::CommitChunk(msg)
    }
}

impl From<ChallengeMsg> for Msg {
    fn from(msg: ChallengeMsg) -> Self {
        Msg::Challenge(msg)
    }
}

impl From<ChallengeResponseMsgHeader> for Msg {
    fn from(msg: ChallengeResponseMsgHeader) -> Self {
        Msg::ChallengeResponseHeader(msg)
    }
}

impl From<ChallengeResponseMsgChunk> for Msg {
    fn from(msg: ChallengeResponseMsgChunk) -> Self {
        Msg::ChallengeResponseChunk(msg)
    }
}

impl From<AdaptorMsgChunk> for Msg {
    fn from(msg: AdaptorMsgChunk) -> Self {
        Msg::AdaptorChunk(msg)
    }
}

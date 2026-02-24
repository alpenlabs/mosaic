use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _, SerializationError};
use mosaic_cac_types::{
    Adaptor, ChallengeIndices, CircuitInputShares, CircuitOutputShare, CompletedSignatures,
    DepositInputs, GarblingTableCommitment, OutputPolynomialCommitment, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptorsChunk, WithdrawalInputs,
};

use crate::{
    keyspace::KeyDomain,
    row_spec::{
        KVRowSpec, PackableKey, SerializableValue,
        error::{ArkKeyUnpackError, ArkSerializationError},
        garbler::{
            DepositChunkKey, DepositKey, ROW_TAG_CHALLENGE_INDICES, ROW_TAG_COMPLETED_SIGNATURES,
            ROW_TAG_DEPOSIT_ADAPTOR_CHUNK, ROW_TAG_DEPOSIT_INPUTS, ROW_TAG_DEPOSIT_SIGHASHES,
            ROW_TAG_GARBLING_TABLE_COMMITMENT, ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK,
            ROW_TAG_INPUT_SHARE, ROW_TAG_OUTPUT_POLY_COMMITMENT, ROW_TAG_OUTPUT_SHARE,
            ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK, ROW_TAG_WITHDRAWAL_INPUT,
        },
    },
};

/// Row-local key for singleton protocol rows.
#[derive(Debug)]
pub struct ProtocolSingletonKey;

impl PackableKey for ProtocolSingletonKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = Vec<u8>;

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        Ok(Vec::new())
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if !bytes.is_empty() {
            return Err(ArkKeyUnpackError::TrailingBytes);
        }
        Ok(Self)
    }
}

/// Row-local key for protocol rows keyed by wire index.
#[derive(Debug, Clone, Copy)]
pub struct WireIndexKey {
    pub(crate) wire_idx: u16,
}

impl WireIndexKey {
    /// Create a key for a given wire index.
    pub fn new(wire_idx: u16) -> Self {
        Self { wire_idx }
    }
}

impl PackableKey for WireIndexKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = [u8; 2];

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        Ok(self.wire_idx.to_be_bytes())
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if bytes.len() != 2 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 2,
                found: bytes.len(),
            });
        }
        Ok(Self {
            wire_idx: u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }
}

/// Row-local key for protocol rows keyed by circuit index.
#[derive(Debug, Clone, Copy)]
pub struct CircuitIndexKey {
    pub(crate) ckt_idx: u16,
}

impl CircuitIndexKey {
    /// Create a key for a given circuit index.
    pub fn new(ckt_idx: u16) -> Self {
        Self { ckt_idx }
    }
}

impl PackableKey for CircuitIndexKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = [u8; 2];

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        Ok(self.ckt_idx.to_be_bytes())
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if bytes.len() != 2 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 2,
                found: bytes.len(),
            });
        }
        Ok(Self {
            ckt_idx: u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }
}

macro_rules! impl_ark_serializable_value {
    ($ty:ty) => {
        impl SerializableValue for $ty {
            type SerializeError = ArkSerializationError;
            type DeserializeError = ArkSerializationError;
            type Serialized = Vec<u8>;

            fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
                let mut value = Vec::new();
                self.serialize_uncompressed(&mut value)
                    .map_err(ArkSerializationError::from)?;
                Ok(value)
            }

            fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
                let mut reader = bytes;
                // NOTE: for polynomial commitment x 256 ~ 1.3
                // deserialize_compressed ~ 7s
                // deserialize_uncompressed ~ 235ms
                // deserialize_uncompressed_unchecked ~ 89ms
                let value = <$ty>::deserialize_uncompressed_unchecked(&mut reader)
                    .map_err(ArkSerializationError::from)?;
                if !reader.is_empty() {
                    return Err(ArkSerializationError::from(SerializationError::InvalidData));
                }
                Ok(value)
            }
        }
    };
}

impl_ark_serializable_value!(WideLabelWirePolynomialCommitments);
impl_ark_serializable_value!(OutputPolynomialCommitment);
impl_ark_serializable_value!(CircuitInputShares);
impl_ark_serializable_value!(CircuitOutputShare);
impl_ark_serializable_value!(GarblingTableCommitment);
impl_ark_serializable_value!(ChallengeIndices);
impl_ark_serializable_value!(Sighashes);
impl_ark_serializable_value!(DepositInputs);
impl_ark_serializable_value!(WithdrawalInputs);
impl_ark_serializable_value!(Adaptor);
impl_ark_serializable_value!(WithdrawalAdaptorsChunk);
impl_ark_serializable_value!(CompletedSignatures);

/// Row spec for input polynomial commitment chunks.
#[derive(Debug)]
pub struct InputPolynomialCommitmentChunkRowSpec;

impl KVRowSpec for InputPolynomialCommitmentChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK;

    type Key = WireIndexKey;
    type Value = WideLabelWirePolynomialCommitments;
}

/// Row spec for output polynomial commitment.
#[derive(Debug)]
pub struct OutputPolynomialCommitmentRowSpec;

impl KVRowSpec for OutputPolynomialCommitmentRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_POLY_COMMITMENT;

    type Key = ProtocolSingletonKey;
    type Value = OutputPolynomialCommitment;
}

/// Row spec for input shares by circuit index.
#[derive(Debug)]
pub struct InputShareRowSpec;

impl KVRowSpec for InputShareRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_INPUT_SHARE;

    type Key = CircuitIndexKey;
    type Value = CircuitInputShares;
}

/// Row spec for output shares by circuit index.
#[derive(Debug)]
pub struct OutputShareRowSpec;

impl KVRowSpec for OutputShareRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_SHARE;

    type Key = CircuitIndexKey;
    type Value = CircuitOutputShare;
}

/// Row spec for garbling table commitments by zero-based circuit index.
#[derive(Debug)]
pub struct GarblingTableCommitmentRowSpec;

impl KVRowSpec for GarblingTableCommitmentRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_GARBLING_TABLE_COMMITMENT;

    type Key = CircuitIndexKey;
    type Value = GarblingTableCommitment;
}

/// Row spec for challenge indices singleton.
#[derive(Debug)]
pub struct ChallengeIndicesRowSpec;

impl KVRowSpec for ChallengeIndicesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_CHALLENGE_INDICES;

    type Key = ProtocolSingletonKey;
    type Value = ChallengeIndices;
}

/// Row spec for per-deposit sighashes.
#[derive(Debug)]
pub struct DepositSighashesRowSpec;

impl KVRowSpec for DepositSighashesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_SIGHASHES;

    type Key = DepositKey;
    type Value = Sighashes;
}

/// Row spec for per-deposit inputs.
#[derive(Debug)]
pub struct DepositInputsRowSpec;

impl KVRowSpec for DepositInputsRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_INPUTS;

    type Key = DepositKey;
    type Value = DepositInputs;
}

/// Row spec for per-deposit withdrawal inputs.
#[derive(Debug)]
pub struct WithdrawalInputRowSpec;

impl KVRowSpec for WithdrawalInputRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_INPUT;

    type Key = DepositKey;
    type Value = WithdrawalInputs;
}

/// Row spec for per-deposit adaptor chunks.
#[derive(Debug)]
pub struct DepositAdaptorChunkRowSpec;

impl KVRowSpec for DepositAdaptorChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_ADAPTOR_CHUNK;

    type Key = DepositChunkKey;
    type Value = Adaptor;
}

/// Row spec for per-deposit withdrawal adaptor chunks.
#[derive(Debug)]
pub struct WithdrawalAdaptorChunkRowSpec;

impl KVRowSpec for WithdrawalAdaptorChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK;

    type Key = DepositChunkKey;
    type Value = WithdrawalAdaptorsChunk;
}

/// Row spec for per-deposit completed signatures.
#[derive(Debug)]
pub struct CompletedSignaturesRowSpec;

impl KVRowSpec for CompletedSignaturesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_COMPLETED_SIGNATURES;

    type Key = DepositKey;
    type Value = CompletedSignatures;
}

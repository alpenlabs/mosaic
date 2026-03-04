//! Common key/value encodings for garbler and evaluator row specs.

use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _, SerializationError};
use mosaic_cac_types::{
    Adaptor, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CircuitOutputShare,
    CompletedSignatures, DepositAdaptors, DepositId, DepositInputs, OpenedGarblingSeeds,
    OpenedOutputShares, OutputPolynomialCommitment, PolynomialCommitment, ReservedSetupInputShares,
    Sighashes, WideLabelWireAdaptors, WideLabelWirePolynomialCommitments, WideLabelWireShares,
    WithdrawalAdaptorsChunk, WithdrawalInputs,
};
use mosaic_common::Byte32;

use crate::row_spec::{
    PackableKey, SerializableValue,
    error::{ArkKeyUnpackError, ArkSerializationError},
};

pub(crate) fn pack_deposit_id(deposit_id: &DepositId) -> Result<Vec<u8>, ArkSerializationError> {
    let mut key = Vec::new();
    deposit_id
        .serialize_compressed(&mut key)
        .map_err(ArkSerializationError::from)?;
    Ok(key)
}

pub(crate) fn unpack_deposit_id(bytes: &[u8]) -> Result<DepositId, ArkKeyUnpackError> {
    let mut reader = bytes;
    let deposit_id =
        DepositId::deserialize_compressed(&mut reader).map_err(ArkKeyUnpackError::Deserialize)?;
    if !reader.is_empty() {
        return Err(ArkKeyUnpackError::TrailingBytes);
    }
    Ok(deposit_id)
}

/// Reusable row-local key for singleton protocol rows.
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

/// Reusable row-local key for one deposit-scoped record.
#[derive(Debug, Clone, Copy)]
pub struct DepositKey {
    pub(crate) deposit_id: DepositId,
}

impl DepositKey {
    /// Create a row key from a deposit id.
    pub fn new(deposit_id: DepositId) -> Self {
        Self { deposit_id }
    }
}

impl PackableKey for DepositKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = Vec<u8>;

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        pack_deposit_id(&self.deposit_id)
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let deposit_id = unpack_deposit_id(bytes)?;
        Ok(Self { deposit_id })
    }
}

/// Reusable row-local key for one deposit-scoped chunk record.
#[derive(Debug, Clone, Copy)]
pub struct DepositChunkKey {
    pub(crate) deposit_id: DepositId,
    pub(crate) chunk_idx: u8,
}

impl DepositChunkKey {
    /// Create a row key from deposit id and chunk index.
    pub fn new(deposit_id: DepositId, chunk_idx: u8) -> Self {
        Self {
            deposit_id,
            chunk_idx,
        }
    }
}

impl PackableKey for DepositChunkKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = Vec<u8>;

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        let mut key = pack_deposit_id(&self.deposit_id)?;
        key.push(self.chunk_idx);
        Ok(key)
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let Some((&chunk_idx, deposit_bytes)) = bytes.split_last() else {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 1,
                found: 0,
            });
        };
        let deposit_id = unpack_deposit_id(deposit_bytes)?;
        Ok(Self {
            deposit_id,
            chunk_idx,
        })
    }
}

/// Row-local key for protocol rows keyed by wire index and sub-chunk index.
#[derive(Debug, Clone, Copy)]
pub struct WireSubChunkKey {
    pub(crate) wire_idx: u16,
    pub(crate) sub_chunk_idx: u8,
}

impl WireSubChunkKey {
    /// Create a key for a given wire index and sub-chunk index.
    pub fn new(wire_idx: u16, sub_chunk_idx: u8) -> Self {
        Self {
            wire_idx,
            sub_chunk_idx,
        }
    }
}

impl PackableKey for WireSubChunkKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = [u8; 3];

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        let [a, b] = self.wire_idx.to_be_bytes();
        Ok([a, b, self.sub_chunk_idx])
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if bytes.len() != 3 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 3,
                found: bytes.len(),
            });
        }
        Ok(Self {
            wire_idx: u16::from_be_bytes([bytes[0], bytes[1]]),
            sub_chunk_idx: bytes[2],
        })
    }
}

/// Row-local key for protocol rows keyed by circuit index and sub-chunk index.
#[derive(Debug, Clone, Copy)]
pub struct CircuitSubChunkKey {
    pub(crate) ckt_idx: u16,
    pub(crate) sub_chunk_idx: u8,
}

impl CircuitSubChunkKey {
    /// Create a key for a given circuit index and sub-chunk index.
    pub fn new(ckt_idx: u16, sub_chunk_idx: u8) -> Self {
        Self {
            ckt_idx,
            sub_chunk_idx,
        }
    }
}

impl PackableKey for CircuitSubChunkKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = [u8; 3];

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        let [a, b] = self.ckt_idx.to_be_bytes();
        Ok([a, b, self.sub_chunk_idx])
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if bytes.len() != 3 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 3,
                found: bytes.len(),
            });
        }
        Ok(Self {
            ckt_idx: u16::from_be_bytes([bytes[0], bytes[1]]),
            sub_chunk_idx: bytes[2],
        })
    }
}

/// Row-local key for deposit-scoped double-chunk records (e.g. sub-chunked withdrawal adaptors).
#[derive(Debug, Clone, Copy)]
pub struct DepositDoubleChunkKey {
    pub(crate) deposit_id: DepositId,
    pub(crate) chunk_idx: u8,
    pub(crate) sub_chunk_idx: u8,
}

impl DepositDoubleChunkKey {
    /// Create a row key from deposit id, chunk index, and sub-chunk index.
    pub fn new(deposit_id: DepositId, chunk_idx: u8, sub_chunk_idx: u8) -> Self {
        Self {
            deposit_id,
            chunk_idx,
            sub_chunk_idx,
        }
    }
}

impl PackableKey for DepositDoubleChunkKey {
    type PackingError = ArkSerializationError;

    type UnpackingError = ArkKeyUnpackError;

    type Packed = Vec<u8>;

    fn pack(&self) -> Result<Self::Packed, Self::PackingError> {
        let mut key = pack_deposit_id(&self.deposit_id)?;
        key.push(self.chunk_idx);
        key.push(self.sub_chunk_idx);
        Ok(key)
    }

    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        if bytes.len() < 2 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 2,
                found: bytes.len(),
            });
        }
        let sub_chunk_idx = bytes[bytes.len() - 1];
        let chunk_idx = bytes[bytes.len() - 2];
        let deposit_bytes = &bytes[..bytes.len() - 2];
        let deposit_id = unpack_deposit_id(deposit_bytes)?;
        Ok(Self {
            deposit_id,
            chunk_idx,
            sub_chunk_idx,
        })
    }
}

macro_rules! impl_trusted_ark_serializable_value {
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
                // SAFETY: `deserialize_uncompressed_unchecked` skips costly curve-point
                // validation checks. This is acceptable here because the data is read
                // exclusively from a local database that was written by the same node,
                // so the serialized points are already known to be well-formed.
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

impl_trusted_ark_serializable_value!(WideLabelWirePolynomialCommitments);
impl_trusted_ark_serializable_value!(PolynomialCommitment);
impl_trusted_ark_serializable_value!(OutputPolynomialCommitment);
impl_trusted_ark_serializable_value!(CircuitInputShares);
impl_trusted_ark_serializable_value!(WideLabelWireShares);
impl_trusted_ark_serializable_value!(CircuitOutputShare);
impl_trusted_ark_serializable_value!(AllGarblingTableCommitments);
impl_trusted_ark_serializable_value!(ChallengeIndices);
impl_trusted_ark_serializable_value!(ReservedSetupInputShares);
impl_trusted_ark_serializable_value!(OpenedOutputShares);
impl_trusted_ark_serializable_value!(OpenedGarblingSeeds);
impl_trusted_ark_serializable_value!(Sighashes);
impl_trusted_ark_serializable_value!(DepositInputs);
impl_trusted_ark_serializable_value!(WithdrawalInputs);
impl_trusted_ark_serializable_value!(Adaptor);
impl_trusted_ark_serializable_value!(DepositAdaptors);
impl_trusted_ark_serializable_value!(WideLabelWireAdaptors);
impl_trusted_ark_serializable_value!(WithdrawalAdaptorsChunk);
impl_trusted_ark_serializable_value!(CompletedSignatures);

impl SerializableValue for [u8; 16] {
    type SerializeError = ArkSerializationError;
    type DeserializeError = ArkKeyUnpackError;
    type Serialized = [u8; 16];

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(*self)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        if bytes.len() != 16 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 16,
                found: bytes.len(),
            });
        }
        let mut value = [0u8; 16];
        value.copy_from_slice(bytes);
        Ok(value)
    }
}

impl SerializableValue for Byte32 {
    type SerializeError = ArkSerializationError;
    type DeserializeError = ArkKeyUnpackError;
    type Serialized = [u8; 32];

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok((*self).into())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        if bytes.len() != 32 {
            return Err(ArkKeyUnpackError::InvalidLength {
                expected: 32,
                found: bytes.len(),
            });
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(bytes);
        Ok(Byte32::from(value))
    }
}

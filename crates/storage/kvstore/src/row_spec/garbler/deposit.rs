use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};
use mosaic_cac_types::{DepositId, state_machine::garbler::DepositState};

use crate::{
    keyspace::KeyDomain,
    row_spec::{
        KVRowSpec, PackableKey, SerializableValue,
        error::{ArkKeyUnpackError, ArkSerializationError},
        garbler::ROW_TAG_DEPOSIT_STATE,
    },
};

fn pack_deposit_id(deposit_id: &DepositId) -> Result<Vec<u8>, ArkSerializationError> {
    let mut key = Vec::new();
    deposit_id
        .serialize_compressed(&mut key)
        .map_err(ArkSerializationError::from)?;
    Ok(key)
}

fn unpack_deposit_id(bytes: &[u8]) -> Result<DepositId, ArkKeyUnpackError> {
    let mut reader = bytes;
    let deposit_id =
        DepositId::deserialize_compressed(&mut reader).map_err(ArkKeyUnpackError::Deserialize)?;
    if !reader.is_empty() {
        return Err(ArkKeyUnpackError::TrailingBytes);
    }
    Ok(deposit_id)
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

/// Row-local key for one garbler deposit state record.
#[derive(Debug)]
pub struct DepositStateKey {
    pub(crate) deposit_id: DepositId,
}

impl DepositStateKey {
    /// Create a row key from a deposit id.
    pub fn new(deposit_id: DepositId) -> Self {
        Self { deposit_id }
    }
}

impl PackableKey for DepositStateKey {
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

impl SerializableValue for DepositState {
    type SerializeError = postcard::Error;

    type DeserializeError = postcard::Error;

    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        postcard::to_allocvec(&self)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        postcard::from_bytes(bytes)
    }
}

/// Row specification for garbler per-deposit state.
#[derive(Debug)]
pub struct DepositStateRowSpec;

impl KVRowSpec for DepositStateRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_STATE;

    type Key = DepositStateKey;
    type Value = DepositState;
}

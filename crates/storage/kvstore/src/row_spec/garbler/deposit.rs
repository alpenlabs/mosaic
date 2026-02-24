use mosaic_cac_types::{DepositId, state_machine::garbler::DepositState};

use crate::{
    keyspace::KeyDomain,
    row_spec::{
        KVRowSpec, PackableKey, SerializableValue,
        common::{pack_deposit_id, unpack_deposit_id},
        error::{ArkKeyUnpackError, ArkSerializationError},
        garbler::ROW_TAG_DEPOSIT_STATE,
    },
};

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

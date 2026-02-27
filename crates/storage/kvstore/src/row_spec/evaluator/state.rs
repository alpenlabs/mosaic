use mosaic_cac_types::{
    DepositId,
    state_machine::evaluator::{DepositState, EvaluatorState},
};

use crate::row_spec::{
    KVRowSpec, PackableKey, SerializableValue,
    common::{pack_deposit_id, unpack_deposit_id},
    error::{ArkKeyUnpackError, ArkSerializationError},
    evaluator::{ROW_TAG_DEPOSIT_STATE, ROW_TAG_ROOT_STATE},
};

/// Row-local key for evaluator root state.
#[derive(Debug)]
pub struct RootStateKey;

impl PackableKey for RootStateKey {
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

impl SerializableValue for EvaluatorState {
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

/// Row specification for evaluator root state.
#[derive(Debug)]
pub struct RootStateRowSpec;

impl KVRowSpec for RootStateRowSpec {
    const ROW_TAG: u8 = ROW_TAG_ROOT_STATE;

    type Key = RootStateKey;
    type Value = EvaluatorState;
}

/// Row-local key for one evaluator deposit state record.
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

/// Row specification for evaluator per-deposit state.
#[derive(Debug)]
pub struct DepositStateRowSpec;

impl KVRowSpec for DepositStateRowSpec {
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_STATE;

    type Key = DepositStateKey;
    type Value = DepositState;
}

use mosaic_cac_types::state_machine::garbler::GarblerState;

use crate::row_spec::{
    KVRowSpec, PackableKey, SerializableValue,
    error::{ArkKeyUnpackError, ArkSerializationError},
    garbler::{ROW_TAG_ROOT_STATE},
};
use crate::keyspace::KeyDomain;

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

impl SerializableValue for GarblerState {
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

pub struct RootStateRowSpec;

impl KVRowSpec for RootStateRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_ROOT_STATE;

    type Key = RootStateKey;
    type Value = GarblerState;
}

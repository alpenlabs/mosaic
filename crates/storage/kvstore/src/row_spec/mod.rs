//! Row specifications for mapping typed state into KV rows.

use std::{error::Error, fmt::Debug};

use crate::keyspace::KeyDomain;

pub mod error;
pub mod garbler;

/// Specification for one logical KV row (domain, row tag, key, and value).
pub trait KVRowSpec {
    /// Domain this row belongs to (garbler/evaluator).
    const DOMAIN: KeyDomain;
    /// Row tag unique within the domain.
    const ROW_TAG: u8;

    /// Type of the key.
    type Key: PackableKey;
    /// Type of the value.
    type Value: SerializableValue;
}

/// A key that can be packed and unpacked into bytes. This is effective
/// serialization and deserialization, using FDB's terminology for keys
/// specifically.
pub trait PackableKey: Sized {
    /// Error type that can occur during packing.
    type PackingError: Error + Debug + Send + Sync + 'static;

    /// Error type that can occur during unpacking.
    type UnpackingError: Error + Debug + Send + Sync + 'static;

    /// Packed representation of the key.
    type Packed: AsRef<[u8]> + Clone + Send + Sync;

    /// Packs the row-local key into bytes.
    fn pack(&self) -> Result<Self::Packed, Self::PackingError>;

    /// Unpacks the row-local key from bytes.
    fn unpack(bytes: &[u8]) -> Result<Self, Self::UnpackingError>;
}

/// A value that can be serialized and deserialized into bytes.
pub trait SerializableValue: Sized {
    /// Error type that can occur during serialization.
    type SerializeError: Error + Debug + Send + Sync + 'static;

    /// Error type that can occur during deserialization.
    type DeserializeError: Error + Debug + Send + Sync + 'static;

    /// Serialized representation of the value.
    type Serialized: AsRef<[u8]> + Clone + Send + Sync;

    /// Serializes self to bytes.
    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError>;

    /// Deserializes self from bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError>;
}

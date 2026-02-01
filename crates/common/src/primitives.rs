use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// A 32 byte value.
#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Deserialize,
    Serialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Byte32([u8; 32]);

impl AsRef<[u8]> for Byte32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Byte32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<Byte32> for [u8; 32] {
    fn from(value: Byte32) -> Self {
        value.0
    }
}

impl Byte32 {
    /// Returns the value as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            use std::fmt::Write;
            write!(s, "{:02x}", byte).unwrap();
        }
        s
    }
}

impl std::fmt::Display for Byte32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Represents a stable identifier for a node over p2p.
#[derive(
    Clone, Debug, Deserialize, Serialize, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct PeerId(pub Vec<u8>);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

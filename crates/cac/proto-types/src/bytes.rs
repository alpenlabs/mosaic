use serde::{Deserialize, Serialize};

// TODO: serialize as hex string for humans

/// A 32 byte value.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
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

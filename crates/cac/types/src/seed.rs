use std::fmt;

use mosaic_vs3::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Seed for deterministic Garbling Table generation
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Create a [`Seed`] from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw 32-byte representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the raw 32-byte array by value.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return a lowercase hex encoding of the peer ID.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Generate a random seed using provided rng.
    pub fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<[u8; 32]> for Seed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Seed> for [u8; 32] {
    fn from(id: Seed) -> Self {
        id.0
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for Seed {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Seed {
    type Error = std::array::TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = slice.try_into()?;
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Display / Debug
// ---------------------------------------------------------------------------

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed({})", &hex::encode(self.0))
    }
}

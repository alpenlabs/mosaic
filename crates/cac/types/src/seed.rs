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
    pub fn rand<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
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
// Display / Debug — both deliberately redact secret bytes
// ---------------------------------------------------------------------------
//
// `Seed` carries protocol-secret material (garbling seeds, polynomial seeds).
// Default formatting (`{}`, `{:?}`, derived `Debug` on enclosing types) must
// not leak these bytes into logs, panic messages, or operator-visible
// diagnostics. Callers that need the raw bytes must reach for the explicit
// accessors (`to_hex`, `as_bytes`, `to_bytes`).

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_seed_bytes() {
        let seed = Seed::from_bytes([0xAB; 32]);
        let debug = format!("{seed:?}");
        assert!(
            !debug.contains("ab"),
            "Debug must not include raw hex; got: {debug}"
        );
        assert_eq!(debug, "Seed(<redacted>)");
    }

    #[test]
    fn display_does_not_leak_seed_bytes() {
        let seed = Seed::from_bytes([0xCD; 32]);
        let display = format!("{seed}");
        assert!(
            !display.contains("cd"),
            "Display must not include raw hex; got: {display}"
        );
        assert_eq!(display, "Seed(<redacted>)");
    }

    #[test]
    fn to_hex_remains_the_explicit_accessor() {
        let seed = Seed::from_bytes([0xEF; 32]);
        let hex = seed.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ef"));
    }
}

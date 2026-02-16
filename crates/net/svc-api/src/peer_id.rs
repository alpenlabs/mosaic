//! Peer identity types.
//!
//! A peer is identified by its 32-byte Ed25519 public key. This module
//! provides the [`PeerId`] newtype and helpers for deriving it from
//! Ed25519 keys.

use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Peer identity — 32-byte Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Create a [`PeerId`] from raw bytes.
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
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<[u8; 32]> for PeerId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<PeerId> for [u8; 32] {
    fn from(id: PeerId) -> Self {
        id.0
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for PeerId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = std::array::TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = slice.try_into()?;
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Display / Debug
// ---------------------------------------------------------------------------

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", &hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// Ed25519 helpers
// ---------------------------------------------------------------------------

/// Derive a [`PeerId`] from an Ed25519 [`VerifyingKey`].
pub fn peer_id_from_verifying_key(key: &VerifyingKey) -> PeerId {
    PeerId(key.to_bytes())
}

/// Derive a [`PeerId`] from an Ed25519 [`SigningKey`].
pub fn peer_id_from_signing_key(key: &SigningKey) -> PeerId {
    peer_id_from_verifying_key(&key.verifying_key())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let peer_id = peer_id_from_signing_key(&signing_key);
        let verifying_key = signing_key.verifying_key();

        assert_eq!(peer_id, peer_id_from_verifying_key(&verifying_key));
        assert_eq!(*peer_id.as_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [7u8; 32];
        let id = PeerId::from_bytes(bytes);
        assert_eq!(id.to_bytes(), bytes);
    }

    #[test]
    fn try_from_slice() {
        let bytes = [3u8; 32];
        let id = PeerId::try_from(bytes.as_slice()).unwrap();
        assert_eq!(id, PeerId::from(bytes));

        let short = [0u8; 16];
        assert!(PeerId::try_from(short.as_slice()).is_err());
    }

    #[test]
    fn display_is_hex() {
        let id = PeerId::from([0xab; 32]);
        assert_eq!(id.to_string(), "ab".repeat(32));
    }
}

//! Peer identity types.
//!
//! A peer is identified by its 32-byte Ed25519 public key. This module
//! provides the [`PeerId`] type alias and helpers for deriving it from
//! Ed25519 keys.

use ed25519_dalek::{SigningKey, VerifyingKey};

/// Peer identity — 32-byte Ed25519 public key.
pub type PeerId = [u8; 32];

/// Extract [`PeerId`] from a [`VerifyingKey`].
pub fn peer_id_from_verifying_key(key: &VerifyingKey) -> PeerId {
    key.to_bytes()
}

/// Extract [`PeerId`] from a [`SigningKey`].
pub fn peer_id_from_signing_key(key: &SigningKey) -> PeerId {
    peer_id_from_verifying_key(&key.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let peer_id = peer_id_from_signing_key(&signing_key);
        let verifying_key = signing_key.verifying_key();

        assert_eq!(peer_id, peer_id_from_verifying_key(&verifying_key));
        assert_eq!(peer_id, verifying_key.to_bytes());
    }
}

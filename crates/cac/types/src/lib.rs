//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

// Used by examples
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::Valid;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Used by benchmarks
#[cfg(test)]
use criterion as _;

pub mod adaptor;
mod msgs;
mod protocol;
mod seed;
pub mod state_machine;

pub use adaptor::{Adaptor, Signature};
use mosaic_adaptor_sigs::{deserialize_field, serialize_field};
use mosaic_common::{Byte32, impl_serde_ark};
use mosaic_vs3::{Point, Scalar};
pub use msgs::*;
pub use protocol::*;
pub use seed::Seed;
use serde::{Deserialize, Serialize};

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Unique deposit id.
#[derive(
    Debug,
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
pub struct DepositId(pub Byte32);

impl std::fmt::Display for DepositId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<Byte32>> From<T> for DepositId {
    fn from(value: T) -> Self {
        DepositId(value.into())
    }
}

/// Sighash used in transaction signing;
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sighash(pub Byte32);

impl<T: Into<Byte32>> From<T> for Sighash {
    fn from(value: T) -> Self {
        Sighash(value.into())
    }
}

/// Secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey(pub Scalar);

impl_serde_ark!(SecretKey);

impl SecretKey {
    /// Create a secret key from bytes for tests.
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        let scalar = Scalar::from_le_bytes_mod_order(bytes);
        Self(scalar)
    }

    /// Generate a random secret key.
    pub fn rand<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        Self(Scalar::rand(rng))
    }

    /// Derive the public key from this secret key.
    pub fn to_pubkey(&self) -> PubKey {
        PubKey(Point::generator() * self.0)
    }
}

/// Public Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PubKey(pub Point);

impl_serde_ark!(PubKey);

impl PubKey {
    /// A Schnorr signing key is valid if it is non-zero and its affine y-coordinate is even.
    pub fn valid(&self) -> bool {
        let aff = self.0.into_affine();

        if aff.is_zero() {
            return false;
        }

        aff.y().is_some_and(|y| y.into_bigint().is_even())
    }

    /// Create from BIP340 compatible x-only pubkey bytes
    pub fn try_from_bytes(bytes: &[u8; 32]) -> Result<Self, String> {
        let x: ark_secp256k1::Fq = deserialize_field(bytes).map_err(|e| e.to_string())?;

        let (y, neg_y) = ark_secp256k1::Affine::get_ys_from_x_unchecked(x).unwrap();

        let y = if y.into_bigint().is_even() { y } else { neg_y };

        let a = ark_secp256k1::Affine::new_unchecked(x, y);

        a.check().map_err(|e| e.to_string())?;

        Ok(PubKey(a.into()))
    }

    /// Convert to BIP340 compatible x-only pubkey bytes
    pub fn to_x_only_bytes(&self) -> [u8; 32] {
        let aff = self.0.into_affine();

        serialize_field(&aff.x)
    }
}

#[cfg(test)]
mod serde_tests;

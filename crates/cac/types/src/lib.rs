//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

// Used by examples
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Used by benchmarks
#[cfg(test)]
use criterion as _;

mod adaptor;
mod msgs;
mod protocol;
pub mod state_machine;

pub use adaptor::*;
use mosaic_common::{Byte32, impl_serde_ark};
use mosaic_vs3::{Point, Scalar};
pub use msgs::*;
pub use protocol::*;
use serde::{Deserialize, Serialize};

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Seed for deterministic Garbling Table generation
pub type Seed = Byte32;

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
    /// Helpers to serialize and deserialize field as per BIP340
    pub fn serialize_field<F: PrimeField>(x: &F) -> [u8; 32] {
        // `Fq` modulus is 256 bits, so its big-endian encoding always fits in 32 bytes.
        x.into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("Fq encodes to exactly 32 bytes")
    }

    fn deserialize_field<F: PrimeField>(bytes: [u8; 32]) -> Result<F, String> {
        fn bytes_be_to_bits_be(bytes: &[u8]) -> Vec<bool> {
            let mut bits = Vec::with_capacity(bytes.len() * 8);
            for &b in bytes {
                for i in (0..8).rev() {
                    bits.push(((b >> i) & 1) == 1);
                }
            }
            bits
        }
        let rint = F::BigInt::from_bits_be(&bytes_be_to_bits_be(&bytes));
        F::from_bigint(rint).ok_or(String::from(
            "conversion from bigint to field element",
        ))
    }

    /// Create a secret key from bytes for tests.
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        let scalar = Self::deserialize_field(*bytes).unwrap();
        Self(scalar)
    }

    /// Generate a random secret key.
    pub fn rand<R: rand::Rng>(rng: &mut R) -> Self {
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
}

#[cfg(test)]
mod serde_tests;

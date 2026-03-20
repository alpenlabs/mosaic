use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mosaic_common::impl_serde_ark;
use mosaic_vs3::{Point, Scalar, gen_mul};
use rand::{CryptoRng, RngCore};

/// Secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey(pub Scalar);

impl_serde_ark!(SecretKey);

impl SecretKey {
    #[cfg(feature = "test-utils")]
    /// Create a secret key from bytes for tests.
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        let scalar = Scalar::from_be_bytes_mod_order(bytes);
        Self(scalar)
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

/// secp256k1 keypair
#[derive(Debug, Clone, Copy)]
pub struct KeyPair(SecretKey, PubKey);

impl KeyPair {
    /// Generates a random secp256k1 keypair where the public key has an even Y coordinate.
    pub fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        loop {
            let mut sk = ark_secp256k1::Fr::rand(rng);
            if sk == ark_secp256k1::Fr::ZERO {
                continue;
            }

            let mut pk = gen_mul(&sk);
            let pk_affine = pk.into_affine();
            let y_is_odd = pk_affine.y.into_bigint().is_odd();

            if y_is_odd {
                sk.neg_in_place();
                pk.neg_in_place();
            }
            return Self(SecretKey(sk), PubKey(pk));
        }
    }

    /// Get pubkey
    pub fn public_key(&self) -> PubKey {
        self.1
    }

    /// Get secretkey
    pub fn secret_key(&self) -> SecretKey {
        self.0
    }
}

//! Polynomial arithmetic over the secp256k1 curve for the VS3 protocol.

use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
pub use ark_secp256k1::{Fr as Scalar, Projective as Point};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid, Validate};
use ckt_gobble::Label;
use rand_chacha::rand_core::{CryptoRng, RngCore};

use crate::{
    error::Error, psm::{gen_batch_mul, gen_mul}, N_COEFFICIENTS, N_DOMAIN_UPPER_BOUND
};

/// Represents an evaluation index for a polynomial, type-safe and bounds-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Index(usize);

impl CanonicalSerialize for Index {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.0 as u64).serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        (self.0 as u64).serialized_size(compress)
    }
}

impl CanonicalDeserialize for Index {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = u64::deserialize_with_mode(reader, compress, validate)?;
        Ok(Self(value as usize))
    }
}

impl Valid for Index {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Index {
    /// Minimum index, we reserve index 0.
    pub const MIN: usize = 1;
    /// Maximum index.
    pub const MAX: usize = N_DOMAIN_UPPER_BOUND;

    /// Check the index is within bounds.
    pub const fn new(value: usize) -> Option<Self> {
        if value >= Self::MIN && value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Get reserved index.
    pub const fn reserved() -> Self {
        Self(0)
    }

    /// Get the underlying index value.
    pub const fn get(&self) -> usize {
        self.0
    }

    /// Convert index to a scalar for evaluation.
    pub fn to_scalar(&self) -> Scalar {
        Scalar::from(self.0 as u64)
    }
}

/// A share of a polynomial, representing an index and an evaluation value at that index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Share(Index, Scalar);

impl Share {
    /// Create a new share.
    pub fn new(index: Index, value: Scalar) -> Self {
        Self(index, value)
    }

    /// Get the index of this share.
    pub fn index(&self) -> Index {
        self.0
    }

    /// Get the value of this share.
    pub fn value(&self) -> Scalar {
        self.1
    }

    /// Commit to a share.
    pub fn commit(&self) -> ShareCommitment {
        ShareCommitment(self.0, gen_mul(&self.1))
    }

    /// truncate: conversion from Share to ckt_gobble::Label
    pub fn truncate(&self) -> Label {
        let x: [u8; 32] = self
            .1
            .into_bigint()
            .to_bytes_le()
            .try_into()
            .expect("encode 32 bytes");
        let x: [u8; 16] = x[0..16].try_into().unwrap();
        Label::from(x)
    }
}

/// A commitment to a share of a polynomial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShareCommitment(Index, Point);

impl ShareCommitment {
    /// Returns the index component of this share commitment.
    pub fn index(&self) -> Index {
        self.0
    }

    /// Returns the point component of this share commitment (the EC commitment
    /// to the share's scalar value).
    pub fn point(&self) -> Point {
        self.1
    }
}

/// A polynomial with scalar coefficients.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Polynomial {
    coefficients: [Scalar; N_COEFFICIENTS],
}

impl Polynomial {
    /// Generates a random polynomial with scalar coefficients.
    pub fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            coefficients: std::array::from_fn(|_| Scalar::rand(rng)),
        }
    }

    /// Evaluate polynomial at `idx` with Horner's method.
    pub fn eval(&self, idx: Index) -> Share {
        if self.coefficients.is_empty() {
            return Share::new(idx, Scalar::zero());
        }
        let x = idx.to_scalar();
        let mut it = self.coefficients.iter().rev();
        let mut acc = *it.next().unwrap();
        for c in it {
            acc = *c + acc * x;
        }
        Share::new(idx, acc)
    }

    /// Commit to the polynomial by committing to each of its coefficients.
    pub fn commit(&self) -> PolynomialCommitment {
        PolynomialCommitment {
            coefficients: gen_batch_mul(&self.coefficients).try_into().unwrap(),
        }
    }
}

/// A polynomial with point coefficients, representing a commitment to the polynomial's scalar
/// coefficients.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolynomialCommitment {
    coefficients: [Point; N_COEFFICIENTS],
}

impl PolynomialCommitment {
    /// Evaluate the committed polynomial at `idx` with Horner's method.
    pub fn eval(&self, idx: Index) -> ShareCommitment {
        if self.coefficients.is_empty() {
            return ShareCommitment(idx, Point::zero());
        }
        let x = idx.to_scalar();
        let mut it = self.coefficients.iter().rev();
        let mut acc = *it.next().unwrap();
        for c in it {
            acc = *c + acc * x;
        }
        ShareCommitment(idx, acc)
    }

    /// Verify a share: `commitment of (polynomial(idx)) == (commitment of polynomial)(idx)`.
    pub fn verify_share(&self, share: Share) -> Result<(), Error> {
        let expected = self.eval(share.0);
        if expected == share.commit() {
            Ok(())
        } else {
            Err(Error::ShareCommitmentMismatch { index: share.0 })
        }
    }

    /// Returns the zeroth coefficient of this polynomial commitment.
    ///
    /// This is the EC commitment to the polynomial's constant term, which
    /// equals the commitment to the share at reserved index 0. Used by the
    /// evaluator to compute share commitments for adaptor signature generation.
    pub fn get_zeroth_coefficient(&self) -> Point {
        self.coefficients[0]
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::One;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_index_new() {
        // Test valid indices
        assert!(Index::new(Index::MIN).is_some());
        assert!(Index::new(Index::MAX).is_some());
        assert!(Index::new(5).is_some());

        // Test invalid indices
        assert!(Index::new(0).is_none()); // Below MIN
        assert!(Index::new(Index::MAX + 1).is_none()); // Above MAX
    }

    #[test]
    fn test_index_reserved() {
        let reserved = Index::reserved();
        assert_eq!(reserved.get(), 0);
    }

    #[test]
    fn test_index_get() {
        let idx = Index::new(42).unwrap();
        assert_eq!(idx.get(), 42);
    }

    #[test]
    fn test_index_to_scalar() {
        let idx = Index::new(7).unwrap();
        let scalar = idx.to_scalar();
        assert_eq!(scalar, Scalar::from(7u64));

        let reserved = Index::reserved();
        assert_eq!(reserved.to_scalar(), Scalar::from(0u64));
    }

    #[test]
    fn test_index_display() {
        let idx = Index::new(123).unwrap();
        assert_eq!(format!("{}", idx), "123");
    }

    #[test]
    fn test_share_new_and_accessors() {
        let index = Index::new(5).unwrap();
        let value = Scalar::from(42u64);
        let share = Share::new(index, value);

        assert_eq!(share.index(), index);
        assert_eq!(share.value(), value);
    }

    #[test]
    fn test_share_commit() {
        let index = Index::new(3).unwrap();
        let value = Scalar::from(10u64);
        let share = Share::new(index, value);

        let commitment = share.commit();

        // Commitment should use gen_mul on the value
        let expected_point = gen_mul(&value);
        assert_eq!(commitment, ShareCommitment(index, expected_point));
    }

    #[test]
    fn test_polynomial_eval_simple() {
        // Create a simple polynomial: f(x) = 2 + 3x + 5x^2
        let mut coeffs = [Scalar::zero(); N_COEFFICIENTS];
        coeffs[0] = Scalar::from(2u64);
        coeffs[1] = Scalar::from(3u64);
        coeffs[2] = Scalar::from(5u64);

        let poly = Polynomial {
            coefficients: coeffs,
        };

        // Evaluate at x = 4
        let index = Index::new(4).unwrap();
        let share = poly.eval(index);

        // f(4) = 2 + 3*4 + 5*16 = 2 + 12 + 80 = 94
        let expected = Scalar::from(2u64)
            + Scalar::from(3u64) * Scalar::from(4u64)
            + Scalar::from(5u64) * Scalar::from(16u64);

        assert_eq!(share.index(), index);
        assert_eq!(share.value(), expected);
    }

    #[test]
    fn test_polynomial_eval_at_zero() {
        // Create polynomial with random coefficients
        let mut rng = OsRng;
        let poly = Polynomial::rand(&mut rng);

        // Evaluate at reserved index (0)
        let reserved = Index::reserved();
        let share = poly.eval(reserved);

        // At x=0, f(0) should equal the constant term (first coefficient)
        assert_eq!(share.value(), poly.coefficients[0]);
    }

    #[test]
    fn test_polynomial_eval_horner() {
        // Test that Horner's method works correctly
        // f(x) = 1 + 2x + 3x^2
        let mut coeffs = [Scalar::zero(); N_COEFFICIENTS];
        coeffs[0] = Scalar::one();
        coeffs[1] = Scalar::from(2u64);
        coeffs[2] = Scalar::from(3u64);

        let poly = Polynomial {
            coefficients: coeffs,
        };

        let x = Index::new(10).unwrap();
        let share = poly.eval(x);

        // Manual calculation: 1 + 2*10 + 3*100 = 1 + 20 + 300 = 321
        let expected = Scalar::one()
            + Scalar::from(2u64) * Scalar::from(10u64)
            + Scalar::from(3u64) * Scalar::from(100u64);

        assert_eq!(share.value(), expected);
    }

    #[test]
    fn test_polynomial_commit() {
        let mut coeffs = [Scalar::zero(); N_COEFFICIENTS];
        coeffs[0] = Scalar::from(5u64);
        coeffs[1] = Scalar::from(7u64);

        let poly = Polynomial {
            coefficients: coeffs,
        };

        let commitment = poly.commit();

        // Check that commitments match gen_batch_mul
        let expected_points = gen_batch_mul(&poly.coefficients);
        for (i, expected) in expected_points.iter().enumerate() {
            assert_eq!(commitment.coefficients[i], *expected);
        }
    }

    #[test]
    fn test_polynomial_commitment_eval() {
        // Create a simple polynomial
        let mut coeffs = [Scalar::zero(); N_COEFFICIENTS];
        coeffs[0] = Scalar::from(1u64);
        coeffs[1] = Scalar::from(2u64);

        let poly = Polynomial {
            coefficients: coeffs,
        };

        let commitment = poly.commit();
        let index = Index::new(5).unwrap();
        let share_commitment = commitment.eval(index);

        // Manually compute what the commitment should be
        // Using Horner's method on points
        let x = Scalar::from(5u64);
        let point_coeffs = gen_batch_mul(&coeffs);

        let mut expected = point_coeffs[N_COEFFICIENTS - 1];
        for i in (0..N_COEFFICIENTS - 1).rev() {
            expected = point_coeffs[i] + expected * x;
        }

        assert_eq!(share_commitment, ShareCommitment(index, expected));
    }

    #[test]
    fn test_verify_share_success() {
        let mut rng = OsRng;
        let poly = Polynomial::rand(&mut rng);
        let commitment = poly.commit();

        // Generate a valid share
        let index = Index::new(7).unwrap();
        let share = poly.eval(index);

        // Verification should succeed
        assert!(commitment.verify_share(share).is_ok());
    }

    #[test]
    fn test_verify_share_failure() {
        let mut rng = OsRng;
        let poly = Polynomial::rand(&mut rng);
        let commitment = poly.commit();

        // Create an invalid share (wrong value for the index)
        let index = Index::new(7).unwrap();
        let wrong_value = Scalar::from(999u64);
        let invalid_share = Share::new(index, wrong_value);

        // Verification should fail
        let result = commitment.verify_share(invalid_share);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::ShareCommitmentMismatch { .. }
        ));
    }

    #[test]
    fn test_share_commitment_homomorphism() {
        // Test that commit(f(x)) == commit(f)(x)
        let mut rng = OsRng;
        let poly = Polynomial::rand(&mut rng);
        let poly_commitment = poly.commit();

        // Test at multiple indices
        for i in 1..=10 {
            let index = Index::new(i).unwrap();

            // Method 1: evaluate then commit
            let share = poly.eval(index);
            let share_commitment1 = share.commit();

            // Method 2: commit then evaluate
            let share_commitment2 = poly_commitment.eval(index);

            // They should be equal
            assert_eq!(
                share_commitment1, share_commitment2,
                "Homomorphism failed at index {}",
                i
            );
        }
    }
}

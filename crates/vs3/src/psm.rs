//! Point scalar multiplication precomputation for secp256k1's generator G.

use ark_ec::{PrimeGroup, scalar_mul::BatchMulPreprocessing};
use ark_secp256k1::{Fr as Scalar, Projective as Point};
use std::sync::LazyLock;

/// Number of scalars that will be multiplied in parallel.
const NUM_SCALARS: usize = 174;

/// Point scalar multiplication precomputation for G.
static PRECOMP_G: LazyLock<BatchMulPreprocessing<Point>> =
    LazyLock::new(|| BatchMulPreprocessing::new(Point::generator(), NUM_SCALARS));

/// Accessor for the point scalar multiplication precomputation.
#[inline]
pub fn precomp() -> &'static BatchMulPreprocessing<Point> {
    &PRECOMP_G
}

/// Single scalar version.
#[inline]
pub fn gen_mul(scalar: &Scalar) -> Point {
    precomp().batch_mul(&[*scalar])[0].into()
}

/// Batch version.
#[inline]
pub fn gen_batch_mul(scalars: &[Scalar]) -> Vec<Point> {
    precomp()
        .batch_mul(scalars)
        .into_iter()
        .map(|p| p.into())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, UniformRand, Zero};
    use rand::rngs::OsRng;

    #[test]
    fn test_gen_mul_correctness() {
        let mut rng = OsRng;
        let g = Point::generator();

        // Test with zero
        let zero = Scalar::zero();
        let result = gen_mul(&zero);
        let expected = g * zero;
        assert_eq!(result, expected, "gen_mul failed for zero scalar");

        // Test with one
        let one = Scalar::one();
        let result = gen_mul(&one);
        let expected = g * one;
        assert_eq!(result, expected, "gen_mul failed for one scalar");

        // Test with random scalars
        for _ in 0..10 {
            let scalar = Scalar::rand(&mut rng);
            let result = gen_mul(&scalar);
            let expected = g * scalar;
            assert_eq!(result, expected, "gen_mul failed for random scalar");
        }
    }

    #[test]
    fn test_gen_batch_mul_correctness() {
        let mut rng = OsRng;
        let g = Point::generator();

        // Test with empty batch
        let scalars: Vec<Scalar> = vec![];
        let results = gen_batch_mul(&scalars);
        assert_eq!(results.len(), 0, "batch mul should handle empty input");

        // Test with single scalar
        let scalar = Scalar::rand(&mut rng);
        let results = gen_batch_mul(&[scalar]);
        let expected = g * scalar;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], expected, "batch mul failed for single scalar");

        // Test with multiple random scalars
        let scalars: Vec<Scalar> = (0..20).map(|_| Scalar::rand(&mut rng)).collect();
        let results = gen_batch_mul(&scalars);
        assert_eq!(results.len(), scalars.len());

        for (i, scalar) in scalars.iter().enumerate() {
            let expected = g * scalar;
            assert_eq!(results[i], expected, "batch mul failed at index {}", i);
        }
    }

    #[test]
    fn test_gen_batch_mul_matches_gen_mul() {
        let mut rng = OsRng;

        // Generate random scalars
        let scalars: Vec<Scalar> = (0..15).map(|_| Scalar::rand(&mut rng)).collect();

        // Compute using batch version
        let batch_results = gen_batch_mul(&scalars);

        // Compute using single version
        let single_results: Vec<Point> = scalars.iter().map(gen_mul).collect();

        // They should match
        assert_eq!(batch_results.len(), single_results.len());
        for (i, (batch_result, single_result)) in
            batch_results.iter().zip(single_results.iter()).enumerate()
        {
            assert_eq!(batch_result, single_result, "mismatch at index {}", i);
        }
    }
}

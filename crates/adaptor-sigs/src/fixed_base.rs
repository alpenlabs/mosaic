//! Global fixed-base precomputation for secp256k1's generator G.

use ark_ec::{PrimeGroup, scalar_mul::BatchMulPreprocessing};
use ark_secp256k1::{Fr as Scalar, Projective as Point};
use mosaic_common::constants::{N_INPUT_WIRES, N_OPEN_CIRCUITS};
use once_cell::sync::Lazy;

const N_COEFFICIENTS: usize = N_OPEN_CIRCUITS + 1;
const APPROX_MULS: usize = N_INPUT_WIRES * N_COEFFICIENTS * 256;

/// Single global precomputation for G.
static PRECOMP_G: Lazy<BatchMulPreprocessing<Point>> =
    Lazy::new(|| BatchMulPreprocessing::new(Point::generator(), APPROX_MULS));

/// Accessor for the global precomputation.
#[inline]
fn precomp() -> &'static BatchMulPreprocessing<Point> {
    &PRECOMP_G
}

/// Single scalar version.
#[inline]
pub(crate) fn gen_mul(scalar: &Scalar) -> Point {
    precomp().batch_mul(&[*scalar])[0].into()
}

/// Batch version.
#[cfg(test)]
#[inline]
pub(crate) fn gen_batch_mul(scalars: &[Scalar]) -> Vec<Point> {
    precomp()
        .batch_mul(scalars)
        .into_iter()
        .map(|p| p.into())
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_ff::{One, UniformRand, Zero};
    use ark_secp256k1::{Fr as Scalar, Projective as Point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn precomp_is_singleton() {
        let p1 = super::precomp() as *const _;
        let p2 = super::precomp() as *const _;
        assert_eq!(p1, p2, "precomp() must return the same address");
    }

    #[test]
    fn fixed_base_mul_zero_and_one() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        let g = Point::generator();

        let m0 = super::gen_mul(&zero);
        let m1 = super::gen_mul(&one);

        assert_eq!(m0, Point::zero(), "G·0 should be identity");
        assert_eq!(m1, g, "G·1 should be generator");
    }

    #[test]
    fn fixed_base_mul_matches_naive_scalar_mul_random() {
        // Deterministic RNG for reproducibility
        let mut rng = ChaCha20Rng::seed_from_u64(0xABCDEF01);

        for _ in 0..128 {
            let s = Scalar::rand(&mut rng);
            let got = super::gen_mul(&s);
            let exp = Point::generator() * s;
            assert_eq!(got, exp, "fixed_base_mul mismatch vs. naive mul");
        }
    }

    #[test]
    fn linearity_property() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xABCDEF01);

        for _ in 0..64 {
            let a = Scalar::rand(&mut rng);
            let b = Scalar::rand(&mut rng);

            let ga = super::gen_mul(&a);
            let gb = super::gen_mul(&b);
            let g_a_plus_b = super::gen_mul(&(a + b));

            // G·a + G·b == G·(a+b)
            assert_eq!(ga + gb, g_a_plus_b);
        }
    }

    #[test]
    fn determinism_across_calls() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for _ in 0..50 {
            let s = Scalar::rand(&mut rng);
            let a = super::gen_mul(&s);
            let b = super::gen_mul(&s);
            assert_eq!(a, b, "same scalar must yield identical point");
        }
    }

    #[test]
    fn batch_mul_matches_point_mul_vector_and_single() {
        let mut rng = ChaCha20Rng::seed_from_u64(2024);
        // include some edge scalars explicitly
        let mut scalars: Vec<Scalar> = vec![Scalar::zero(), Scalar::one()];
        scalars.extend((0..64).map(|_| Scalar::rand(&mut rng)));

        let batch = super::gen_batch_mul(&scalars);

        assert_eq!(batch.len(), scalars.len());
        for (i, s) in scalars.iter().enumerate() {
            let got_batch = batch[i];
            let got_single = super::gen_mul(s);
            let exp = Point::generator() * *s;

            assert_eq!(got_batch, got_single, "batch != single at index {i}");
            assert_eq!(got_batch, exp, "batch result != naive mul at index {i}");
        }
    }

    #[test]
    fn batch_mul_empty_input() {
        let scalars: Vec<Scalar> = vec![];
        let out = super::gen_batch_mul(&scalars);
        assert!(out.is_empty());
    }
}

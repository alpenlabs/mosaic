//! Interpolation of polynomials for the VS3 protocol.

use ark_ff::{Field, One, Zero};
use ark_secp256k1::Fr as Scalar;

use crate::constants::{N_CIRCUITS, N_COEFFICIENTS};
use crate::error::Error;
use crate::polynomial::{Index, Share};

/// Interpolate missing shares from known shares using Lagrange interpolation.
///
/// Given exactly `N_COEFFICIENTS` known shares (which must include the reserved index 0),
/// this function computes all missing shares from the remaining indices in `[0, N_CIRCUITS)`.
///
/// # Arguments
/// * `known_shares` - Known shares, must be exactly `N_COEFFICIENTS` and include reserved index
///
/// # Returns
/// Vector of missing shares interpolated from the known shares
///
/// # Errors
/// Returns an error if:
/// - The number of known shares is not exactly `N_COEFFICIENTS`
/// - The reserved index (0) is not present in the known shares
pub fn interpolate(known_shares: &[Share]) -> Result<Vec<Share>, Error> {
    // Check that we have exactly N_COEFFICIENTS known shares
    if known_shares.len() != N_COEFFICIENTS {
        return Err(Error::InvalidShareCount {
            expected: N_COEFFICIENTS,
            actual: known_shares.len(),
        });
    }

    // Check that the reserved index (0) is present
    let has_reserved = known_shares
        .iter()
        .any(|share| share.index() == Index::reserved());
    if !has_reserved {
        return Err(Error::MissingReservedIndex);
    }

    // Convert known shares to (usize, Scalar) format
    let known_points: Vec<(usize, Scalar)> = known_shares
        .iter()
        .map(|share| (share.index().get(), share.value()))
        .collect();

    // Determine missing indices: all indices in [0, N_CIRCUITS) not in known_shares
    let known_indices: std::collections::HashSet<usize> = known_shares
        .iter()
        .map(|share| share.index().get())
        .collect();

    let missing_indices: Vec<usize> = (0..N_CIRCUITS)
        .filter(|i| !known_indices.contains(i))
        .collect();

    // Interpolate missing scalar values
    let missing_values = lagrange_interpolate_whole_polynomial(&known_points, &missing_indices);

    // Convert back to Share format
    let missing_shares: Vec<Share> = missing_indices
        .iter()
        .zip(missing_values.iter())
        .map(|(idx, value)| {
            let index = if *idx == 0 {
                Index::reserved()
            } else {
                Index::new(*idx).expect("index in bounds")
            };
            Share::new(index, *value)
        })
        .collect();

    Ok(missing_shares)
}

/// Precompute factorials, inverse factorials, and modular inverses up to `n`.
fn precalculated_factorials_and_inverses(n: usize) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
    let factorial: Vec<Scalar> = std::iter::once(Scalar::one())
        .chain((1..n).scan(Scalar::one(), |state, i| {
            *state *= Scalar::from(i as u64);
            Some(*state)
        }))
        .collect();

    // inv_fact[i] = 1 / factorial[i]
    let inv_factorial: Vec<Scalar> = (0..n)
        .rev()
        .scan(
            factorial[n - 1]
                .inverse()
                .expect("factorial[n-1] must be invertible"),
            |cur_state, i| {
                let ith_value = *cur_state;
                *cur_state *= Scalar::from(i as u64);
                Some(ith_value)
            },
        )
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    // inv[i] = 1 / i
    let inv: Vec<Scalar> = (0..n)
        .map(|i| {
            if i == 0 {
                Scalar::zero() // unused sentinel
            } else {
                inv_factorial[i] * factorial[i - 1]
            }
        })
        .collect();

    (factorial, inv_factorial, inv)
}

/// Optimized interpolation for missing points in a degree-k polynomial
/// defined by known_points. Assumes known + missing = {0,...,n-1}.
fn lagrange_interpolate_whole_polynomial(
    known_points: &[(usize, Scalar)],
    missing_points: &[usize],
) -> Vec<Scalar> {
    let n = known_points.len() + missing_points.len();
    let (factorial, inv_factorial, inv) = precalculated_factorials_and_inverses(n);

    // Computes coefficient depending on whether we want inverse (for known points)
    let get_coeff = |x: usize, is_inverse: bool| {
        let mut result = if is_inverse {
            inv_factorial[x] * inv_factorial[n - 1 - x]
        } else {
            factorial[x] * factorial[n - 1 - x]
        };

        if (n - x) % 2 == 1 {
            // adjust sign
            result *= -Scalar::one();
        }

        for i in missing_points {
            if *i == x {
                continue;
            }
            result *= if is_inverse {
                Scalar::from(x as i64 - *i as i64)
            } else if *i < x {
                inv[x - i]
            } else {
                -inv[i - x]
            }
        }
        result
    };

    // Precompute coeffs for known points
    let lagrange_coeffs: Vec<(usize, Scalar)> = known_points
        .iter()
        .map(|(x, y)| (*x, get_coeff(*x, true) * y))
        .collect();

    // Evaluate polynomial at each missing point
    missing_points
        .iter()
        .map(|x| {
            let all_diffs = get_coeff(*x, false);
            lagrange_coeffs
                .iter()
                .fold(Scalar::zero(), |acc, (i, coeff_i)| {
                    let diff_inv = if i < x { inv[x - i] } else { -inv[i - x] };
                    acc + diff_inv * all_diffs * *coeff_i
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{N_CIRCUITS, N_COEFFICIENTS};
    use crate::polynomial::{Index, Polynomial, Share};
    use rand::rngs::OsRng;

    #[test]
    fn test_interpolate_missing_shares() {
        use rand::seq::SliceRandom;
        let mut rng = OsRng;

        // Generate a random polynomial
        let poly = Polynomial::rand(&mut rng);

        // Generate all shares (including reserved index 0)
        let all_shares: Vec<Share> = (0..N_CIRCUITS)
            .map(|idx| {
                let index = if idx == 0 {
                    Index::reserved()
                } else {
                    Index::new(idx).expect("index in bounds")
                };
                poly.eval(index)
            })
            .collect();

        // Randomly sample N_COEFFICIENTS indices, ensuring reserved index (0) is included
        let mut available_indices: Vec<usize> = (1..N_CIRCUITS).collect();
        available_indices.shuffle(&mut rng);

        let mut selected_indices = vec![0]; // Always include reserved index
        selected_indices.extend(&available_indices[0..N_COEFFICIENTS - 1]);

        let known_shares: Vec<Share> = selected_indices
            .iter()
            .map(|&idx| all_shares[idx].clone())
            .collect();

        // Interpolate missing shares
        let missing_shares = interpolate(&known_shares).expect("interpolation should succeed");

        // Verify we got the right number of missing shares
        assert_eq!(missing_shares.len(), N_CIRCUITS - N_COEFFICIENTS);

        // Verify all missing shares match the ground truth
        let known_indices: std::collections::HashSet<usize> =
            selected_indices.iter().copied().collect();

        for share in &missing_shares {
            let idx = share.index().get();
            assert!(
                !known_indices.contains(&idx),
                "missing share should not be in known shares"
            );
            assert_eq!(
                share.value(),
                all_shares[idx].value(),
                "mismatch at index {idx}"
            );
        }
    }

    #[test]
    fn test_interpolate_missing_shares_errors() {
        let mut rng = OsRng;
        let poly = Polynomial::rand(&mut rng);

        // Test error: wrong number of shares
        let too_few_shares: Vec<Share> = (0..N_COEFFICIENTS - 1)
            .map(|idx| {
                let index = if idx == 0 {
                    Index::reserved()
                } else {
                    Index::new(idx).expect("index in bounds")
                };
                poly.eval(index)
            })
            .collect();

        let result = interpolate(&too_few_shares);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidShareCount { .. }
        ));

        // Test error: missing reserved index
        let shares_without_reserved: Vec<Share> = (1..=N_COEFFICIENTS)
            .map(|idx| {
                let index = Index::new(idx).expect("index in bounds");
                poly.eval(index)
            })
            .collect();

        let result = interpolate(&shares_without_reserved);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::MissingReservedIndex));
    }
}

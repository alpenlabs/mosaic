//! Specification of the number of coefficients and evaluation domain size is informed by mosaic
use mosaic_common::constants::{N_CIRCUITS, N_OPEN_CIRCUITS};

/// Number of Coefficients of Polynomial
pub(crate) const N_COEFFICIENTS: usize = N_OPEN_CIRCUITS + 1;

/// Upper Bound of Evaluation domain [0, N_DOMAIN_UPPER_BOUND] i.e. 0..=N_DOMAIN_UPPER_BOUND
pub(crate) const N_DOMAIN_UPPER_BOUND: usize = N_CIRCUITS;

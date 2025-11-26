//! Verifiable secret sharing over the secp256k1 curve.

mod constants;
mod error;
mod interpolate;
mod polynomial;
mod psm;

// Re-export all constants
pub use constants::*;

// Re-export error types
pub use error::Error;

// Re-export interpolation function
pub use interpolate::interpolate;

// Re-export polynomial types
pub use polynomial::{Index, Polynomial, PolynomialCommitment, Share, ShareCommitment};

// Re-export point scalar multiplication functions
pub use psm::{gen_batch_mul, gen_mul, precomp};

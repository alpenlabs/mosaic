use ark_secp256k1::{Fr as Scalar, Projective as Point};

/// An adaptor pre-signature
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Adaptor {
    /// The tweaked scalar component.
    pub tweaked_s: Scalar,
    /// The tweaked point component.
    pub tweaked_r: Point,
    /// Commitment to the signer's share, used for verification.
    pub share_commitment: Point,
}

use ark_secp256k1::{Fr as Scalar, Projective as Point};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// An adaptor pre-signature (verifiably encrypted signature).
#[derive(Copy, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Adaptor {
    /// The tweaked scalar component.
    pub tweaked_s: Scalar,
    /// The tweaked point component.
    pub tweaked_r: Point,
    /// Commitment to the signer's share, used for verification.
    pub share_commitment: Point,
}

/// A completed signature
// TODO: replace this type after adaptor related changes are merged.
#[derive(Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    /// S
    pub s: Scalar,
    /// R
    pub r: Point,
}

//! Conversions between service domain types and RPC for cryptographic types.

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::Valid as _;
use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use mosaic_adaptor_sigs::{deserialize_field, serialize_field};
use mosaic_cac_types::{PubKey, Signature};

/// Converts an internal [`Signature`] to a bitcoin [`SchnorrSignature`].
pub(crate) fn into_schnorr_signature(sig: Signature) -> SchnorrSignature {
    SchnorrSignature::from_slice(&sig.to_bytes()).expect("64 bytes data")
}

/// Converts a bitcoin [`SchnorrSignature`] to an internal [`Signature`].
pub(crate) fn try_from_schnorr_signature(
    schnorr_sig: SchnorrSignature,
) -> Result<Signature, String> {
    Signature::from_bytes(schnorr_sig.serialize()).map_err(|e| e.to_string())
}

/// Converts an internal [`PubKey`] (an ark-ec projective curve point) to a bitcoin
/// [`XOnlyPublicKey`].
///
/// An x-only public key is a 32-byte encoding of just the x-coordinate of a secp256k1 curve
/// point, as defined in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
/// This drops the y-coordinate since it can be recovered (up to sign) from the curve equation
/// y² = x³ + 7, and BIP-340 implicitly chooses the even y.
pub(crate) fn try_into_x_only_pubkey(pubkey: PubKey) -> Result<XOnlyPublicKey, String> {
    // Convert from projective (X:Y:Z) to affine (x, y) coordinates so we can extract the
    // x-coordinate as a field element.
    let aff = pubkey.0.into_affine();

    // Serialize the x-coordinate field element to 32 big-endian bytes.
    let bytes = serialize_field(&aff.x);

    XOnlyPublicKey::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Converts a bitcoin [`XOnlyPublicKey`] to an internal [`PubKey`] (an ark-ec projective curve
/// point).
///
/// Since an x-only key only encodes the x-coordinate, we must recover y from the secp256k1 curve
/// equation y² = x³ + 7. This yields two solutions (y, -y); per BIP-340 we choose the even y
/// (i.e. the one whose least-significant bit is 0).
pub(crate) fn try_from_x_only_pubkey(x_pk: XOnlyPublicKey) -> Result<PubKey, String> {
    let bytes = x_pk.serialize();

    // Deserialize the 32 big-endian bytes back into a base field element (Fq for secp256k1).
    let x: ark_secp256k1::Fq = deserialize_field(&bytes).map_err(|e| e.to_string())?;

    // Solve y² = x³ + 7 for y. Returns both square roots (y, -y).
    let (y, neg_y) = ark_secp256k1::Affine::get_ys_from_x_unchecked(x)
        .ok_or_else(|| format!("no valid y-coordinate for x = {x}"))?;

    // BIP-340 convention: choose the even y-coordinate (least-significant bit == 0).
    let y = if y.into_bigint().is_even() { y } else { neg_y };

    // Construct the affine point without checking it lies on the curve (we derived y from x,
    // so it does), then validate with an explicit check.
    let aff = ark_secp256k1::Affine::new_unchecked(x, y);

    // Verify the point is on the curve and in the correct subgroup.
    aff.check().map_err(|e| e.to_string())?;

    Ok(PubKey(aff.into()))
}

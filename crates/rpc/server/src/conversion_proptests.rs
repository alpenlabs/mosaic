//! Property-based tests for conversions between internal and bitcoin crypto types.

use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use mosaic_adaptor_sigs::serialize_field;
use mosaic_cac_types::{Adaptor, PubKey, Signature};
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secp256k1::SECP256K1;
use sha2::{Digest, Sha256};

use crate::conversions::{
    into_schnorr_signature, try_from_schnorr_signature, try_from_x_only_pubkey,
    try_into_x_only_pubkey,
};

/// Generate an even-y internal keypair from a seed.
fn internal_keypair_from_seed(seed: u64) -> (ark_secp256k1::Fr, ark_secp256k1::Projective) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    Signature::keypair(&mut rng)
}

/// Generate a bitcoin keypair from a seed.
fn bitcoin_keypair_from_seed(seed: u64) -> secp256k1::Keypair {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    secp256k1::Keypair::new(SECP256K1, &mut rng)
}

/// Generate an adaptor-completed internal signature from a seed.
fn internal_signature_from_seed(seed: u64) -> Signature {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (eval_sk, eval_pk) = Signature::keypair(&mut rng);
    let garbler_share = ark_secp256k1::Fr::rand(&mut rng);
    let garbler_commit = ark_secp256k1::Projective::generator() * garbler_share;
    let sighash = Sha256::digest(b"proptest-sig").to_vec();

    let adaptor = Adaptor::generate(&mut rng, garbler_commit, eval_sk, eval_pk, &sighash)
        .expect("adaptor generation should succeed");
    adaptor.complete(garbler_share)
}

/// Generate a bitcoin schnorr signature from a seed.
fn bitcoin_signature_from_seed(seed: u64) -> (secp256k1::schnorr::Signature, secp256k1::Keypair) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let keypair = secp256k1::Keypair::new(SECP256K1, &mut rng);
    // Use the seed bytes as part of the message for variety
    let msg = secp256k1::Message::from_digest(Sha256::digest(seed.to_le_bytes()).into());
    let sig = keypair.sign_schnorr(msg);
    (sig, keypair)
}

// ── Round-trip: pubkey ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn internal_pubkey_to_bitcoin_roundtrip(seed in any::<u64>()) {
        let (_sk, pk_proj) = internal_keypair_from_seed(seed);
        let pubkey = PubKey(pk_proj);
        prop_assert!(pubkey.valid(), "keypair should produce valid (even-y) pubkey");

        let original_bytes = pubkey.to_x_only_bytes();

        // Internal -> Bitcoin -> Internal
        let x_only = try_into_x_only_pubkey(pubkey).expect("conversion should succeed");
        prop_assert_eq!(x_only.serialize(), original_bytes);

        let recovered = try_from_x_only_pubkey(x_only).expect("conversion back should succeed");
        prop_assert!(recovered.valid());
        prop_assert_eq!(recovered.to_x_only_bytes(), original_bytes);
    }

    #[test]
    fn bitcoin_pubkey_to_internal_roundtrip(seed in any::<u64>()) {
        let keypair = bitcoin_keypair_from_seed(seed);
        let (x_only, _parity) = keypair.x_only_public_key();
        let original_bytes = x_only.serialize();

        // Bitcoin -> Internal -> Bitcoin
        let pubkey = try_from_x_only_pubkey(x_only).expect("conversion should succeed");
        prop_assert!(pubkey.valid());
        prop_assert_eq!(pubkey.to_x_only_bytes(), original_bytes);

        let recovered = try_into_x_only_pubkey(pubkey).expect("conversion back should succeed");
        prop_assert_eq!(recovered.serialize(), original_bytes);
    }
}

// ── Round-trip: signature ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn internal_signature_to_bitcoin_roundtrip(seed in any::<u64>()) {
        let sig = internal_signature_from_seed(seed);
        let original_bytes = sig.to_bytes();

        // Internal -> Bitcoin -> Internal
        let schnorr_sig = into_schnorr_signature(sig);
        prop_assert_eq!(schnorr_sig.serialize(), original_bytes);

        let recovered =
            try_from_schnorr_signature(schnorr_sig).expect("conversion back should succeed");
        prop_assert_eq!(recovered.to_bytes(), original_bytes);
        prop_assert_eq!(recovered, sig);
    }

    #[test]
    fn bitcoin_signature_to_internal_roundtrip(seed in any::<u64>()) {
        let (schnorr_sig, _keypair) = bitcoin_signature_from_seed(seed);
        let original_bytes = schnorr_sig.serialize();

        // Bitcoin -> Internal -> Bitcoin
        let internal_sig =
            try_from_schnorr_signature(schnorr_sig).expect("conversion should succeed");
        prop_assert_eq!(internal_sig.to_bytes(), original_bytes);

        let recovered = into_schnorr_signature(internal_sig);
        prop_assert_eq!(recovered.serialize(), original_bytes);
    }
}

// ── Cross-verification ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn cross_verify_internal_to_bitcoin(seed in any::<u64>()) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (eval_sk, eval_pk) = Signature::keypair(&mut rng);
        let garbler_share = ark_secp256k1::Fr::rand(&mut rng);
        let garbler_commit = ark_secp256k1::Projective::generator() * garbler_share;

        let sighash_bytes: [u8; 32] = Sha256::digest(seed.to_le_bytes()).into();

        let adaptor =
            Adaptor::generate(&mut rng, garbler_commit, eval_sk, eval_pk, &sighash_bytes)
                .expect("adaptor generation should succeed");
        let sig = adaptor.complete(garbler_share);

        // Convert to bitcoin types and verify
        let schnorr_sig = into_schnorr_signature(sig);
        let pubkey = PubKey(eval_pk);
        let x_only_pk =
            try_into_x_only_pubkey(pubkey).expect("pubkey conversion should succeed");

        let msg = secp256k1::Message::from_digest(sighash_bytes);
        SECP256K1
            .verify_schnorr(&schnorr_sig, &msg, &x_only_pk)
            .expect("internally generated signature should verify with bitcoin/secp256k1");
    }

    #[test]
    fn cross_verify_bitcoin_to_internal(seed in any::<u64>()) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let keypair = secp256k1::Keypair::new(SECP256K1, &mut rng);
        let (x_only_pk, _parity) = keypair.x_only_public_key();
        let msg_bytes: [u8; 32] = Sha256::digest(seed.to_le_bytes()).into();
        let msg = secp256k1::Message::from_digest(msg_bytes);
        let schnorr_sig = keypair.sign_schnorr(msg);

        // Convert to internal types
        let internal_sig =
            try_from_schnorr_signature(schnorr_sig).expect("sig conversion should succeed");
        let internal_pk =
            try_from_x_only_pubkey(x_only_pk).expect("pubkey conversion should succeed");

        // Manual BIP340 verification: s*G == R + e*P

        // Reconstruct R from sig.r (x-coordinate, pick even y)
        let (y, neg_y) = ark_secp256k1::Affine::get_ys_from_x_unchecked(internal_sig.r)
            .expect("valid x coordinate on curve");
        let r_y = if y.into_bigint().is_even() { y } else { neg_y };
        let r_point = ark_secp256k1::Affine::new_unchecked(internal_sig.r, r_y);

        // Compute challenge: e = H(BIP0340/challenge, R.x, P.x, msg)
        let tag_hash = Sha256::digest(b"BIP0340/challenge");
        let mut h = Sha256::new();
        h.update(tag_hash);
        h.update(tag_hash);
        h.update(serialize_field::<ark_secp256k1::Fq>(&internal_sig.r));
        h.update(internal_pk.to_x_only_bytes());
        h.update(msg_bytes);
        let e_bytes = h.finalize();
        let e = ark_secp256k1::Fr::from_be_bytes_mod_order(&e_bytes);

        // Verify: s*G == R + e*P
        let s_g = ark_secp256k1::Projective::generator() * internal_sig.s;
        let r_plus_ep = ark_secp256k1::Projective::from(r_point) + internal_pk.0 * e;
        prop_assert_eq!(
            s_g, r_plus_ep,
            "BIP340 verification equation should hold for bitcoin-generated signature"
        );
    }
}

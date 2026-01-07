#![allow(non_snake_case)]
//! Adaptor for the VSSS
//!
//! This module implements an adaptor-based disclosure of per-wire VSSS shares (does not support
//! wide labels yet):
//! - `Adaptor::generate` constructs (s', R', S) where R' = r'G, R = R' + S, e = H(tag, R.x, P.x,
//!   wire_index, sighash),  s' = r' + e·x.
//! - `Adaptor::verify`   checks s'·G == R' + e·P.
//! - `Adaptor::complete` produces a Schnorr-like (s, R) by s = s' + share, R = R' + S.
//! - `Adaptor::extract_share` recovers `share` from (s, R) and the adaptor as s − s'.
//
// Notes:
// - We keep `challenge_e` as a private helper to mirror BIP340 tagging.
// - `extract_share` is intentionally a pure algebraic operation and does not verify `R`. Callers
//   who want that check should compare `sig.R` to `adaptor.expected_R()`.

use std::str::FromStr;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::Valid;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use crate::{error::Error, fixed_base::gen_mul};
/* ------------------------------ Utilities --------------------------------- */

fn serialize_field<F: PrimeField>(x: &F) -> [u8; 32] {
    // `Fq` modulus is 256 bits, so its big-endian encoding always fits in 32 bytes.
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fq encodes to exactly 32 bytes")
}

fn deserialize_field<F: PrimeField>(bytes: [u8; 32]) -> Result<F, Error> {
    fn bytes_be_to_bits_be(bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for &b in bytes {
            for i in (0..8).rev() {
                bits.push(((b >> i) & 1) == 1);
            }
        }
        bits
    }
    let rint = F::BigInt::from_bits_be(&bytes_be_to_bits_be(&bytes));
    if rint > F::MODULUS {
        return Err(Error::Deserialization("integer greater than field modulus"));
    }
    F::from_bigint(rint).ok_or(Error::Deserialization(
        "conversion from bigint to field element",
    ))
}

/* --------------------------------- Types ---------------------------------- */

/// Adaptor for the VSSS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adaptor {
    /// s' = r' + e * x  (the evaluator’s partial Schnorr s)
    pub tweaked_s: ark_secp256k1::Fr,
    /// R' = r'*G
    pub tweaked_R: ark_secp256k1::Projective,
    /// S = share*G
    pub share_commitment: ark_secp256k1::Projective,
}

/// Signature for the VSSS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// s = s' + share
    pub s: ark_secp256k1::Fr,
    /// R = R' + S
    pub R: ark_secp256k1::Projective,
}

impl Signature {
    /// Signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let rx = self.R.into_affine().x;
        let r_x = serialize_field(&rx);
        let s_bytes = serialize_field(&self.s);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r_x);
        out[32..].copy_from_slice(&s_bytes);
        out
    }

    /// Signature from bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, Error> {
        let rx: ark_secp256k1::Fq = deserialize_field(bytes[0..32].try_into().unwrap())?;
        if rx == ark_secp256k1::Fq::ZERO {
            return Err(Error::Deserialization("signature.r can not be zero"));
        }
        let s: ark_secp256k1::Fr = deserialize_field(bytes[32..].try_into().unwrap())?;
        if s == ark_secp256k1::Fr::ZERO {
            return Err(Error::Deserialization("signature.s can not be zero"));
        }
        let ry = {
            let coeff_b = ark_secp256k1::Fq::from_str("7").unwrap();
            let x3b = rx.square() * rx + coeff_b;
            let mut y = x3b
                .sqrt()
                .ok_or(Error::DeserializationErrorInPointOnCurve)?;
            if y.into_bigint().is_odd() {
                y.neg_in_place();
            }
            y
        };
        let R = ark_secp256k1::Affine::new_unchecked(rx, ry);
        if R.check().is_err() {
            return Err(Error::Deserialization("ark_secp256k1::Affine::check fails"));
        }
        Ok(Signature { s, R: R.into() })
    }
}

/* ----------------------------- Challenge helper --------------------------- */

/// e = H(BIP0340/challenge, R.x, P.x, wire_index, sighash)
fn challenge_e(Rx: &[u8], Px: &[u8], sighash: &[u8]) -> ark_secp256k1::Fr {
    // BIP340 tag
    let tag_hash = Sha256::digest(b"BIP0340/challenge");
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(Rx);
    h.update(Px);
    h.update(sighash);
    let digest = h.finalize();
    ark_secp256k1::Fr::from_be_bytes_mod_order(&digest)
}

/* --------------------------------- Methods -------------------------------- */

impl Adaptor {
    /// Generates an adaptor from the evaluator’s master secret key `x`, a commitment
    /// to the garbler’s share (`S = share·G`), and the `(wire_index, sighash)` transcript data.
    /// Purely algebraic operation that can't fail.
    pub fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        share_commitment: ark_secp256k1::Projective,
        evaluator_master_sk: ark_secp256k1::Fr,
        evaluator_master_pk: ark_secp256k1::Projective,
        sighash: &[u8],
    ) -> Self {
        assert_ne!(evaluator_master_sk, ark_secp256k1::Fr::ZERO);
        // r', R' = r'·G
        let mut tweaked_r = ark_secp256k1::Fr::rand(rng);
        assert_ne!(tweaked_r, ark_secp256k1::Fr::ZERO);
        let tweaked_R = gen_mul(&tweaked_r);

        // R = R' + S
        let R = tweaked_R + share_commitment;

        // P = x·G
        let P = evaluator_master_pk.into_affine();
        let Px = serialize_field(&P.x);

        let R_aff = R.into_affine();
        let Rx = serialize_field(&R_aff.x);

        let e = challenge_e(&Rx, &Px, sighash);

        // s' = ±r' + e·x
        if R_aff.y.into_bigint().is_odd() {
            tweaked_r.neg_in_place();
        }
        let tweaked_s = tweaked_r + e * evaluator_master_sk;

        Adaptor {
            tweaked_s,
            tweaked_R,
            share_commitment,
        }
    }

    /// Expected R value for this adaptor, i.e. `R' + S`.
    fn expected_R(&self) -> ark_secp256k1::Projective {
        self.tweaked_R + self.share_commitment
    }

    /// Verifies that this adaptor is well-formed for `(P, wire_index, sighash)`:
    /// checks `s'·G == R' + e·P`, where `e = H(tag, (R'+S).x, P.x, wire_index, sighash)`.
    pub fn verify(
        &self,
        evaluator_master_pk: ark_secp256k1::Projective,
        sighash: &[u8],
    ) -> Result<(), Error> {
        let R = self.expected_R();
        let R_aff = R.into_affine();
        let Rx = serialize_field(&R_aff.x);

        let P_aff = evaluator_master_pk.into_affine();
        let Px = serialize_field(&P_aff.x);

        let e = challenge_e(&Rx, &Px, sighash);

        // LHS: s'·G
        let lhs = gen_mul(&self.tweaked_s);
        // RHS: R' + e·P
        let tweaked_R = if R_aff.y.into_bigint().is_odd() {
            let neg_one = -ark_secp256k1::Fr::ONE;
            self.tweaked_R.mul_bigint(neg_one.into_bigint())
        } else {
            self.tweaked_R
        };
        let rhs = tweaked_R + evaluator_master_pk * e;

        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::VerificationFailed {
                what: "adaptor relation s'·G != R' + e·P",
            })
        }
    }

    /// Completes the adaptor with the garbler’s ark_secp256k1::Fr share to produce a `(s, R)` pair.
    /// Purely algebraic operation that can't fail.
    pub fn complete(&self, share: ark_secp256k1::Fr) -> Signature {
        let R = self.expected_R();
        let ry = R.into_affine().y;
        let (R, s) = if ry.into_bigint().is_odd() {
            (-R, self.tweaked_s - share)
        } else {
            (R, self.tweaked_s + share)
        };
        Signature { s, R }
    }

    /// Recovers the share from `(s, R)` and this adaptor as `s − s'`.
    /// Purely algebraic operation that can't fail.
    ///
    /// Note: This method does **not** check that `R == self.expected_R()`. Callers who require
    /// that binding must check `sig.R == adaptor.expected_R()` themselves before extraction.
    pub fn extract_share(&self, signature: &Signature) -> ark_secp256k1::Fr {
        let is_odd = self.expected_R().into_affine().y.into_bigint().is_odd();
        let diff = signature.s - self.tweaked_s;
        if is_odd { -diff } else { diff }
    }
}

/* ---------------------------------- Tests ---------------------------------- */
#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_ff::{UniformRand, Zero};
    use bitcoin::{
        Address, Amount, Network, Script, ScriptBuf, TapLeafHash, TapSighashType, Transaction,
        TxIn, TxOut, Witness, XOnlyPublicKey,
        absolute::LockTime,
        hashes::Hash,
        key::UntweakedPublicKey,
        sighash::{Prevouts, ScriptPath, SighashCache},
        taproot::{LeafVersion, TAPROOT_ANNEX_PREFIX, TaprootBuilder, TaprootSpendInfo},
        transaction::Version,
    };
    use bitcoin_script::script;
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
    use k256::{
        elliptic_curve::point::AffineCoordinates,
        schnorr::{Signature as KSig, SigningKey, VerifyingKey},
    };
    use rand::{RngCore, SeedableRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    use super::*;

    /// Build a consistent fixture for many tests.
    #[allow(dead_code)]
    struct Fix {
        share: ark_secp256k1::Fr,
        S: ark_secp256k1::Projective,
        x: ark_secp256k1::Fr,
        P: ark_secp256k1::Projective,
        wire_index: usize,
        sighash: Vec<u8>,
        adaptor: Adaptor,
    }

    fn fixture<R: CryptoRng + RngCore>(rng: &mut R) -> Fix {
        // Garbler’s ark_secp256k1::Fr share and commitment
        let share = ark_secp256k1::Fr::rand(rng);
        let S = gen_mul(&share);

        // Evaluator’s master secret/public
        let x = ark_secp256k1::Fr::rand(rng);
        let P = gen_mul(&x);

        // Transcript
        let wire_index = 7usize;
        let sighash = Sha256::digest(b"demo message").to_vec();

        // Generate adaptor
        let adaptor = Adaptor::generate(rng, S, x, P, &sighash);

        Fix {
            share,
            S,
            x,
            P,
            wire_index,
            sighash,
            adaptor,
        }
    }

    #[test]
    fn generate_verify_complete_extract_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        for _ in 0..10 {
            let fx = fixture(&mut rng);

            // Verify adaptor
            fx.adaptor.verify(fx.P, &fx.sighash).unwrap();

            // Complete with the garbler’s share and check R binding
            let sig = fx.adaptor.complete(fx.share);
            let expected_r = fx.adaptor.expected_R();
            let is_odd = expected_r.into_affine().y.into_bigint().is_odd();
            if is_odd {
                assert_eq!(-sig.R, expected_r);
            } else {
                assert_eq!(sig.R, expected_r);
            }
            // Extract share back
            let extracted = fx.adaptor.extract_share(&sig);
            assert_eq!(extracted, fx.share);
        }
    }

    #[test]
    fn signature_s_is_tweaked_s_plus_share() {
        let mut rng = thread_rng();
        let fx = fixture(&mut rng);
        let sig = fx.adaptor.complete(fx.share);
        let is_odd = fx
            .adaptor
            .expected_R()
            .into_affine()
            .y
            .into_bigint()
            .is_odd();
        if is_odd {
            assert_eq!(sig.s, fx.adaptor.tweaked_s - fx.share);
        } else {
            assert_eq!(sig.s, fx.adaptor.tweaked_s + fx.share);
        }
    }

    #[test]
    fn test_serialize_and_deserialize_signature() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let fx = fixture(&mut rng);
            let sig = fx.adaptor.complete(fx.share);
            let sig_bytes = sig.to_bytes();
            let sig2 = Signature::from_bytes(sig_bytes).expect("expected valid signature");
            assert_eq!(sig, sig2);
        }
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let mut rng = thread_rng();
        let fx = fixture(&mut rng);
        // Wrong key
        let x_wrong = ark_secp256k1::Fr::rand(&mut thread_rng());
        let P_wrong = gen_mul(&x_wrong);

        assert!(fx.adaptor.verify(P_wrong, &fx.sighash).is_err());
        // Correct key passes
        fx.adaptor.verify(fx.P, &fx.sighash).unwrap();
    }

    #[test]
    fn verify_fails_with_wrong_sighash_or_wire_index() {
        let mut rng = thread_rng();
        let fx = fixture(&mut rng);
        // Wrong sighash
        let bad_sighash = Sha256::digest(b"other message").to_vec();
        assert!(fx.adaptor.verify(fx.P, &bad_sighash).is_err());

        // Correct tuple passes
        fx.adaptor.verify(fx.P, &fx.sighash).unwrap();
    }

    #[test]
    fn verify_fails_if_tweaked_r_is_tampered() {
        let mut rng = thread_rng();
        let mut fx = fixture(&mut rng);
        // Tamper tweaked_R (equivalent to changing r')
        fx.adaptor.tweaked_R += ark_secp256k1::Projective::generator(); // any non-identity tweak should break relation
        assert!(fx.adaptor.verify(fx.P, &fx.sighash).is_err());
    }

    #[test]
    fn verify_fails_if_share_commitment_is_tampered() {
        let mut rng = thread_rng();
        let mut fx = fixture(&mut rng);
        fx.adaptor.share_commitment += ark_secp256k1::Projective::generator();
        assert!(fx.adaptor.verify(fx.P, &fx.sighash).is_err());
    }

    #[test]
    fn zero_share_commitment_behaves_like_plain_r_prime() {
        // share = 0 → S = 0 → R = R' + 0
        let mut rng = thread_rng();
        let share = ark_secp256k1::Fr::zero();
        let S = ark_secp256k1::Projective::zero();

        let x = ark_secp256k1::Fr::rand(&mut rng);
        let P = gen_mul(&x);

        let sighash = Sha256::digest(b"zero-share").to_vec();

        let mut rng = thread_rng();
        let ad = Adaptor::generate(&mut rng, S, x, P, &sighash);

        // Still should verify
        ad.verify(P, &sighash).unwrap();

        // Complete and extract should be no-ops on share part
        let sig = ad.complete(share);
        let recovered = ad.extract_share(&sig);
        assert_eq!(recovered, ark_secp256k1::Fr::zero());
    }

    #[test]
    fn verify_equation_matches_definition() {
        // Cross-check: s'·G == R' + e·P with e computed from (R'+S).x, P.x, wire_index, sighash.
        let mut rng = thread_rng();
        let fx = fixture(&mut rng);

        // Recompute e like verify() does
        let R = fx.adaptor.expected_R().into_affine();
        let P = fx.P.into_affine();
        let e = super::challenge_e(&serialize_field(&R.x), &serialize_field(&P.x), &fx.sighash);

        let lhs = gen_mul(&fx.adaptor.tweaked_s); // s'·G
        let tweaked_R = if R.y.into_bigint().is_odd() {
            let neg_one = -ark_secp256k1::Fr::ONE;
            fx.adaptor.tweaked_R.mul_bigint(neg_one.into_bigint())
        } else {
            fx.adaptor.tweaked_R
        };
        let rhs = tweaked_R + fx.P * e; // R' + e·P
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn generate_is_randomized_even_with_same_inputs() {
        // With a fixed seed RNG, `generate` is deterministic; with thread_rng, subsequent
        // calls should produce different adaptors in practice (r' differs).
        let mut rng = thread_rng();

        let share = ark_secp256k1::Fr::from(42u64);
        let S = gen_mul(&share);

        let x = ark_secp256k1::Fr::from(999u64);
        let P = gen_mul(&x);

        let sighash = Sha256::digest(b"entropy").to_vec();

        let ad1 = Adaptor::generate(&mut rng, S, x, P, &sighash);
        let ad2 = Adaptor::generate(&mut rng, S, x, P, &sighash);

        // With a single RNG stream, two sequential calls still produce different tweaked_r by
        // construction (two independent ark_secp256k1::Fr::rand draws)
        assert_ne!(ad1.tweaked_R, ad2.tweaked_R);
        assert_ne!(ad1.tweaked_s, ad2.tweaked_s);

        // Both should verify with the same transcript and key
        ad1.verify(P, &sighash).unwrap();
        ad2.verify(P, &sighash).unwrap();
    }

    #[test]
    fn fq_to_be32_padded_has_expected_shape() {
        // Quick sanity on padding: roundtrip length and monotonicity with respect to big-endian
        // bytes
        let mut rng = thread_rng();
        let P = gen_mul(&ark_secp256k1::Fr::rand(&mut rng)).into_affine();
        let bytes = serialize_field(&P.x);
        assert_eq!(bytes.len(), 32);
        // Not all-zero except for the (extremely unlikely) zero x-coordinate case
        assert!(bytes.iter().any(|&b| b != 0) || P.x.is_zero());
    }

    #[test]
    fn test_compare_with_k256() {
        fn fr_from_sk(sk: &SigningKey) -> ark_secp256k1::Fr {
            let bytes = sk.to_bytes();
            ark_secp256k1::Fr::from_be_bytes_mod_order(bytes.as_slice())
        }
        let mut rng = ChaCha20Rng::seed_from_u64(20);
        for _ in 0..10 {
            let evaluator_privkey = SigningKey::random(&mut rng);
            let evaluator_secret_fr = fr_from_sk(&evaluator_privkey);
            let evaluator_master_pk = gen_mul(&evaluator_secret_fr);
            let garbler_secret_fr = ark_secp256k1::Fr::rand(&mut rng);
            let garbler_commit = ark_secp256k1::Projective::generator() * garbler_secret_fr;

            let sighash = Sha256::digest(b"some message").to_vec();
            let adaptor = Adaptor::generate(
                &mut rng,
                garbler_commit,
                evaluator_secret_fr,
                evaluator_master_pk,
                sighash.as_slice(),
            );

            let garbler_sig = adaptor.complete(garbler_secret_fr);
            let garbler_sig_bytes = garbler_sig.to_bytes();
            // Verify using k256 in test only
            let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
            let ksig = KSig::try_from(garbler_sig_bytes.as_slice()).expect("valid sig");
            verifying_key
                .verify_raw(sighash.as_slice(), &ksig)
                .expect("signature should be valid");

            let tmp_garbler_sig =
                Signature::from_bytes(garbler_sig_bytes).expect("expected valid signature");
            assert_eq!(tmp_garbler_sig, garbler_sig);
            let secret = adaptor.extract_share(&garbler_sig);
            assert_eq!(secret, garbler_secret_fr);
        }
    }

    pub(crate) fn unspendable_pubkey() -> UntweakedPublicKey {
        XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            .unwrap()
    }

    fn spend_info_from_script(script: ScriptBuf) -> TaprootSpendInfo {
        let secp = bitcoin::key::Secp256k1::new();

        TaprootBuilder::with_huffman_tree(vec![(1, script)])
            .unwrap()
            .finalize(&secp, unspendable_pubkey())
            .unwrap()
    }

    fn address_from_spend_info(spend_info: &TaprootSpendInfo, network: Network) -> Address {
        let secp = bitcoin::key::Secp256k1::new();
        Address::p2tr(
            &secp,
            spend_info.internal_key(),
            spend_info.merkle_root(),
            network,
        )
    }

    /// Dry-runs a specific taproot input
    fn dry_run_taproot_input(tx: &Transaction, input_index: usize, prevouts: &[TxOut]) -> bool {
        let script = tx.input[input_index]
            .witness
            .taproot_leaf_script()
            .unwrap()
            .script;
        let stack = {
            let witness_items = tx.input[input_index].witness.to_vec();
            let last = witness_items.last().unwrap();

            // From BIP341:
            // If there are at least two witness elements, and the first byte of
            // the last element is 0x50, this last element is called annex a
            // and is removed from the witness stack.
            let script_index =
                if witness_items.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    witness_items.len() - 3
                } else {
                    witness_items.len() - 2
                };

            witness_items[0..script_index].to_vec()
        };

        let leaf_hash = TapLeafHash::from_script(
            Script::from_bytes(script.as_bytes()),
            LeafVersion::TapScript,
        );

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx: tx.clone(),
                prevouts: prevouts.into(),
                input_idx: input_index,
                taproot_annex_scriptleaf: Some((leaf_hash, None)),
            },
            ScriptBuf::from_bytes(script.to_bytes()),
            stack,
        )
        .expect("error creating exec");

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        res.success
    }

    #[test]
    fn test_tx() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let evaluator_privkey = SigningKey::random(&mut rng);
            let evaluator_pubkey = evaluator_privkey.verifying_key().as_affine().x().to_vec();
            let evaluator_secret_fr = {
                let b = evaluator_privkey.to_bytes();
                ark_secp256k1::Fr::from_be_bytes_mod_order(b.as_slice())
            };
            let garbler_secret_fr = ark_secp256k1::Fr::rand(&mut rng);
            let garbler_commit = ark_secp256k1::Projective::generator() * garbler_secret_fr;

            let script = script! {
                { evaluator_pubkey }
                OP_CHECKSIG
            }
            .compile();

            let spend_info = spend_info_from_script(script.clone());
            let address = address_from_spend_info(&spend_info, Network::Testnet);
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn::default()],
                output: vec![TxOut {
                    value: Amount::from_sat(2000),
                    script_pubkey: address.script_pubkey(),
                }],
            };

            // Provide a concrete prevout matching the spend script to compute taproot sighash
            let prevouts = vec![TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: address.script_pubkey(),
            }];
            let mut sighash_cache = SighashCache::new(&tx);

            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    ScriptPath::with_defaults(script.as_script()),
                    TapSighashType::Default,
                )
                .unwrap();
            let sighash = sighash.to_byte_array();

            let adaptor = Adaptor::generate(
                &mut rng,
                garbler_commit,
                evaluator_secret_fr,
                gen_mul(&evaluator_secret_fr),
                &sighash,
            );

            let garbler_sig = adaptor.complete(garbler_secret_fr);
            let garbler_sig_bytes = garbler_sig.to_bytes();
            // Verify using k256 in test only
            let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
            let ksig = KSig::try_from(garbler_sig_bytes.as_slice()).expect("valid sig");
            verifying_key
                .verify_raw(sighash.as_slice(), &ksig)
                .expect("signature should be valid");

            let secret = adaptor.extract_share(&garbler_sig);
            assert_eq!(secret, garbler_secret_fr);

            let control_block = spend_info
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize();

            let witness: Witness =
                vec![garbler_sig_bytes.to_vec(), script.to_bytes(), control_block].into();

            tx.input[0].witness = witness;

            let success = dry_run_taproot_input(&tx, 0, &prevouts[..]);
            assert!(success);
        }
    }
}

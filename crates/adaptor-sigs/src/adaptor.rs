#![allow(non_snake_case)]
//! Adaptor for the VSSS
//!
//! This module implements an adaptor-based disclosure of per-wire VSSS shares (does not support
//! wide labels yet):
//! - `Adaptor::generate` constructs (s', R', S) where R' = r'G, R = R' + S, e = H(tag, R.x, P.x,
//!   sighash),  s' = r' + e·x.
//! - `Adaptor::verify`   checks s'·G == R' + e·P.
//! - `Adaptor::complete` produces a Schnorr-like (s, R) by s = s' + share, R = R' + S.
//! - `Adaptor::extract_share` recovers `share` from (s, R) and the adaptor as s − s'.
//
// Notes:
// - We keep `challenge_e` as a private helper to mirror BIP340 tagging.
// - `extract_share` is intentionally a pure algebraic operation and does not verify `R`. Callers
//   who want that check should compare `sig.R` to `adaptor.expected_R()`.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use crate::{error::Error, fixed_base::gen_mul};

/// Helpers to serialize and deserialize field as per BIP340
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
    F::from_bigint(rint).ok_or(Error::Deserialization(
        "conversion from bigint to field element",
    ))
}

/// Signature for the VSSS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// s = s' ± share
    pub s: ark_secp256k1::Fr,
    /// r = (R' + S).x
    pub r: ark_secp256k1::Fq,
}

impl Signature {
    /// Signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let r_x = serialize_field(&self.r);
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
        Ok(Signature { s, r: rx })
    }
}

/// Adaptor for the VSSS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adaptor {
    /// s' = ±r' + e * x  (the evaluator’s partial Schnorr s)
    pub tweaked_s: ark_secp256k1::Fr,
    /// R' = r'*G
    pub R_dash_commit: ark_secp256k1::Projective,
    /// S = share*G
    pub share_commitment: ark_secp256k1::Projective,
}

impl Adaptor {
    /// Generates an adaptor from the evaluator’s master secret key `x`, a commitment
    /// to the garbler’s share (`S = share·G`), and the `sighash`
    pub fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        share_commitment: ark_secp256k1::Projective,
        evaluator_master_sk: ark_secp256k1::Fr,
        evaluator_master_pk: ark_secp256k1::Projective,
        sighash: &[u8],
    ) -> Result<Self, Error> {
        if evaluator_master_sk == ark_secp256k1::Fr::ZERO {
            return Err(Error::AdaptorGenerationFailed(
                "input evaluator_master_sk can't be zero",
            ));
        }
        // P = x·G
        let evaluator_master_pk = evaluator_master_pk.into_affine();
        if evaluator_master_pk.is_zero() {
            return Err(Error::AdaptorGenerationFailed(
                "input evaluator_master_pk can't be inf",
            ));
        }
        if evaluator_master_pk.y.into_bigint().is_odd() {
            return Err(Error::AdaptorGenerationFailed(
                "input evaluator_master_pk can't have odd y",
            ));
        }

        // key consistency
        if gen_mul(&evaluator_master_sk) != evaluator_master_pk {
            return Err(Error::AdaptorGenerationFailed(
                "evaluator master keys fail consistency check",
            ));
        }

        // r', R' = r'·G
        let mut r_dash = ark_secp256k1::Fr::rand(rng);
        if r_dash == ark_secp256k1::Fr::ZERO {
            return Err(Error::AdaptorGenerationFailed(
                "sampled partial nonce can't be zero",
            ));
        }
        let R_dash_commit = gen_mul(&r_dash);

        // R = R' + S
        let expected_R = (R_dash_commit + share_commitment).into_affine();
        if expected_R.is_zero() {
            return Err(Error::AdaptorGenerationFailed(
                "evaluator can guess garbler's secret share",
            ));
        }

        let e = Self::challenge_e(expected_R, evaluator_master_pk, sighash);

        if expected_R.y.into_bigint().is_odd() {
            // negate to make commitment of completed nonce (i.e. r_dash + share) even
            r_dash.neg_in_place();
        }
        // s' = ±r' + e·x
        let tweaked_s = r_dash + e * evaluator_master_sk;

        Ok(Adaptor {
            tweaked_s,
            R_dash_commit,
            share_commitment,
        })
    }

    /// Expected R value for this adaptor, i.e. `R' + S`.
    fn expected_R(&self) -> ark_secp256k1::Projective {
        self.R_dash_commit + self.share_commitment
    }

    /// Verifies that this adaptor is well-formed for `(P, sighash)`:
    /// checks `s'·G - e.P == R'`, where `e = H(tag, (R'+S).x, P.x, sighash)`.
    pub fn verify(
        &self,
        evaluator_master_pk: ark_secp256k1::Projective,
        sighash: &[u8],
    ) -> Result<(), Error> {
        let expected_R = self.expected_R().into_affine();
        if expected_R.is_zero() {
            return Err(Error::AdaptorGenerationFailed(
                "evaluator can guess garbler's secret share",
            ));
        }
        let evaluator_master_pk_affine = evaluator_master_pk.into_affine();
        if evaluator_master_pk_affine.is_zero() {
            return Err(Error::AdaptorGenerationFailed(
                "input evaluator_master_pk can't be inf",
            ));
        }
        if evaluator_master_pk_affine.y.into_bigint().is_odd() {
            return Err(Error::AdaptorGenerationFailed(
                "input evaluator_master_pk can't have odd y",
            ));
        }

        let e = Self::challenge_e(expected_R, evaluator_master_pk_affine, sighash);

        // LHS: s'·G - e.P
        let lhs = gen_mul(&self.tweaked_s) - evaluator_master_pk * e;
        // RHS: R'
        let rhs = if expected_R.y.into_bigint().is_odd() {
            -self.R_dash_commit
        } else {
            self.R_dash_commit
        };

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
        let R = self.expected_R().into_affine();
        assert!(
            !R.is_zero(),
            "a verified adaptor can not have expected R to be zero"
        );
        let s = if R.y.into_bigint().is_odd() {
            self.tweaked_s - share
        } else {
            self.tweaked_s + share
        };
        // Note: bip-0340 suggests the signing method to validate the computed Signature before
        // returning it. If so, we need to implement signature validation here.
        // Also Note: signature validation differs from adaptor verification `verify()` method above
        // in that adaptor verify works over partial signature while signature verification works
        // over completed one. As such signature verify will mimick bip-0340 suggested
        // `Verification` protocol.
        Signature { s, r: R.x }
    }

    /// Recovers the share from `(s, R)` and this adaptor as `s − s'`.
    /// Purely algebraic operation that can't fail.
    /// `signature` is obtained from a value committed on chain, so it is assumed to be valid
    pub fn extract_share(&self, signature: &Signature) -> ark_secp256k1::Fr {
        let R = self.expected_R().into_affine();
        assert!(
            !R.is_zero(),
            "a verified adaptor can not have expected R to be zero"
        );
        let is_odd = R.y.into_bigint().is_odd();
        let diff = signature.s - self.tweaked_s;
        if is_odd { -diff } else { diff }
    }

    /// e = H(BIP0340/challenge, R.x, P.x, sighash)
    fn challenge_e(
        R: ark_secp256k1::Affine,
        P: ark_secp256k1::Affine,
        sighash: &[u8],
    ) -> ark_secp256k1::Fr {
        // BIP340 tag
        let tag_hash = Sha256::digest(b"BIP0340/challenge");
        let mut h = Sha256::new();
        h.update(tag_hash);
        h.update(tag_hash);
        h.update(serialize_field(&R.x));
        h.update(serialize_field(&P.x));
        h.update(sighash);
        let digest = h.finalize();
        ark_secp256k1::Fr::from_be_bytes_mod_order(&digest)
    }
}

/* ---------------------------------- Tests ---------------------------------- */
#[cfg(test)]
mod tests {
    use std::str::FromStr;

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
        sighash: Vec<u8>,
        adaptor: Adaptor,
    }

    fn fixture<R: CryptoRng + RngCore>(rng: &mut R) -> Fix {
        // Garbler’s ark_secp256k1::Fr share and commitment
        let share = ark_secp256k1::Fr::rand(rng);
        let S = gen_mul(&share);

        // Evaluator’s master secret/public
        let mut x = ark_secp256k1::Fr::rand(rng);
        let mut P = gen_mul(&x);
        if P.into_affine().y.into_bigint().is_odd() {
            x.neg_in_place();
            P.neg_in_place();
        }

        // Transcript
        let sighash = Sha256::digest(b"demo message").to_vec();

        // Generate adaptor
        let adaptor = Adaptor::generate(rng, S, x, P, &sighash).expect("expected valid Adaptor");

        Fix {
            share,
            S,
            x,
            P,
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
    fn verify_fails_with_wrong_sighash() {
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
        fx.adaptor.R_dash_commit += ark_secp256k1::Projective::generator(); // any non-identity tweak should break relation
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

        let mut x = ark_secp256k1::Fr::rand(&mut rng);
        let mut P = gen_mul(&x);
        if P.into_affine().y.into_bigint().is_odd() {
            x.neg_in_place();
            P.neg_in_place();
        }

        let sighash = Sha256::digest(b"zero-share").to_vec();

        let mut rng = thread_rng();
        let ad = Adaptor::generate(&mut rng, S, x, P, &sighash).expect("expected valid adaptor");

        // Still should verify
        ad.verify(P, &sighash).unwrap();

        // Complete and extract should be no-ops on share part
        let sig = ad.complete(share);
        let recovered = ad.extract_share(&sig);
        assert_eq!(recovered, ark_secp256k1::Fr::zero());
    }

    #[test]
    fn verify_equation_matches_definition() {
        // Cross-check: s'·G == R' + e·P with e computed from (R'+S).x, P.x, sighash.
        let mut rng = thread_rng();
        let fx = fixture(&mut rng);

        // Recompute e like verify() does
        let R = fx.adaptor.expected_R().into_affine();
        let P = fx.P.into_affine();
        let e = Adaptor::challenge_e(R, P, &fx.sighash);

        let lhs = gen_mul(&fx.adaptor.tweaked_s); // s'·G
        let tweaked_R = if R.y.into_bigint().is_odd() {
            -fx.adaptor.R_dash_commit
        } else {
            fx.adaptor.R_dash_commit
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

        let mut x = ark_secp256k1::Fr::from(999u64);
        let mut P = gen_mul(&x);
        if P.into_affine().y.into_bigint().is_odd() {
            x.neg_in_place();
            P.neg_in_place();
        }

        let sighash = Sha256::digest(b"entropy").to_vec();

        let ad1 = Adaptor::generate(&mut rng, S, x, P, &sighash).expect("expected valid adaptor");
        let ad2 = Adaptor::generate(&mut rng, S, x, P, &sighash).expect("expected valid adaptor");

        // With a single RNG stream, two sequential calls still produce different tweaked_r by
        // construction (two independent ark_secp256k1::Fr::rand draws)
        assert_ne!(ad1.R_dash_commit, ad2.R_dash_commit);
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
            let mut evaluator_secret_fr = fr_from_sk(&evaluator_privkey);
            let mut evaluator_master_pk = gen_mul(&evaluator_secret_fr);
            if evaluator_master_pk.into_affine().y.into_bigint().is_odd() {
                evaluator_secret_fr.neg_in_place();
                evaluator_master_pk.neg_in_place();
            }

            let garbler_secret_fr = ark_secp256k1::Fr::rand(&mut rng);
            let garbler_commit = ark_secp256k1::Projective::generator() * garbler_secret_fr;

            let sighash = Sha256::digest(b"some message").to_vec();
            let adaptor = Adaptor::generate(
                &mut rng,
                garbler_commit,
                evaluator_secret_fr,
                evaluator_master_pk,
                sighash.as_slice(),
            )
            .expect("expected valid adaptor");

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
            let mut evaluator_secret_fr = {
                let b = evaluator_privkey.to_bytes();
                ark_secp256k1::Fr::from_be_bytes_mod_order(b.as_slice())
            };
            let mut evaluator_master_pk = gen_mul(&evaluator_secret_fr);
            if evaluator_master_pk.into_affine().y.into_bigint().is_odd() {
                evaluator_secret_fr.neg_in_place();
                evaluator_master_pk.neg_in_place();
            }

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
                evaluator_master_pk,
                &sighash,
            )
            .expect("expected valid adaptor");

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

//! Property-based tests for serialization roundtrips.
//!
//! These tests verify that all message types can be serialized and deserialized
//! correctly using ark-serialize's CanonicalSerialize/CanonicalDeserialize traits.

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use mosaic_common::{
    Byte32,
    constants::{N_CIRCUITS, N_OPEN_CIRCUITS},
};
use mosaic_vs3::{Index, Point, Polynomial, PolynomialCommitment, Scalar, Share};
use proptest::prelude::*;

use crate::{
    Adaptor, AdaptorMsgChunk, AdaptorMsgChunkWithdrawals, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, CircuitInputShares, CommitMsgChunk, DepositId, Msg, PubKey,
    SecretKey, Sighash, Signature, WideLabelWireAdaptors, WideLabelWirePolynomialCommitments,
    WideLabelWireShares,
};

/// Helper to perform a serialization roundtrip and verify equality.
fn roundtrip<T>(value: &T) -> T
where
    T: CanonicalSerialize + CanonicalDeserialize,
{
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .expect("serialization should succeed");
    T::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
        .expect("deserialization should succeed")
}

/// Helper to perform an uncompressed serialization roundtrip.
/// Use this for large messages where compressed deserialization is slow.
fn roundtrip_uncompressed<T>(value: &T) -> T
where
    T: CanonicalSerialize + CanonicalDeserialize,
{
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::No)
        .expect("serialization should succeed");
    T::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes)
        .expect("deserialization should succeed")
}

/// Helper to verify roundtrip preserves the value.
fn assert_roundtrip<T>(value: &T)
where
    T: CanonicalSerialize + CanonicalDeserialize + PartialEq + std::fmt::Debug,
{
    let recovered = roundtrip(value);
    assert_eq!(value, &recovered, "roundtrip should preserve value");
}

/// Helper to verify uncompressed roundtrip preserves the value.
/// Use this for large messages where compressed deserialization is slow.
fn assert_roundtrip_uncompressed<T>(value: &T)
where
    T: CanonicalSerialize + CanonicalDeserialize + PartialEq + std::fmt::Debug,
{
    let recovered = roundtrip_uncompressed(value);
    assert_eq!(value, &recovered, "roundtrip should preserve value");
}

// =============================================================================
// Strategies for generating random cryptographic types
// =============================================================================

/// Generate a random Scalar using ark's randomness.
fn arb_scalar() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>().prop_map(|bytes| Scalar::from_le_bytes_mod_order(&bytes))
}

/// Generate a random Point (as scalar * generator).
fn arb_point() -> impl Strategy<Value = Point> {
    arb_scalar().prop_map(|s| Point::generator() * s)
}

/// Generate a random valid Index (1..=N_CIRCUITS).
fn arb_index() -> impl Strategy<Value = Index> {
    (1usize..=N_CIRCUITS).prop_map(|i| Index::new(i).expect("valid index"))
}

/// Generate a random Share.
fn arb_share() -> impl Strategy<Value = Share> {
    (arb_index(), arb_scalar()).prop_map(|(idx, val)| Share::new(idx, val))
}

/// Generate a random Adaptor.
fn arb_adaptor() -> impl Strategy<Value = Adaptor> {
    (arb_scalar(), arb_point(), arb_point()).prop_map(|(tweaked_s, tweaked_r, share_commitment)| {
        Adaptor {
            tweaked_s,
            tweaked_r,
            share_commitment,
        }
    })
}

/// Generate a random Polynomial.
fn arb_polynomial() -> impl Strategy<Value = Polynomial> {
    Just(()).prop_map(|_| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_entropy();
        Polynomial::rand(&mut rng)
    })
}

/// Generate a random PolynomialCommitment.
fn arb_polynomial_commitment() -> impl Strategy<Value = PolynomialCommitment> {
    arb_polynomial().prop_map(|p| p.commit())
}

/// Generate a random Signature.
fn arb_signature() -> impl Strategy<Value = Signature> {
    (arb_scalar(), arb_point()).prop_map(|(s, r)| Signature { s, r })
}

// =============================================================================
// Strategies for generating message types
// =============================================================================

/// Generate a ChallengeMsg with random indices.
fn arb_challenge_msg() -> impl Strategy<Value = ChallengeMsg> {
    any::<u64>().prop_map(|seed| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Generate N_OPEN_CIRCUITS unique indices from 1..=N_CIRCUITS
        let mut indices: Vec<usize> = (1..=N_CIRCUITS).collect();
        use rand::seq::SliceRandom;
        indices.shuffle(&mut rng);
        indices.truncate(N_OPEN_CIRCUITS);
        indices.sort();

        let challenge_indices: ChallengeIndices =
            ChallengeIndices::new(|i| Index::new(indices[i]).expect("valid index"));

        ChallengeMsg { challenge_indices }
    })
}

/// Generate a CommitMsgChunk using fixed/cloned values for speed.
fn arb_commit_msg_chunk() -> impl Strategy<Value = CommitMsgChunk> {
    any::<u64>().prop_map(|seed| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let single_poly_commit = Polynomial::rand(&mut rng).commit();

        CommitMsgChunk {
            wire_index: (seed % 172) as u16,
            commitments: WideLabelWirePolynomialCommitments::new(|_| single_poly_commit.clone()),
        }
    })
}

/// Generate a ChallengeResponseMsgChunk using fixed/cloned values for speed.
fn arb_challenge_response_msg_chunk() -> impl Strategy<Value = ChallengeResponseMsgChunk> {
    any::<u64>().prop_map(|seed| {
        let bytes: [u8; 32] = std::array::from_fn(|i| ((seed >> (i % 8)) & 0xff) as u8);
        let single_scalar = Scalar::from_le_bytes_mod_order(&bytes);
        let idx = Index::new(1).unwrap_or(Index::reserved());
        let share = Share::new(idx, single_scalar);

        ChallengeResponseMsgChunk {
            circuit_index: (seed % 174) as u16,
            shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| share.clone())),
        }
    })
}

/// Generate an AdaptorMsgChunk using fixed/cloned values for speed.
fn arb_adaptor_msg_chunk() -> impl Strategy<Value = AdaptorMsgChunk> {
    any::<u64>().prop_map(|seed| {
        let bytes: [u8; 32] = std::array::from_fn(|i| ((seed >> (i % 8)) & 0xff) as u8);
        let scalar = Scalar::from_le_bytes_mod_order(&bytes);
        let point = Point::generator() * scalar;

        let single_adaptor = Adaptor {
            tweaked_s: scalar,
            tweaked_r: point,
            share_commitment: point,
        };

        AdaptorMsgChunk {
            chunk_index: (seed % 4) as u8,
            deposit_adaptor: single_adaptor,
            withdrawal_adaptors: AdaptorMsgChunkWithdrawals::new(|_| {
                WideLabelWireAdaptors::new(|_| single_adaptor)
            }),
        }
    })
}

/// Generate a random Msg variant.
fn arb_msg() -> impl Strategy<Value = Msg> {
    prop_oneof![
        arb_commit_msg_chunk().prop_map(Msg::CommitChunk),
        arb_challenge_msg().prop_map(Msg::Challenge),
        arb_challenge_response_msg_chunk().prop_map(Msg::ChallengeResponseChunk),
        arb_adaptor_msg_chunk().prop_map(Msg::AdaptorChunk),
    ]
}

// =============================================================================
// Property tests for primitive types
// =============================================================================

proptest! {
    // Primitive types are fast to test, so we can run more cases
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_byte32_roundtrip(bytes in any::<[u8; 32]>()) {
        let value = Byte32::from(bytes);
        assert_roundtrip(&value);
    }

    #[test]
    fn test_scalar_roundtrip(bytes in any::<[u8; 32]>()) {
        let value = Scalar::from_le_bytes_mod_order(&bytes);
        assert_roundtrip(&value);
    }

    #[test]
    fn test_point_roundtrip(scalar in arb_scalar()) {
        let point = Point::generator() * scalar;
        assert_roundtrip(&point);
    }

    #[test]
    fn test_index_roundtrip(idx in 1usize..=N_CIRCUITS) {
        let value = Index::new(idx).expect("valid index");
        assert_roundtrip(&value);
    }

    #[test]
    fn test_share_roundtrip(share in arb_share()) {
        assert_roundtrip(&share);
    }

    #[test]
    fn test_polynomial_roundtrip(poly in arb_polynomial()) {
        assert_roundtrip(&poly);
    }

    #[test]
    fn test_polynomial_commitment_roundtrip(commit in arb_polynomial_commitment()) {
        assert_roundtrip(&commit);
    }

    #[test]
    fn test_adaptor_roundtrip(adaptor in arb_adaptor()) {
        assert_roundtrip(&adaptor);
    }

    #[test]
    fn test_signature_roundtrip(sig in arb_signature()) {
        assert_roundtrip(&sig);
    }

    #[test]
    fn test_deposit_id_roundtrip(bytes in any::<[u8; 32]>()) {
        let value = DepositId(Byte32::from(bytes));
        assert_roundtrip(&value);
    }

    #[test]
    fn test_sighash_roundtrip(bytes in any::<[u8; 32]>()) {
        let value = Sighash(Byte32::from(bytes));
        assert_roundtrip(&value);
    }

    #[test]
    fn test_secret_key_roundtrip(scalar in arb_scalar()) {
        let value = SecretKey(scalar);
        assert_roundtrip(&value);
    }

    #[test]
    fn test_pub_key_roundtrip(point in arb_point()) {
        let value = PubKey(point);
        assert_roundtrip(&value);
    }
}

// =============================================================================
// Property tests for chunk types (network messages)
// =============================================================================

proptest! {
    // Chunk types are moderately sized, can run more cases than full messages
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_commit_msg_chunk_roundtrip(chunk in arb_commit_msg_chunk()) {
        assert_roundtrip_uncompressed(&chunk);
    }

    #[test]
    fn test_challenge_response_msg_chunk_roundtrip(chunk in arb_challenge_response_msg_chunk()) {
        assert_roundtrip_uncompressed(&chunk);
    }

    #[test]
    fn test_adaptor_msg_chunk_roundtrip(chunk in arb_adaptor_msg_chunk()) {
        assert_roundtrip_uncompressed(&chunk);
    }

    #[test]
    fn test_commit_msg_chunk_compressed_roundtrip(chunk in arb_commit_msg_chunk()) {
        assert_roundtrip(&chunk);
    }

    #[test]
    fn test_adaptor_msg_chunk_compressed_roundtrip(chunk in arb_adaptor_msg_chunk()) {
        assert_roundtrip(&chunk);
    }

    #[test]
    fn test_challenge_msg_roundtrip(msg in arb_challenge_msg()) {
        assert_roundtrip(&msg);
    }
}

// =============================================================================
// Property tests for the Msg enum
// =============================================================================

proptest! {
    // Msg enum contains large chunk types, limit cases
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_msg_enum_roundtrip(msg in arb_msg()) {
        // We can't use assert_roundtrip because Msg doesn't derive PartialEq
        // So we check that roundtrip doesn't panic and produces same variant
        // Use uncompressed to avoid slow decompression
        let mut bytes = Vec::new();
        msg.serialize_with_mode(&mut bytes, Compress::No)
            .expect("serialization should succeed");

        let recovered = Msg::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes)
            .expect("deserialization should succeed");

        // Check variant matches
        match (&msg, &recovered) {
            (Msg::CommitChunk(_), Msg::CommitChunk(_)) => {}
            (Msg::Challenge(_), Msg::Challenge(_)) => {}
            (Msg::ChallengeResponseChunk(_), Msg::ChallengeResponseChunk(_)) => {}
            (Msg::AdaptorChunk(_), Msg::AdaptorChunk(_)) => {}
            _ => panic!("variant mismatch after roundtrip"),
        }
    }
}

// =============================================================================
// Tests for serialization size consistency
// =============================================================================

proptest! {
    // Size consistency tests with chunk messages
    #![proptest_config(ProptestConfig::with_cases(5))]

    #[test]
    fn test_serialized_size_matches_actual_commit_chunk(chunk in arb_commit_msg_chunk()) {
        // Use uncompressed to avoid slow operations
        let expected_size = chunk.serialized_size(Compress::No);
        let mut bytes = Vec::new();
        chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
        prop_assert_eq!(expected_size, bytes.len());
    }

    #[test]
    fn test_serialized_size_matches_actual_challenge(msg in arb_challenge_msg()) {
        let expected_size = msg.serialized_size(Compress::Yes);
        let mut bytes = Vec::new();
        msg.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();
        prop_assert_eq!(expected_size, bytes.len());
    }

    #[test]
    fn test_serialized_size_matches_actual_challenge_response_chunk(chunk in arb_challenge_response_msg_chunk()) {
        let expected_size = chunk.serialized_size(Compress::No);
        let mut bytes = Vec::new();
        chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
        prop_assert_eq!(expected_size, bytes.len());
    }

    #[test]
    fn test_serialized_size_matches_actual_adaptor_chunk(chunk in arb_adaptor_msg_chunk()) {
        // Use uncompressed to avoid slow operations
        let expected_size = chunk.serialized_size(Compress::No);
        let mut bytes = Vec::new();
        chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
        prop_assert_eq!(expected_size, bytes.len());
    }
}

// =============================================================================
// Tests for uncompressed mode
// =============================================================================

proptest! {
    // Uncompressed tests with chunk messages
    #![proptest_config(ProptestConfig::with_cases(5))]

    #[test]
    fn test_challenge_msg_roundtrip_uncompressed(msg in arb_challenge_msg()) {
        let mut bytes = Vec::new();
        msg.serialize_with_mode(&mut bytes, Compress::No)
            .expect("serialization should succeed");
        let recovered = ChallengeMsg::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes)
            .expect("deserialization should succeed");
        assert_eq!(msg, recovered);
    }
}

// =============================================================================
// Edge case tests
// =============================================================================

#[test]
fn test_empty_deserialization_fails() {
    let bytes: &[u8] = &[];

    assert!(CommitMsgChunk::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).is_err());
    assert!(ChallengeMsg::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).is_err());
    assert!(
        ChallengeResponseMsgChunk::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
            .is_err()
    );
    assert!(AdaptorMsgChunk::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).is_err());
    assert!(Msg::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).is_err());
}

#[test]
fn test_truncated_data_fails() {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    // Create a valid ChallengeMsg and serialize it
    let mut indices: Vec<usize> = (1..=N_CIRCUITS).collect();
    use rand::seq::SliceRandom;
    indices.shuffle(&mut rng);
    indices.truncate(N_OPEN_CIRCUITS);
    indices.sort();

    let challenge_indices: ChallengeIndices =
        ChallengeIndices::new(|i| Index::new(indices[i]).expect("valid index"));

    let msg = ChallengeMsg { challenge_indices };

    let mut bytes = Vec::new();
    msg.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();

    // Try deserializing truncated data
    for len in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        let truncated = &bytes[..len];
        assert!(
            ChallengeMsg::deserialize_with_mode(truncated, Compress::Yes, Validate::Yes).is_err(),
            "deserialization should fail for truncated data of length {}",
            len
        );
    }
}

#[test]
fn test_invalid_msg_variant_fails() {
    // Create bytes with an invalid variant discriminant
    let bytes: &[u8] = &[255, 0, 0, 0];
    assert!(Msg::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).is_err());
}

#[test]
fn test_invalid_point_deserialization_fails() {
    // Test that invalid curve points are rejected during deserialization.
    // We serialize a valid point, then corrupt the bytes to create invalid data.

    // First, get a valid point and its serialization
    let valid_point = Point::generator();
    let mut valid_bytes = Vec::new();
    valid_point
        .serialize_with_mode(&mut valid_bytes, Compress::Yes)
        .unwrap();

    // Sanity check: valid point should deserialize successfully
    assert!(
        Point::deserialize_with_mode(&valid_bytes[..], Compress::Yes, Validate::Yes).is_ok(),
        "valid point should deserialize successfully"
    );

    // Case 1: Corrupt the point data by flipping bits - this creates an invalid point
    let mut corrupted_bytes = valid_bytes.clone();
    // Flip several bits in the middle of the serialized data
    for byte in corrupted_bytes.iter_mut().skip(5).take(10) {
        *byte ^= 0xFF;
    }
    assert!(
        Point::deserialize_with_mode(&corrupted_bytes[..], Compress::Yes, Validate::Yes).is_err(),
        "corrupted point data should fail deserialization"
    );

    // Case 2: Truncated point data should fail
    let truncated = &valid_bytes[..valid_bytes.len() / 2];
    assert!(
        Point::deserialize_with_mode(truncated, Compress::Yes, Validate::Yes).is_err(),
        "truncated point should fail deserialization"
    );

    // Case 3: Empty data should fail
    let empty: &[u8] = &[];
    assert!(
        Point::deserialize_with_mode(empty, Compress::Yes, Validate::Yes).is_err(),
        "empty point data should fail deserialization"
    );

    // Case 4: All zeros is not a valid point (not on curve)
    let zeros = vec![0u8; valid_bytes.len()];
    assert!(
        Point::deserialize_with_mode(&zeros[..], Compress::Yes, Validate::Yes).is_err(),
        "all-zero bytes should fail as invalid point"
    );

    // Case 5: All 0xFF bytes should fail
    let all_ff = vec![0xFF; valid_bytes.len()];
    assert!(
        Point::deserialize_with_mode(&all_ff[..], Compress::Yes, Validate::Yes).is_err(),
        "all-0xFF bytes should fail as invalid point"
    );
}

#[test]
fn test_invalid_scalar_deserialization_fails() {
    // Test that invalid/malformed scalar data is rejected during deserialization.
    // Note: ark-serialize rejects scalar values >= field order (returns InvalidData error),
    // it does NOT reduce them mod field order. We test both structural invalidity (wrong size)
    // and out-of-range values.

    // First, get a valid scalar and its serialization
    let valid_scalar = Scalar::from(12345u64);
    let mut valid_bytes = Vec::new();
    valid_scalar
        .serialize_with_mode(&mut valid_bytes, Compress::Yes)
        .unwrap();

    // Sanity check: valid scalar should roundtrip correctly
    let recovered =
        Scalar::deserialize_with_mode(&valid_bytes[..], Compress::Yes, Validate::Yes).unwrap();
    assert_eq!(
        valid_scalar, recovered,
        "valid scalar should roundtrip correctly"
    );

    // Case 1: Truncated scalar data should fail
    let truncated = &valid_bytes[..valid_bytes.len() / 2];
    assert!(
        Scalar::deserialize_with_mode(truncated, Compress::Yes, Validate::Yes).is_err(),
        "truncated scalar should fail deserialization"
    );

    // Case 2: Empty data should fail
    let empty: &[u8] = &[];
    assert!(
        Scalar::deserialize_with_mode(empty, Compress::Yes, Validate::Yes).is_err(),
        "empty scalar should fail deserialization"
    );

    // Case 3: Single byte should fail
    let single_byte: &[u8] = &[0x42];
    assert!(
        Scalar::deserialize_with_mode(single_byte, Compress::Yes, Validate::Yes).is_err(),
        "single byte should fail scalar deserialization"
    );

    // Case 4: Scalar value >= field order should fail with Validate::Yes
    // ark-serialize rejects out-of-range scalars during validation
    let out_of_range_bytes: [u8; 32] = [0xFF; 32];
    assert!(
        Scalar::deserialize_with_mode(&out_of_range_bytes[..], Compress::Yes, Validate::Yes)
            .is_err(),
        "scalar >= field order should fail deserialization with validation"
    );
}

#[test]
fn test_deterministic_serialization() {
    use rand::SeedableRng;

    // Same seed should produce identical serialization
    let seed = 12345u64;

    let msg1 = {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut indices: Vec<usize> = (1..=N_CIRCUITS).collect();
        use rand::seq::SliceRandom;
        indices.shuffle(&mut rng);
        indices.truncate(N_OPEN_CIRCUITS);
        indices.sort();

        let challenge_indices: ChallengeIndices =
            ChallengeIndices::new(|i| Index::new(indices[i]).expect("valid index"));

        ChallengeMsg { challenge_indices }
    };

    let msg2 = {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut indices: Vec<usize> = (1..=N_CIRCUITS).collect();
        use rand::seq::SliceRandom;
        indices.shuffle(&mut rng);
        indices.truncate(N_OPEN_CIRCUITS);
        indices.sort();

        let challenge_indices: ChallengeIndices =
            ChallengeIndices::new(|i| Index::new(indices[i]).expect("valid index"));

        ChallengeMsg { challenge_indices }
    };

    let mut bytes1 = Vec::new();
    let mut bytes2 = Vec::new();
    msg1.serialize_with_mode(&mut bytes1, Compress::Yes)
        .unwrap();
    msg2.serialize_with_mode(&mut bytes2, Compress::Yes)
        .unwrap();

    assert_eq!(
        bytes1, bytes2,
        "same input should produce identical serialization"
    );
}

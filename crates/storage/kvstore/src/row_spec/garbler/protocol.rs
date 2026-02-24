use mosaic_cac_types::{
    Adaptor, ChallengeIndices, CircuitInputShares, CircuitOutputShare, CompletedSignatures,
    DepositInputs, GarblingTableCommitment, OutputPolynomialCommitment, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptorsChunk, WithdrawalInputs,
};
use mosaic_common::Byte32;

use crate::{
    keyspace::KeyDomain,
    row_spec::{
        KVRowSpec,
        common::{
            CircuitIndexKey, DepositChunkKey, DepositKey, ProtocolSingletonKey, WireIndexKey,
        },
        garbler::{
            ROW_TAG_AES128_KEY, ROW_TAG_CHALLENGE_INDICES, ROW_TAG_COMPLETED_SIGNATURES,
            ROW_TAG_CONSTANT_ONE_LABEL, ROW_TAG_CONSTANT_ZERO_LABEL, ROW_TAG_DEPOSIT_ADAPTOR_CHUNK,
            ROW_TAG_DEPOSIT_INPUTS, ROW_TAG_DEPOSIT_SIGHASHES, ROW_TAG_GARBLING_TABLE_COMMITMENT,
            ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK, ROW_TAG_INPUT_SHARE, ROW_TAG_OUTPUT_LABEL_CT,
            ROW_TAG_OUTPUT_POLY_COMMITMENT, ROW_TAG_OUTPUT_SHARE, ROW_TAG_PUBLIC_S,
            ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK, ROW_TAG_WITHDRAWAL_INPUT,
        },
    },
};

/// Row spec for input polynomial commitment chunks.
#[derive(Debug)]
pub struct InputPolynomialCommitmentChunkRowSpec;

impl KVRowSpec for InputPolynomialCommitmentChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK;

    type Key = WireIndexKey;
    type Value = WideLabelWirePolynomialCommitments;
}

/// Row spec for output polynomial commitment.
#[derive(Debug)]
pub struct OutputPolynomialCommitmentRowSpec;

impl KVRowSpec for OutputPolynomialCommitmentRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_POLY_COMMITMENT;

    type Key = ProtocolSingletonKey;
    type Value = OutputPolynomialCommitment;
}

/// Row spec for input shares by circuit index.
#[derive(Debug)]
pub struct InputShareRowSpec;

impl KVRowSpec for InputShareRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_INPUT_SHARE;

    type Key = CircuitIndexKey;
    type Value = CircuitInputShares;
}

/// Row spec for output shares by circuit index.
#[derive(Debug)]
pub struct OutputShareRowSpec;

impl KVRowSpec for OutputShareRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_SHARE;

    type Key = CircuitIndexKey;
    type Value = CircuitOutputShare;
}

/// Row spec for garbling table commitments by zero-based circuit index.
#[derive(Debug)]
pub struct GarblingTableCommitmentRowSpec;

impl KVRowSpec for GarblingTableCommitmentRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_GARBLING_TABLE_COMMITMENT;

    type Key = CircuitIndexKey;
    type Value = GarblingTableCommitment;
}

/// Row spec for challenge indices singleton.
#[derive(Debug)]
pub struct ChallengeIndicesRowSpec;

impl KVRowSpec for ChallengeIndicesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_CHALLENGE_INDICES;

    type Key = ProtocolSingletonKey;
    type Value = ChallengeIndices;
}

/// Row spec for per-deposit sighashes.
#[derive(Debug)]
pub struct DepositSighashesRowSpec;

impl KVRowSpec for DepositSighashesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_SIGHASHES;

    type Key = DepositKey;
    type Value = Sighashes;
}

/// Row spec for per-deposit inputs.
#[derive(Debug)]
pub struct DepositInputsRowSpec;

impl KVRowSpec for DepositInputsRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_INPUTS;

    type Key = DepositKey;
    type Value = DepositInputs;
}

/// Row spec for per-deposit withdrawal inputs.
#[derive(Debug)]
pub struct WithdrawalInputRowSpec;

impl KVRowSpec for WithdrawalInputRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_INPUT;

    type Key = DepositKey;
    type Value = WithdrawalInputs;
}

/// Row spec for per-deposit adaptor chunks.
#[derive(Debug)]
pub struct DepositAdaptorChunkRowSpec;

impl KVRowSpec for DepositAdaptorChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_ADAPTOR_CHUNK;

    type Key = DepositChunkKey;
    type Value = Adaptor;
}

/// Row spec for per-deposit withdrawal adaptor chunks.
#[derive(Debug)]
pub struct WithdrawalAdaptorChunkRowSpec;

impl KVRowSpec for WithdrawalAdaptorChunkRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK;

    type Key = DepositChunkKey;
    type Value = WithdrawalAdaptorsChunk;
}

/// Row spec for per-deposit completed signatures.
#[derive(Debug)]
pub struct CompletedSignaturesRowSpec;

impl KVRowSpec for CompletedSignaturesRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_COMPLETED_SIGNATURES;

    type Key = DepositKey;
    type Value = CompletedSignatures;
}

/// Row spec for per-circuit AES128 key.
#[derive(Debug)]
pub struct Aes128KeyRowSpec;

impl KVRowSpec for Aes128KeyRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_AES128_KEY;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit public S value.
#[derive(Debug)]
pub struct PublicSRowSpec;

impl KVRowSpec for PublicSRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_PUBLIC_S;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit constant-zero label.
#[derive(Debug)]
pub struct ConstantZeroLabelRowSpec;

impl KVRowSpec for ConstantZeroLabelRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_CONSTANT_ZERO_LABEL;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit constant-one label.
#[derive(Debug)]
pub struct ConstantOneLabelRowSpec;

impl KVRowSpec for ConstantOneLabelRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_CONSTANT_ONE_LABEL;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-evaluation-circuit output label ciphertext.
#[derive(Debug)]
pub struct OutputLabelCtRowSpec;

impl KVRowSpec for OutputLabelCtRowSpec {
    const DOMAIN: KeyDomain = KeyDomain::Garbler;
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_LABEL_CT;

    type Key = CircuitIndexKey;
    type Value = Byte32;
}

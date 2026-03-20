use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CompletedSignatures, DepositAdaptors,
    DepositInputs, OpenedGarblingSeeds, OpenedOutputShares, OutputPolynomialCommitment,
    PolynomialCommitment, ReservedSetupInputShares, Sighashes, WideLabelWireAdaptors,
    WideLabelWireShares, WithdrawalInputs,
};
use mosaic_common::Byte32;
use mosaic_vs3::Share;

use crate::row_spec::{
    KVRowSpec,
    common::{
        CircuitIndexKey, CircuitSubChunkKey, DepositDoubleChunkKey, DepositKey,
        ProtocolSingletonKey, WireSubChunkKey,
    },
    evaluator::{
        ROW_TAG_AES128_KEY, ROW_TAG_CHALLENGE_INDICES, ROW_TAG_COMPLETED_SIGNATURES,
        ROW_TAG_CONSTANT_ONE_LABEL, ROW_TAG_CONSTANT_ZERO_LABEL, ROW_TAG_DEPOSIT_ADAPTORS,
        ROW_TAG_DEPOSIT_INPUTS, ROW_TAG_DEPOSIT_SIGHASHES, ROW_TAG_FAULT_SECRET,
        ROW_TAG_GARBLING_TABLE_COMMITMENTS, ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK,
        ROW_TAG_OPENED_GARBLING_SEEDS, ROW_TAG_OPENED_INPUT_SHARE_CHUNK,
        ROW_TAG_OPENED_OUTPUT_SHARES, ROW_TAG_OUTPUT_LABEL_CT, ROW_TAG_OUTPUT_POLY_COMMITMENT,
        ROW_TAG_PUBLIC_S, ROW_TAG_RESERVED_SETUP_INPUT_SHARES, ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK,
        ROW_TAG_WITHDRAWAL_INPUTS,
    },
};

/// Row spec for sub-chunked input polynomial commitments.
/// Stores one `PolynomialCommitment` per (wire_idx, value_idx) pair.
#[derive(Debug)]
pub struct InputPolynomialCommitmentRowSpec;

impl KVRowSpec for InputPolynomialCommitmentRowSpec {
    const ROW_TAG: u8 = ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK;

    type Key = WireSubChunkKey;
    type Value = PolynomialCommitment;
}

/// Row spec for output polynomial commitment singleton.
#[derive(Debug)]
pub struct OutputPolynomialCommitmentRowSpec;

impl KVRowSpec for OutputPolynomialCommitmentRowSpec {
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_POLY_COMMITMENT;

    type Key = ProtocolSingletonKey;
    type Value = OutputPolynomialCommitment;
}

/// Row spec for all garbling table commitments singleton.
#[derive(Debug)]
pub struct GarblingTableCommitmentsRowSpec;

impl KVRowSpec for GarblingTableCommitmentsRowSpec {
    const ROW_TAG: u8 = ROW_TAG_GARBLING_TABLE_COMMITMENTS;

    type Key = ProtocolSingletonKey;
    type Value = AllGarblingTableCommitments;
}

/// Row spec for challenge indices singleton.
#[derive(Debug)]
pub struct ChallengeIndicesRowSpec;

impl KVRowSpec for ChallengeIndicesRowSpec {
    const ROW_TAG: u8 = ROW_TAG_CHALLENGE_INDICES;

    type Key = ProtocolSingletonKey;
    type Value = ChallengeIndices;
}

/// Row spec for sub-chunked opened input shares.
/// Stores one `WideLabelWireShares` per (circuit_idx, wire_idx) pair.
#[derive(Debug)]
pub struct OpenedInputShareRowSpec;

impl KVRowSpec for OpenedInputShareRowSpec {
    const ROW_TAG: u8 = ROW_TAG_OPENED_INPUT_SHARE_CHUNK;

    type Key = CircuitSubChunkKey;
    type Value = WideLabelWireShares;
}

/// Row spec for reserved setup input shares singleton.
#[derive(Debug)]
pub struct ReservedSetupInputSharesRowSpec;

impl KVRowSpec for ReservedSetupInputSharesRowSpec {
    const ROW_TAG: u8 = ROW_TAG_RESERVED_SETUP_INPUT_SHARES;

    type Key = ProtocolSingletonKey;
    type Value = ReservedSetupInputShares;
}

/// Row spec for opened output shares singleton.
#[derive(Debug)]
pub struct OpenedOutputSharesRowSpec;

impl KVRowSpec for OpenedOutputSharesRowSpec {
    const ROW_TAG: u8 = ROW_TAG_OPENED_OUTPUT_SHARES;

    type Key = ProtocolSingletonKey;
    type Value = OpenedOutputShares;
}

/// Row spec for opened garbling seeds singleton.
#[derive(Debug)]
pub struct OpenedGarblingSeedsRowSpec;

impl KVRowSpec for OpenedGarblingSeedsRowSpec {
    const ROW_TAG: u8 = ROW_TAG_OPENED_GARBLING_SEEDS;

    type Key = ProtocolSingletonKey;
    type Value = OpenedGarblingSeeds;
}

/// Row spec for per-deposit sighashes.
#[derive(Debug)]
pub struct DepositSighashesRowSpec;

impl KVRowSpec for DepositSighashesRowSpec {
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_SIGHASHES;

    type Key = DepositKey;
    type Value = Sighashes;
}

/// Row spec for per-deposit inputs.
#[derive(Debug)]
pub struct DepositInputsRowSpec;

impl KVRowSpec for DepositInputsRowSpec {
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_INPUTS;

    type Key = DepositKey;
    type Value = DepositInputs;
}

/// Row spec for per-deposit withdrawal inputs.
#[derive(Debug)]
pub struct WithdrawalInputsRowSpec;

impl KVRowSpec for WithdrawalInputsRowSpec {
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_INPUTS;

    type Key = DepositKey;
    type Value = WithdrawalInputs;
}

/// Row spec for per-deposit adaptor signatures.
#[derive(Debug)]
pub struct DepositAdaptorsRowSpec;

impl KVRowSpec for DepositAdaptorsRowSpec {
    const ROW_TAG: u8 = ROW_TAG_DEPOSIT_ADAPTORS;

    type Key = DepositKey;
    type Value = DepositAdaptors;
}

/// Row spec for sub-chunked per-deposit withdrawal adaptors.
/// Stores one `WideLabelWireAdaptors` per (deposit_id, chunk_idx, wire_idx) triple.
#[derive(Debug)]
pub struct WithdrawalAdaptorRowSpec;

impl KVRowSpec for WithdrawalAdaptorRowSpec {
    const ROW_TAG: u8 = ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK;

    type Key = DepositDoubleChunkKey;
    type Value = WideLabelWireAdaptors;
}

/// Row spec for per-deposit completed signatures.
#[derive(Debug)]
pub struct CompletedSignaturesRowSpec;

impl KVRowSpec for CompletedSignaturesRowSpec {
    const ROW_TAG: u8 = ROW_TAG_COMPLETED_SIGNATURES;

    type Key = DepositKey;
    type Value = CompletedSignatures;
}

/// Row spec for per-circuit AES128 key.
#[derive(Debug)]
pub struct Aes128KeyRowSpec;

impl KVRowSpec for Aes128KeyRowSpec {
    const ROW_TAG: u8 = ROW_TAG_AES128_KEY;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit public S value.
#[derive(Debug)]
pub struct PublicSRowSpec;

impl KVRowSpec for PublicSRowSpec {
    const ROW_TAG: u8 = ROW_TAG_PUBLIC_S;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit constant-zero label.
#[derive(Debug)]
pub struct ConstantZeroLabelRowSpec;

impl KVRowSpec for ConstantZeroLabelRowSpec {
    const ROW_TAG: u8 = ROW_TAG_CONSTANT_ZERO_LABEL;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-circuit constant-one label.
#[derive(Debug)]
pub struct ConstantOneLabelRowSpec;

impl KVRowSpec for ConstantOneLabelRowSpec {
    const ROW_TAG: u8 = ROW_TAG_CONSTANT_ONE_LABEL;

    type Key = CircuitIndexKey;
    type Value = [u8; 16];
}

/// Row spec for per-evaluation-circuit output label ciphertext.
#[derive(Debug)]
pub struct OutputLabelCtRowSpec;

impl KVRowSpec for OutputLabelCtRowSpec {
    const ROW_TAG: u8 = ROW_TAG_OUTPUT_LABEL_CT;

    type Key = CircuitIndexKey;
    type Value = Byte32;
}

/// Row spec for fault secret.
#[derive(Debug)]
pub struct FaultSecretRowSpec;

impl KVRowSpec for FaultSecretRowSpec {
    const ROW_TAG: u8 = ROW_TAG_FAULT_SECRET;

    type Key = ProtocolSingletonKey;
    type Value = Share;
}

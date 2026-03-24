use mosaic_common::{
    Byte32,
    constants::{
        N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS,
        N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
        WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK, WideLabelValue,
    },
};
pub use mosaic_heap_array::HeapArray;
use mosaic_vs3::Point;
pub use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use crate::{Adaptor, GarblingTableCommitment, Seed, Sighash, Signature};

/// Polynomials for all wide label values for a single wire.
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type WideLabelWirePolynomials = HeapArray<Polynomial, WIDE_LABEL_VALUE_COUNT>;
/// Polynomial commitments for all wide label values for a single wire.
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type WideLabelWirePolynomialCommitments =
    HeapArray<PolynomialCommitment, WIDE_LABEL_VALUE_COUNT>;

/// Input wire polynomials.
pub type InputPolynomials = HeapArray<WideLabelWirePolynomials, N_INPUT_WIRES>;
/// Input wire polynomial commitments.
pub type InputPolynomialCommitments = HeapArray<WideLabelWirePolynomialCommitments, N_INPUT_WIRES>;
/// Output wire polynomial.
pub type OutputPolynomial = Polynomial;
/// Output wire polynomial commitment.
pub type OutputPolynomialCommitment = HeapArray<PolynomialCommitment, 1>;

/// Zeroth coefficients for polynomial commitments for all wide label values for a single wire.
pub type WideLabelZerothPolynomialCoefficients = HeapArray<Point, WIDE_LABEL_VALUE_COUNT>;
/// Zeroth coefficients for polynomial commitments for all wide label values for all input wires.
pub type InputPolynomialZerothCoefficients =
    HeapArray<WideLabelZerothPolynomialCoefficients, N_INPUT_WIRES>;

/// All Polynomials.
pub type AllPolynomials = (InputPolynomials, OutputPolynomial);
/// All Polynomial commitments.
pub type AllPolynomialCommitments = (InputPolynomialCommitments, OutputPolynomialCommitment);

/// Commitments for all `N_CIRCUITS` garbling tables.
/// Uses HeapArray for serialization derive macro support.
pub type AllGarblingTableCommitments = HeapArray<GarblingTableCommitment, N_CIRCUITS>;
/// Commitments for opened garbling tables.
pub type OpenedGarblingTableCommitments = HeapArray<GarblingTableCommitment, N_OPEN_CIRCUITS>;
/// Commitments for eval garbling tables.
pub type EvalGarblingTableCommitments = HeapArray<GarblingTableCommitment, N_EVAL_CIRCUITS>;

/// Aes128 keys for all `N_CIRCUITS` garbling tables.
pub type AllAes128Keys = HeapArray<[u8; 16], N_CIRCUITS>;
/// Public S values for all `N_CIRCUITS` garbling tables.
pub type AllPublicSValues = HeapArray<[u8; 16], N_CIRCUITS>;
/// Constant zero labels for all `N_CIRCUITS` garbling tables.
pub type AllConstZeroLabels = HeapArray<[u8; 16], N_CIRCUITS>;
/// Constant one labels for all `N_CIRCUITS` garbling tables.
pub type AllConstOneLabels = HeapArray<[u8; 16], N_CIRCUITS>;
/// Output label ciphertexts for all `N_CIRCUITS` garbling tables.
pub type AllOutputLabelCts = HeapArray<Byte32, N_CIRCUITS>;

/// Challenged `N_COEFFICIENTS` indices. Must NOT include reserved index 0.
/// Uses HeapArray for derive macro support.
pub type ChallengeIndices = HeapArray<Index, N_OPEN_CIRCUITS>;
/// `N_CIRCUITS - N_COEFFICIENTS` indices for evaluation.
pub type EvaluationIndices = [Index; N_EVAL_CIRCUITS];

/// Shares for all wide label values for a single wire.
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type WideLabelWireShares = HeapArray<Share, WIDE_LABEL_VALUE_COUNT>;
/// Shares for all wide label values, for all input wires, for a single circuit.
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type CircuitInputShares = HeapArray<WideLabelWireShares, N_INPUT_WIRES>;
/// Share for value 0 of output wire for a single circuit
pub type CircuitOutputShare = Share;

/// Shares for all wide label values, for all input wires, for all circuit indices, with circuit
/// index 0 being reserved index share.
pub type InputShares = HeapArray<CircuitInputShares, { N_CIRCUITS + 1 }>;
/// Shares for value 0 of output wire for all circuit, with circuit index 0 being reserved index
/// share.
pub type OutputShares = HeapArray<CircuitOutputShare, { N_CIRCUITS + 1 }>;

/// Input shares for all wide label values, for all input wires, for reserved index 0.
/// Equivalent to `InputShares[0]`
pub type ReservedInputShares = CircuitInputShares;

/// Input shares for all wide label values, for all input wires, for all opened indices.
pub type OpenedInputShares = HeapArray<CircuitInputShares, N_OPEN_CIRCUITS>;

/// Reserved input shares for wide labels corresponding to agreed setup inputs, for each setup input
/// wire. Uses HeapArray for serialization derive macro support.
pub type ReservedSetupInputShares = HeapArray<Share, N_SETUP_INPUT_WIRES>;
/// Reserved input shares for all wide label values corresponding to deposit input wires.
pub type ReservedDepositInputShares = [Share; N_DEPOSIT_INPUT_WIRES];
/// Reserved input shares for all wide labels corresponding to withdrawal input wires.
pub type ReservedWithdrawalInputShares = [WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES];
/// Shares for value 0 output wire for for all opened indices.
/// Uses HeapArray for serialization derive macro support.
pub type OpenedOutputShares = HeapArray<CircuitOutputShare, N_OPEN_CIRCUITS>;

/// Seed for garbling table generation.
pub type GarblingSeed = Seed;
/// Seeds for garbling table generation for all indices.
pub type AllGarblingSeeds = HeapArray<GarblingSeed, N_CIRCUITS>;
/// Seeds for garbling table generation for all opened indices.
/// Uses HeapArray for serialization derive macro support.
pub type OpenedGarblingSeeds = HeapArray<GarblingSeed, N_OPEN_CIRCUITS>;
/// Seeds for garbling table generation for evaluation indices.
pub type EvalGarblingSeeds = HeapArray<GarblingSeed, N_EVAL_CIRCUITS>;

/// Adaptor pre-signaures for all wide label values for a single wire.
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type WideLabelWireAdaptors = HeapArray<Adaptor, WIDE_LABEL_VALUE_COUNT>;

/// Adaptor pre-signatures corresponding to deposit input wide label values for deposit wires.
pub type DepositAdaptors = HeapArray<Adaptor, N_DEPOSIT_INPUT_WIRES>;
/// Adaptor pre-signatures for all wide label values for all withdrawal input wires.
pub type WithdrawalAdaptors = HeapArray<WideLabelWireAdaptors, N_WITHDRAWAL_INPUT_WIRES>;
/// Adaptor pre-signatures for withdrawal wires in a single chunk (32 wires × 256 values).
/// Uses HeapArray to avoid LLVM optimization issues with large fixed-size arrays.
pub type WithdrawalAdaptorsChunk =
    HeapArray<WideLabelWireAdaptors, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK>;

/// List of sighashes corresponding to deposit and withdrawal input wires.
pub type Sighashes = HeapArray<Sighash, { N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES }>;

/// Values of setup input wires, represents bridge operator pubkey.
pub type SetupInputs = [WideLabelValue; N_SETUP_INPUT_WIRES];
/// Values of deposit input wires, represents deposit index.
pub type DepositInputs = [WideLabelValue; N_DEPOSIT_INPUT_WIRES];
/// Values of withdrawal input wires, represents a groth16 proof and its public inputs.
pub type WithdrawalInputs = [WideLabelValue; N_WITHDRAWAL_INPUT_WIRES];

/// Completed adaptor signatures.
pub type CompletedSignatures =
    HeapArray<Signature, { N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES }>;

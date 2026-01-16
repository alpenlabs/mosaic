use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
    N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT, WideLabelValue,
};
pub use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use crate::{Adaptor, GarblingTableCommitment, Seed};

/// Setup input values, represents bridge operator pubkey.
pub type SetupInputs = [WideLabelValue; N_SETUP_INPUT_WIRES];

/// Input wire polynomials.
pub type InputPolynomials = [[Polynomial; WIDE_LABEL_VALUE_COUNT]; N_INPUT_WIRES];
/// Input wire polynomial commitments.
pub type InputPolynomialCommitments =
    [[PolynomialCommitment; WIDE_LABEL_VALUE_COUNT]; N_INPUT_WIRES];
/// Output wire polynomial.
pub type OutputPolynomial = Polynomial;
/// Output wire polynomial commitment.
pub type OutputPolynomialCommitment = PolynomialCommitment;

/// All Polynomials.
pub type AllPolynomials = (InputPolynomials, OutputPolynomial);
/// All Polynomial commitments.
pub type AllPolynomialCommitments = (InputPolynomialCommitments, OutputPolynomialCommitment);

/// Commitments for all `N_CIRCUITS` garbling tables.
pub type GarblingTableCommitments = [GarblingTableCommitment; N_CIRCUITS];

/// Challenged `N_COEFFICIENTS` indices. Must NOT include reserved index 0.
pub type ChallengeIndices = [Index; N_OPEN_CIRCUITS];
/// `N_CIRCUITS - N_COEFFICIENTS` indices for evaluation.
pub type EvaluationIndices = [Index; N_CIRCUITS - N_OPEN_CIRCUITS];

/// Shares for all wide label values, for all input wires, for all circuit indices, with circuit
/// index 0 being reserved index share.
pub type InputShares = [[[Share; WIDE_LABEL_VALUE_COUNT]; N_INPUT_WIRES]; N_CIRCUITS + 1];
/// Shares for value 0 of output wire for all circuit, with circuit index 0 being reserved index
/// share.
pub type OutputShares = [Share; N_CIRCUITS + 1];

/// All shares.
pub type AllShares = (InputShares, OutputShares);

/// Input shares for all wide label values, for all input wires, for all opened indices.
pub type OpenedInputShares = [[[Share; WIDE_LABEL_VALUE_COUNT]; N_INPUT_WIRES]; N_OPEN_CIRCUITS];
/// Reserved input shares for wide labels corresponding to agreed setup inputs, for each setup input
/// wire.
pub type ReservedSetupInputShares = [[Share; WIDE_LABEL_VALUE_COUNT]; N_SETUP_INPUT_WIRES];
/// Shares for value 0 output wire for for all opened indices.
pub type OpenedOutputShares = [Share; N_OPEN_CIRCUITS];

/// Seeds for garbling table generation for all indices.
pub type AllGarblingSeeds = [Seed; N_CIRCUITS];
/// Seeds for garbling table generation for all opened indices.
pub type OpenedGarblingSeeds = [Seed; N_OPEN_CIRCUITS];

/// Adaptor pre-signatures corresponding to deposit input wide label values for deposit wires.
pub type DepositAdaptors = [Adaptor; N_DEPOSIT_INPUT_WIRES];
/// Adaptor pre-signatures for all wide label values for all withdrawal input wires.
pub type WithdrawalAdaptors = [[Adaptor; WIDE_LABEL_VALUE_COUNT]; N_WITHDRAWAL_INPUT_WIRES];

/// Deposit and Withdrawal adaptors.
pub type Adaptors = (DepositAdaptors, WithdrawalAdaptors);

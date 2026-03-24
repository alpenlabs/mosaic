//! In-memory storage implementation for evaluator state.

mod state_mut;
mod state_read;

use std::collections::{BTreeMap, HashMap};

use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, OpenedGarblingSeeds, OpenedOutputShares,
    OutputPolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WideLabelZerothPolynomialCoefficients,
    WithdrawalAdaptorsChunk, WithdrawalInputs,
    state_machine::evaluator::{DepositState, EvaluatorState},
};
use mosaic_common::Byte32;
use mosaic_vs3::Share;

use crate::error::DbError;

/// In-memory storage for evaluator protocol state and cryptographic data.
#[derive(Debug, Clone, Default)]
pub struct StoredEvaluatorState {
    /// Root evaluator state machine state.
    pub state: Option<EvaluatorState>,
    /// Input polynomial commitments indexed by wire.
    pub input_polynomial_commitments: BTreeMap<usize, WideLabelWirePolynomialCommitments>,
    /// Zeroth coefficients for polynomial commitments indexed by wire.
    pub zeroth_commitments: BTreeMap<usize, WideLabelZerothPolynomialCoefficients>,
    /// Output polynomial commitment.
    pub output_polynomial_commitment: Option<OutputPolynomialCommitment>,
    /// Garbling table commitments for all circuits.
    pub gt_commitments: Option<AllGarblingTableCommitments>,
    /// Challenge indices for verification using CaC.
    pub challenge_indices: Option<ChallengeIndices>,
    /// Shares for input wires, indexed by circuit.
    pub opened_input_shares: BTreeMap<usize, CircuitInputShares>,
    /// Shares for setup input wires at reserved circuit index.
    pub reserved_setup_input_shares: Option<ReservedSetupInputShares>,
    /// Shares for output wires for opened circuits.
    pub opened_output_shares: Option<OpenedOutputShares>,
    /// Opened garbling seeds.
    pub opened_garbling_seeds: Option<OpenedGarblingSeeds>,
    /// AES-128 keys for all garbling instances, indexed by circuit (0-indexed).
    pub aes128_keys: BTreeMap<usize, [u8; 16]>,
    /// Public S values for all garbling instances, indexed by circuit (0-indexed).
    pub public_s_values: BTreeMap<usize, [u8; 16]>,
    /// Constant-false wire labels for all garbling instances, indexed by circuit (0-indexed).
    pub constant_zero_labels: BTreeMap<usize, [u8; 16]>,
    /// Constant-true wire labels for all garbling instances, indexed by circuit (0-indexed).
    pub constant_one_labels: BTreeMap<usize, [u8; 16]>,
    /// Output label ciphertexts for unopened circuits.
    pub output_label_cts: BTreeMap<usize, Byte32>,
    /// Per-deposit state indexed by `DepositId`.
    pub deposits: HashMap<DepositId, EvaluatorDepositState>,
    /// Fault secret
    pub fault_secret: Option<Share>,
}

impl StoredEvaluatorState {
    fn get_deposit_mut_or_default(&mut self, deposit_id: &DepositId) -> &mut EvaluatorDepositState {
        if !self.deposits.contains_key(deposit_id) {
            self.deposits
                .insert(*deposit_id, EvaluatorDepositState::default());
        };
        self.deposits.get_mut(deposit_id).unwrap()
    }

    fn get_deposit_or_err(
        &self,
        deposit_id: &DepositId,
    ) -> Result<&EvaluatorDepositState, DbError> {
        self.deposits
            .get(deposit_id)
            .ok_or_else(|| DbError::unknown_deposit(*deposit_id))
    }
}

/// Per-deposit state for evaluator state machine.
#[derive(Debug, Clone, Default)]
pub struct EvaluatorDepositState {
    /// Root state per Deposit.
    pub state: Option<DepositState>,
    /// Transaction sighashes for this deposit.
    pub sighashes: Option<Sighashes>,
    /// Values for deposit input wires.
    pub deposit_inputs: Option<DepositInputs>,
    /// Inputs for withdrawal input wires.
    pub withdrawal_inputs: Option<WithdrawalInputs>,
    /// Adaptor signatures for deposit input wires.
    pub deposit_adaptors: Option<DepositAdaptors>,
    /// Adaptor signatures for Withdrawal input wires, chunked in `N_ADAPTOR_MSG_CHUNKS` chunks.
    pub withdrawal_adaptors: HashMap<u8, WithdrawalAdaptorsChunk>,
    /// Completed adaptor signatures.
    pub completed_sigs: Option<CompletedSignatures>,
}

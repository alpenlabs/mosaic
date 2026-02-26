//! In-memory storage implementation for garbler state.

mod state_mut;
mod state_read;

use std::collections::{BTreeMap, HashMap};

use mosaic_cac_types::{
    Adaptor, ChallengeIndices, CircuitInputShares, CircuitOutputShare, CompletedSignatures,
    DepositId, DepositInputs, GarblingTableCommitment, OutputPolynomialCommitment, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptorsChunk, WithdrawalInputs,
    state_machine::garbler::{DepositState, GarblerState, GarblingMetadata},
};

use crate::error::DbError;

/// In-memory storage for garbler protocol state and cryptographic data.
#[derive(Debug, Clone, Default)]
pub struct StoredGarblerState {
    /// Root garbler state machine state.
    pub state: GarblerState,
    /// Input polynomial commitments indexed by wire.
    pub input_polynomial_commitments: BTreeMap<usize, WideLabelWirePolynomialCommitments>,
    /// Output polynomial commitment.
    pub output_polynomial_commitment: Option<OutputPolynomialCommitment>,
    /// Shares for input wires, indexed by circuit.
    pub input_shares: BTreeMap<usize, CircuitInputShares>,
    /// Shares for output wires indexed by circuit.
    pub output_shares: BTreeMap<usize, CircuitOutputShare>,
    /// Garbling table commitments indexed by circuit.
    pub gt_commitments: BTreeMap<usize, GarblingTableCommitment>,
    /// Garbling table commitments indexed by circuit.
    pub gt_metadata: BTreeMap<usize, GarblingMetadata>,
    /// Challenge indices for verification using CaC.
    pub challenge_indices: Option<ChallengeIndices>,
    /// Per-deposit state indexed by `DepositId`.
    pub deposits: HashMap<DepositId, GarblerDepositState>,
}

impl StoredGarblerState {
    fn get_deposit_mut_or_default(&mut self, deposit_id: &DepositId) -> &mut GarblerDepositState {
        if !self.deposits.contains_key(deposit_id) {
            self.deposits
                .insert(*deposit_id, GarblerDepositState::default());
        };
        self.deposits.get_mut(deposit_id).unwrap()
    }

    fn get_deposit_or_err(&self, deposit_id: &DepositId) -> Result<&GarblerDepositState, DbError> {
        self.deposits
            .get(deposit_id)
            .ok_or_else(|| DbError::unknown_deposit(*deposit_id))
    }
}

/// Per-deposit state for garbler state machine.
#[derive(Debug, Clone, Default)]
pub struct GarblerDepositState {
    /// Root state per Deposit.
    pub state: Option<DepositState>,
    /// Transaction sighashes for this deposit.
    pub sighashes: Option<Sighashes>,
    /// Values for deposit input wires.
    pub deposit_inputs: Option<DepositInputs>,
    /// Inputs for withdrawal input wires.
    pub withdrawal_inputs: Option<WithdrawalInputs>,
    /// Adaptor signatures for deposit input wires, chunked by chunk index.
    pub deposit_adaptors: BTreeMap<u8, Adaptor>,
    /// Adaptor signatures for withdrawal input wires, chunked in `N_ADAPTOR_MSG_CHUNKS` chunks.
    pub withdrawal_adaptor_chunks: BTreeMap<u8, WithdrawalAdaptorsChunk>,
    /// Completed adaptor signatures.
    pub completed_sigs: Option<CompletedSignatures>,
}

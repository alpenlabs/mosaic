//! In-memory storage implementation for garbler state.

use std::collections::{BTreeMap, HashMap};

use futures::{
    Stream,
    stream::{self, StreamExt},
};
use mosaic_cac_protocol::garbler::{
    deposit::DepositState,
    root_state::GarblerState,
    state::{StateMut, StateRead},
};
use mosaic_cac_types::{
    Adaptor, AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares,
    CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId, DepositInputs,
    GarblingTableCommitment, HeapArray, Index, InputPolynomialCommitments, InputShares,
    OutputPolynomialCommitment, OutputShares, ReservedInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalAdaptorsChunk,
    WithdrawalInputs,
};
use mosaic_common::constants::{N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_INPUT_WIRES};

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

impl StateRead for StoredGarblerState {
    type Error = DbError;

    async fn get_root_state(&self) -> Result<Option<GarblerState>, Self::Error> {
        Ok(Some(self.state.clone()))
    }

    async fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositState>, Self::Error> {
        let Some(deposit_data) = self.deposits.get(deposit_id) else {
            return Ok(None);
        };

        Ok(deposit_data.state.clone())
    }

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send {
        let deposits: Vec<_> = self
            .deposits
            .iter()
            .filter_map(|(id, deposit_data)| deposit_data.state.clone().map(|state| (*id, state)))
            .collect();

        stream::iter(deposits).map(Ok)
    }

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        if self.input_polynomial_commitments.is_empty() {
            return Ok(None);
        }
        let mut input_commitments = Vec::new();
        for idx in 0..N_INPUT_WIRES {
            let commitment = self
                .input_polynomial_commitments
                .get(&idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected input commitment"))?;

            input_commitments.push(commitment);
        }

        Ok(Some(HeapArray::from_vec(input_commitments)))
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        Ok(self.output_polynomial_commitment.clone())
    }

    async fn get_input_shares(&self) -> Result<Option<InputShares>, Self::Error> {
        if self.input_shares.is_empty() {
            return Ok(None);
        }

        let mut input_shares_vec = Vec::new();
        for ckt_idx in 1..N_CIRCUITS + 1 {
            let input_shares = self
                .input_shares
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected input share"))?;
            input_shares_vec.push(input_shares);
        }

        Ok(Some(HeapArray::from_vec(input_shares_vec)))
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        if self.output_shares.is_empty() {
            return Ok(None);
        }

        let mut output_shares_vec = Vec::new();
        for ckt_idx in 1..N_CIRCUITS + 1 {
            let output_shares = self
                .output_shares
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected output share"))?;
            output_shares_vec.push(output_shares);
        }

        Ok(Some(HeapArray::from_vec(output_shares_vec)))
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        Ok(self.input_shares.get(&0).cloned())
    }

    async fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> Result<Option<GarblingTableCommitment>, Self::Error> {
        Ok(self.gt_commitments.get(&index.get()).cloned())
    }

    async fn get_all_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        if self.gt_commitments.is_empty() {
            return Ok(None);
        }

        let mut commitments = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let commitment = self.gt_commitments.get(&ckt_idx).cloned().ok_or_else(|| {
                DbError::state_inconsistency("missing expected garbling table commitment")
            })?;
            commitments.push(commitment);
        }

        Ok(Some(HeapArray::from_vec(commitments)))
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        Ok(self.challenge_indices.clone())
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.sighashes.clone())
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.deposit_inputs)
    }

    async fn get_withdrawal_input(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.withdrawal_inputs)
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        if deposit_data.deposit_adaptors.is_empty() {
            return Ok(None);
        }

        let mut deposit_adaptors_vec = Vec::new();
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let deposit_adaptor = deposit_data
                .deposit_adaptors
                .get(&(chunk_idx as u8))
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("expected deposit adaptor"))?;
            deposit_adaptors_vec.push(deposit_adaptor);
        }

        Ok(Some(HeapArray::from_vec(deposit_adaptors_vec)))
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        if deposit_data.withdrawal_adaptor_chunks.is_empty() {
            return Ok(None);
        }

        let mut withdrawal_adaptors_vec = Vec::new();
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = deposit_data
                .withdrawal_adaptor_chunks
                .get(&(chunk_idx as u8))
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("expected withdrawal adaptor chunk"))?;
            withdrawal_adaptors_vec.append(&mut chunk.to_vec());
        }

        Ok(Some(HeapArray::from_vec(withdrawal_adaptors_vec)))
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<CompletedSignatures, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        deposit_data
            .completed_sigs
            .clone()
            .ok_or_else(|| DbError::state_inconsistency("expected completed signatures"))
    }
}

impl StateMut for StoredGarblerState {
    async fn put_root_state(&mut self, state: &GarblerState) -> Result<(), Self::Error> {
        self.state = state.clone();
        Ok(())
    }

    async fn put_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_state: &DepositState,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(&deposit_id);
        deposit_data.state = Some(deposit_state.clone());
        Ok(())
    }

    async fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> Result<(), Self::Error> {
        self.input_polynomial_commitments
            .insert(wire_idx as usize, commitments.clone());
        Ok(())
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.output_polynomial_commitment = Some(commitment.clone());
        Ok(())
    }

    async fn put_shares_for_index(
        &mut self,
        index: Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> Result<(), Self::Error> {
        self.input_shares.insert(index.get(), input_shares.clone());
        self.output_shares.insert(index.get(), output_share.clone());
        Ok(())
    }

    async fn put_garbling_table_commitment(
        &mut self,
        index: Index,
        commitments: &GarblingTableCommitment,
    ) -> Result<(), Self::Error> {
        self.gt_commitments.insert(index.get(), *commitments);
        Ok(())
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.challenge_indices = Some(challenge_idxs.clone());
        Ok(())
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.sighashes = Some(sighashes.clone());
        Ok(())
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.deposit_inputs = Some(*inputs);
        Ok(())
    }

    async fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data
            .deposit_adaptors
            .insert(adaptor_chunk.chunk_index, adaptor_chunk.deposit_adaptor);
        deposit_data.withdrawal_adaptor_chunks.insert(
            adaptor_chunk.chunk_index,
            adaptor_chunk.withdrawal_adaptors.clone(),
        );
        Ok(())
    }

    async fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.withdrawal_inputs = Some(*withdrawal_input);
        Ok(())
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.completed_sigs = Some(signatures.clone());
        Ok(())
    }
}

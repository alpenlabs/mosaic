use std::{
    collections::HashMap,
    future::{Future, ready},
    sync::{Arc, Mutex},
};

use futures::Stream;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllAes128Keys, AllConstOneLabels, AllConstZeroLabels,
    AllGarblingTableCommitments, AllOutputLabelCts, AllPublicSValues, ChallengeIndices,
    CircuitInputShares, CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, EvaluationIndices, GarblingTableCommitment, Index, InputPolynomialCommitments,
    InputShares, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares,
    OutputPolynomialCommitment, OutputShares, ReservedInputShares, ReservedSetupInputShares,
    Sighashes, WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalAdaptorsChunk,
    WithdrawalInputs,
    state_machine::{evaluator, garbler},
};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut};

use crate::{error::DbError, evaluator::StoredEvaluatorState, garbler::StoredGarblerState};

type GarblerStateMap = HashMap<PeerId, StoredGarblerState>;
type EvaluatorStateMap = HashMap<PeerId, StoredEvaluatorState>;

/// In-memory storage provider with snapshot read handles and commit-on-drop
/// mutable sessions.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStorageProvider {
    garbler: Arc<Mutex<GarblerStateMap>>,
    evaluator: Arc<Mutex<EvaluatorStateMap>>,
}

impl InMemoryStorageProvider {
    /// Create an empty in-memory provider.
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageProvider for InMemoryStorageProvider {
    type GarblerState = StoredGarblerState;
    type EvaluatorState = StoredEvaluatorState;

    fn garbler_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>> + Send {
        ready(Ok(self
            .garbler
            .lock()
            .expect("garbler map mutex poisoned")
            .get(peer_id)
            .cloned()
            .unwrap_or_default()))
    }

    fn evaluator_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>> + Send {
        ready(Ok(self
            .evaluator
            .lock()
            .expect("evaluator map mutex poisoned")
            .get(peer_id)
            .cloned()
            .unwrap_or_default()))
    }
}

impl StorageProviderMut for InMemoryStorageProvider {
    type GarblerState = InMemoryGarblerSession;
    type EvaluatorState = InMemoryEvaluatorSession;

    fn garbler_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>> {
        let state = self
            .garbler
            .lock()
            .expect("garbler map mutex poisoned")
            .get(peer_id)
            .cloned()
            .unwrap_or_default();
        ready(Ok(InMemoryGarblerSession {
            peer_id: *peer_id,
            inner: state,
            map: Arc::clone(&self.garbler),
        }))
    }

    fn evaluator_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>> {
        let state = self
            .evaluator
            .lock()
            .expect("evaluator map mutex poisoned")
            .get(peer_id)
            .cloned()
            .unwrap_or_default();
        ready(Ok(InMemoryEvaluatorSession {
            peer_id: *peer_id,
            inner: state,
            map: Arc::clone(&self.evaluator),
        }))
    }
}

/// Mutable garbler session that commits writes back to the provider map.
#[derive(Debug, Clone)]
pub struct InMemoryGarblerSession {
    peer_id: PeerId,
    inner: StoredGarblerState,
    map: Arc<Mutex<GarblerStateMap>>,
}

impl Commit for InMemoryGarblerSession {
    type Error = DbError;

    async fn commit(self) -> Result<(), Self::Error> {
        self.map
            .lock()
            .expect("garbler map mutex poisoned")
            .insert(self.peer_id, self.inner);
        Ok(())
    }
}

impl garbler::StateRead for InMemoryGarblerSession {
    type Error = DbError;

    async fn get_root_state(&self) -> Result<Option<garbler::GarblerState>, Self::Error> {
        self.inner.get_root_state().await
    }

    async fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<garbler::DepositState>, Self::Error> {
        self.inner.get_deposit(deposit_id).await
    }

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, garbler::DepositState), Self::Error>> + Send {
        self.inner.stream_all_deposits()
    }

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        self.inner.get_input_polynomial_commitments().await
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        self.inner.get_output_polynomial_commitment().await
    }

    async fn get_input_shares(&self) -> Result<Option<InputShares>, Self::Error> {
        self.inner.get_input_shares().await
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        self.inner.get_output_shares().await
    }

    async fn get_input_shares_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitInputShares>, Self::Error> {
        self.inner.get_input_shares_for_circuit(circuit_idx).await
    }

    async fn get_output_share_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitOutputShare>, Self::Error> {
        self.inner.get_output_share_for_circuit(circuit_idx).await
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        self.inner.get_reserved_input_shares().await
    }

    async fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> Result<Option<GarblingTableCommitment>, Self::Error> {
        self.inner.get_garbling_table_commitment(index).await
    }

    async fn get_all_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        self.inner.get_all_garbling_table_commitments().await
    }

    async fn get_all_aes128_keys(&self) -> Result<Option<AllAes128Keys>, Self::Error> {
        self.inner.get_all_aes128_keys().await
    }

    async fn get_all_public_s_values(&self) -> Result<Option<AllPublicSValues>, Self::Error> {
        self.inner.get_all_public_s_values().await
    }

    async fn get_all_constant_zero_labels(
        &self,
    ) -> Result<Option<AllConstZeroLabels>, Self::Error> {
        self.inner.get_all_constant_zero_labels().await
    }

    async fn get_all_constant_one_labels(&self) -> Result<Option<AllConstOneLabels>, Self::Error> {
        self.inner.get_all_constant_one_labels().await
    }

    async fn get_all_output_label_cts(&self) -> Result<Option<AllOutputLabelCts>, Self::Error> {
        self.inner.get_all_output_label_cts().await
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        self.inner.get_challenge_indices().await
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        self.inner.get_deposit_sighashes(deposit_id).await
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        self.inner.get_deposit_inputs(deposit_id).await
    }

    async fn get_withdrawal_input(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        self.inner.get_withdrawal_input(deposit_id).await
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        self.inner.get_deposit_adaptors(deposit_id).await
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        self.inner.get_withdrawal_adaptors(deposit_id).await
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<CompletedSignatures, Self::Error> {
        self.inner.get_completed_signatures(deposit_id).await
    }
}

impl garbler::StateMut for InMemoryGarblerSession {
    async fn put_root_state(&mut self, state: &garbler::GarblerState) -> Result<(), Self::Error> {
        self.inner.put_root_state(state).await
    }

    async fn put_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_state: &garbler::DepositState,
    ) -> Result<(), Self::Error> {
        self.inner.put_deposit(deposit_id, deposit_state).await
    }

    async fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_input_polynomial_commitments_chunk(wire_idx, commitments)
            .await
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_output_polynomial_commitment(commitment)
            .await
    }

    async fn put_shares_for_index(
        &mut self,
        index: Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_shares_for_index(index, input_shares, output_share)
            .await
    }

    async fn put_garbling_table_commitment(
        &mut self,
        index: Index,
        commitments: &GarblingTableCommitment,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_garbling_table_commitment(index, commitments)
            .await
    }

    async fn put_garbling_table_metadata(
        &mut self,
        index: Index,
        metadata: &garbler::GarblingMetadata,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_garbling_table_metadata(index, metadata)
            .await
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.inner.put_challenge_indices(challenge_idxs).await
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_sighashes_for_deposit(deposit_id, sighashes)
            .await
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        self.inner.put_inputs_for_deposit(deposit_id, inputs).await
    }

    async fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_adaptor_msg_chunk_for_deposit(deposit_id, adaptor_chunk)
            .await
    }

    async fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_withdrawal_input(deposit_id, withdrawal_input)
            .await
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_completed_signatures(deposit_id, signatures)
            .await
    }
}

/// Mutable evaluator session that commits writes back to the provider map.
#[derive(Debug, Clone)]
pub struct InMemoryEvaluatorSession {
    peer_id: PeerId,
    inner: StoredEvaluatorState,
    map: Arc<Mutex<EvaluatorStateMap>>,
}

impl Commit for InMemoryEvaluatorSession {
    type Error = DbError;

    async fn commit(self) -> Result<(), Self::Error> {
        self.map
            .lock()
            .expect("evaluator map mutex poisoned")
            .insert(self.peer_id, self.inner);
        Ok(())
    }
}

impl evaluator::StateRead for InMemoryEvaluatorSession {
    type Error = DbError;

    async fn get_root_state(&self) -> Result<Option<evaluator::EvaluatorState>, Self::Error> {
        self.inner.get_root_state().await
    }

    async fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<evaluator::DepositState>, Self::Error> {
        self.inner.get_deposit(deposit_id).await
    }

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, evaluator::DepositState), Self::Error>> + Send {
        self.inner.stream_all_deposits()
    }

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        self.inner.get_input_polynomial_commitments().await
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        self.inner.get_output_polynomial_commitment().await
    }

    async fn get_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        self.inner.get_garbling_table_commitments().await
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        self.inner.get_challenge_indices().await
    }

    async fn get_opened_input_shares(&self) -> Result<Option<OpenedInputShares>, Self::Error> {
        self.inner.get_opened_input_shares().await
    }

    async fn get_reserved_setup_input_shares(
        &self,
    ) -> Result<Option<ReservedSetupInputShares>, Self::Error> {
        self.inner.get_reserved_setup_input_shares().await
    }

    async fn get_opened_output_shares(&self) -> Result<Option<OpenedOutputShares>, Self::Error> {
        self.inner.get_opened_output_shares().await
    }

    async fn get_opened_garbling_seeds(&self) -> Result<Option<OpenedGarblingSeeds>, Self::Error> {
        self.inner.get_opened_garbling_seeds().await
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        self.inner.get_deposit_sighashes(deposit_id).await
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        self.inner.get_deposit_inputs(deposit_id).await
    }

    async fn get_withdrawal_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        self.inner.get_withdrawal_inputs(deposit_id).await
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        self.inner.get_deposit_adaptors(deposit_id).await
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        self.inner.get_withdrawal_adaptors(deposit_id).await
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<CompletedSignatures>, Self::Error> {
        self.inner.get_completed_signatures(deposit_id).await
    }

    async fn get_aes128_key(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error> {
        self.inner.get_aes128_key(index).await
    }

    async fn get_public_s(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error> {
        self.inner.get_public_s(index).await
    }

    async fn get_constant_zero_label(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error> {
        self.inner.get_constant_zero_label(index).await
    }

    async fn get_constant_one_label(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error> {
        self.inner.get_constant_one_label(index).await
    }

    async fn get_output_label_ct(
        &self,
        index: Index,
    ) -> Result<Option<mosaic_common::Byte32>, Self::Error> {
        self.inner.get_output_label_ct(index).await
    }
}

impl evaluator::StateMut for InMemoryEvaluatorSession {
    async fn put_root_state(
        &mut self,
        state: &evaluator::EvaluatorState,
    ) -> Result<(), Self::Error> {
        self.inner.put_root_state(state).await
    }

    async fn put_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_state: &evaluator::DepositState,
    ) -> Result<(), Self::Error> {
        self.inner.put_deposit(deposit_id, deposit_state).await
    }

    async fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_input_polynomial_commitments_chunk(wire_idx, commitments)
            .await
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_output_polynomial_commitment(commitment)
            .await
    }

    async fn put_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> Result<(), Self::Error> {
        self.inner.put_garbling_table_commitments(commitments).await
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.inner.put_challenge_indices(challenge_idxs).await
    }

    async fn put_opened_input_shares_chunk(
        &mut self,
        opened_ckt_idx: u16,
        input_shares: &CircuitInputShares,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_opened_input_shares_chunk(opened_ckt_idx, input_shares)
            .await
    }

    async fn put_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_reserved_setup_input_shares(reserved_setup_input_shares)
            .await
    }

    async fn put_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_opened_output_shares(opened_output_shares)
            .await
    }

    async fn put_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_opened_garbling_seeds(opened_garbling_seeds)
            .await
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_sighashes_for_deposit(deposit_id, sighashes)
            .await
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        self.inner.put_inputs_for_deposit(deposit_id, inputs).await
    }

    async fn put_deposit_adaptors(
        &mut self,
        deposit_id: &DepositId,
        deposit_adaptors: &DepositAdaptors,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_deposit_adaptors(deposit_id, deposit_adaptors)
            .await
    }

    async fn put_withdrawal_adaptors_chunk(
        &mut self,
        deposit_id: &DepositId,
        chunk_idx: u8,
        withdrawal_adaptors: &WithdrawalAdaptorsChunk,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_withdrawal_adaptors_chunk(deposit_id, chunk_idx, withdrawal_adaptors)
            .await
    }

    async fn put_withdrawal_inputs(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_withdrawal_inputs(deposit_id, withdrawal_input)
            .await
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_completed_signatures(deposit_id, signatures)
            .await
    }

    async fn put_all_aes128_keys(
        &mut self,
        keys: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        self.inner.put_all_aes128_keys(keys).await
    }

    async fn put_all_public_s(
        &mut self,
        values: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        self.inner.put_all_public_s(values).await
    }

    async fn put_all_constant_zero_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        self.inner.put_all_constant_zero_labels(labels).await
    }

    async fn put_all_constant_one_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        self.inner.put_all_constant_one_labels(labels).await
    }

    async fn put_unchallenged_output_label_cts(
        &mut self,
        indices: &EvaluationIndices,
        cts: &mosaic_cac_types::HeapArray<
            mosaic_common::Byte32,
            { mosaic_common::constants::N_EVAL_CIRCUITS },
        >,
    ) -> Result<(), Self::Error> {
        self.inner
            .put_unchallenged_output_label_cts(indices, cts)
            .await
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use mosaic_cac_types::state_machine::{
        evaluator,
        evaluator::StateRead as EvaluatorStateRead,
        garbler,
        garbler::{StateMut as GarblerStateMut, StateRead as GarblerStateRead},
    };
    use mosaic_net_svc_api::PeerId;
    use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut};

    use crate::provider::InMemoryStorageProvider;

    #[test]
    fn mutable_session_commits_to_read_provider() {
        block_on(async {
            let provider = InMemoryStorageProvider::new();
            let peer_id = PeerId::from([42; 32]);

            let initial = provider
                .garbler_state(&peer_id)
                .await
                .expect("acquire garbler read state")
                .get_root_state()
                .await
                .expect("read root state")
                .expect("root state should exist");
            assert!(matches!(initial.step, garbler::Step::Uninit));

            {
                let mut session = provider
                    .garbler_state_mut(&peer_id)
                    .await
                    .expect("acquire garbler mutable state");
                let mut state = session
                    .get_root_state()
                    .await
                    .expect("read mutable session root")
                    .expect("root exists");
                state.step = garbler::Step::SetupComplete;
                session
                    .put_root_state(&state)
                    .await
                    .expect("write mutable root state");
                session.commit().await.expect("commit mutable session");
            }

            let committed = provider
                .garbler_state(&peer_id)
                .await
                .expect("acquire garbler read state")
                .get_root_state()
                .await
                .expect("read committed root state")
                .expect("root exists");
            assert!(matches!(committed.step, garbler::Step::SetupComplete));

            let eval_initial = provider
                .evaluator_state(&peer_id)
                .await
                .expect("acquire evaluator read state")
                .get_root_state()
                .await
                .expect("read evaluator root")
                .expect("root exists");
            assert!(matches!(eval_initial.step, evaluator::Step::Uninit));
        });
    }
}

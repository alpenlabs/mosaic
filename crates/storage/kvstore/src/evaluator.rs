//! Evaluator state storage adapter backed by a generic key-value store.

use std::ops::Bound;

use futures::{Stream, StreamExt, TryFutureExt};
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, EvaluationIndices, HeapArray, OpenedGarblingSeeds,
    OpenedOutputShares, OutputPolynomialCommitment, PolynomialCommitment, ReservedSetupInputShares,
    Sighashes, WideLabelWireAdaptors, WideLabelWirePolynomialCommitments, WideLabelWireShares,
    WideLabelZerothPolynomialCoefficients, WithdrawalAdaptors, WithdrawalInputs,
    state_machine::evaluator::{DepositState, EvaluatorState, StateMut, StateRead},
};
use mosaic_common::{
    Byte32,
    constants::{
        N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
        WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
    },
};
use mosaic_storage_api::Commit;
use mosaic_vs3::Share;

use crate::{
    kvstore::KvStore,
    ops::KvStoreOps,
    row_spec::{
        KVRowSpec,
        common::{
            CircuitIndexKey, CircuitSubChunkKey, DepositDoubleChunkKey, DepositKey,
            ProtocolSingletonKey, WireIndexKey, WireSubChunkKey,
        },
        evaluator::{
            Aes128KeyRowSpec, ChallengeIndicesRowSpec, CompletedSignaturesRowSpec,
            ConstantOneLabelRowSpec, ConstantZeroLabelRowSpec, DepositAdaptorsRowSpec,
            DepositInputsRowSpec, DepositSighashesRowSpec, DepositStateKey, DepositStateRowSpec,
            FaultSecretRowSpec, GarblingTableCommitmentsRowSpec, InputPolyZerothCoeffRowSpec,
            InputPolynomialCommitmentRowSpec, OpenedGarblingSeedsRowSpec, OpenedInputShareRowSpec,
            OpenedOutputSharesRowSpec, OutputLabelCtRowSpec, OutputPolynomialCommitmentRowSpec,
            PublicSRowSpec, ReservedSetupInputSharesRowSpec, RootStateKey, RootStateRowSpec,
            WithdrawalAdaptorRowSpec, WithdrawalInputsRowSpec,
        },
    },
    storage_error::StorageError,
};

/// Evaluator storage implementation backed by a generic [`KvStore`].
#[derive(Debug)]
pub struct KvStoreEvaluator<KV: KvStore> {
    store: KV,
}

impl<KV: KvStore> KvStoreOps for KvStoreEvaluator<KV> {
    type Store = KV;

    fn store(&self) -> &KV {
        &self.store
    }

    fn store_mut(&mut self) -> &mut KV {
        &mut self.store
    }
}

impl<KV: KvStore> KvStoreEvaluator<KV> {
    /// Create an evaluator storage handle.
    pub fn new(store: KV) -> Self {
        Self { store }
    }

    async fn ensure_deposit_exists(&self, deposit_id: &DepositId) -> Result<(), StorageError> {
        if self
            .get_value::<DepositStateRowSpec>(&DepositStateKey::new(*deposit_id))
            .await?
            .is_none()
        {
            return Err(StorageError::unknown_deposit(*deposit_id));
        }
        Ok(())
    }

    async fn get_required_deposit_value<R>(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<R::Value>, StorageError>
    where
        R: KVRowSpec<Key = DepositKey>,
    {
        self.ensure_deposit_exists(deposit_id).await?;
        self.get_value::<R>(&DepositKey::new(*deposit_id)).await
    }

    fn index_to_u16(index: mosaic_vs3::Index) -> Result<u16, StorageError> {
        u16::try_from(index.get())
            .map_err(|_| StorageError::state_inconsistency("index does not fit into u16"))
    }
}

impl<KV: KvStore + Sync> StateRead for KvStoreEvaluator<KV> {
    type Error = StorageError;

    async fn get_root_state(&self) -> Result<Option<EvaluatorState>, Self::Error> {
        self.get_value::<RootStateRowSpec>(&RootStateKey).await
    }

    async fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositState>, Self::Error> {
        self.get_value::<DepositStateRowSpec>(&DepositStateKey::new(*deposit_id))
            .await
    }

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send {
        self.stream_row::<DepositStateRowSpec>(Bound::Unbounded, Bound::Unbounded, false)
            .expect("cannot fail")
            .map(|item| item.map(|(key, value)| (key.deposit_id, value)))
    }

    async fn get_input_polynomial_commitments_for_wire(
        &self,
        wire_idx: u16,
    ) -> Result<Option<WideLabelWirePolynomialCommitments>, Self::Error> {
        self
            .collect_fixed_array_row::<
                InputPolynomialCommitmentRowSpec,
                PolynomialCommitment,
                _,
                WIDE_LABEL_VALUE_COUNT,
            >(
                |pc_idx| WireSubChunkKey::new(wire_idx, pc_idx as u8),
                "missing expected input poly commitment sub-chunk",
            )
            .await
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        self.get_value::<OutputPolynomialCommitmentRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_input_polynomial_zeroth_coefficients(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<WideLabelZerothPolynomialCoefficients>, Self::Error> {
        if range.end > N_INPUT_WIRES {
            return Err(StorageError::invalid_argument(
                "wire index range exceeds N_INPUT_WIRES",
            ));
        }
        let expected_len = range.len();

        let results = self
            .collect_row_values::<InputPolyZerothCoeffRowSpec>(
                Bound::Included(WireIndexKey::new(range.start as u16)),
                Bound::Excluded(WireIndexKey::new(range.end as u16)),
            )
            .await?;

        if results.len() != expected_len {
            return Err(StorageError::state_inconsistency(
                "missing zeroth polynomial coefficients for wire",
            ));
        }
        Ok(results)
    }

    async fn get_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        self.get_value::<GarblingTableCommitmentsRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        self.get_value::<ChallengeIndicesRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_opened_input_shares_for_circuit(
        &self,
        circuit_idx: u16,
    ) -> Result<Option<CircuitInputShares>, Self::Error> {
        self
            .collect_fixed_array_row::<
                OpenedInputShareRowSpec,
                WideLabelWireShares,
                _,
                N_INPUT_WIRES,
            >(
                |wire_idx| CircuitSubChunkKey::new(circuit_idx, wire_idx as u8),
                "missing expected opened input share sub-chunk",
            )
            .await
    }

    async fn get_reserved_setup_input_shares(
        &self,
    ) -> Result<Option<ReservedSetupInputShares>, Self::Error> {
        self.get_value::<ReservedSetupInputSharesRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_opened_output_shares(&self) -> Result<Option<OpenedOutputShares>, Self::Error> {
        self.get_value::<OpenedOutputSharesRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_opened_garbling_seeds(&self) -> Result<Option<OpenedGarblingSeeds>, Self::Error> {
        self.get_value::<OpenedGarblingSeedsRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        self.get_required_deposit_value::<DepositSighashesRowSpec>(deposit_id)
            .await
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        self.get_required_deposit_value::<DepositInputsRowSpec>(deposit_id)
            .await
    }

    async fn get_withdrawal_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        self.get_required_deposit_value::<WithdrawalInputsRowSpec>(deposit_id)
            .await
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        self.get_required_deposit_value::<DepositAdaptorsRowSpec>(deposit_id)
            .await
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        self.ensure_deposit_exists(deposit_id).await?;

        // Check presence via the first sub-chunk.
        if self
            .get_value::<WithdrawalAdaptorRowSpec>(&DepositDoubleChunkKey::new(*deposit_id, 0, 0))
            .await?
            .is_none()
        {
            return Ok(None);
        }

        let mut all_wire_adaptors = Vec::new();
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = self
                .collect_fixed_array_row::<
                    WithdrawalAdaptorRowSpec,
                    WideLabelWireAdaptors,
                    _,
                    WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
                >(
                    |wire_idx| {
                        DepositDoubleChunkKey::new(*deposit_id, chunk_idx as u8, wire_idx as u8)
                    },
                    "missing withdrawal adaptor sub-chunk",
                )
                .await?
                .ok_or_else(|| {
                    StorageError::state_inconsistency("partial withdrawal adaptor sub-chunks")
                })?;
            all_wire_adaptors.extend(chunk.to_vec());
        }

        Ok(Some(HeapArray::from_vec(all_wire_adaptors)))
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<CompletedSignatures>, Self::Error> {
        self.get_required_deposit_value::<CompletedSignaturesRowSpec>(deposit_id)
            .await
    }

    async fn get_aes128_key(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<[u8; 16]>, Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        self.get_value::<Aes128KeyRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_public_s(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<[u8; 16]>, Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        self.get_value::<PublicSRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_constant_zero_label(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<[u8; 16]>, Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        self.get_value::<ConstantZeroLabelRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_constant_one_label(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<[u8; 16]>, Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        self.get_value::<ConstantOneLabelRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_output_label_ct(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<Byte32>, Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        self.get_value::<OutputLabelCtRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_fault_secret_share(&self) -> Result<Option<Share>, Self::Error> {
        self.get_value::<FaultSecretRowSpec>(&ProtocolSingletonKey)
            .await
    }
}

impl<KV: KvStore + Sync> StateMut for KvStoreEvaluator<KV> {
    async fn put_root_state(&mut self, state: &EvaluatorState) -> Result<(), Self::Error> {
        self.put_value::<RootStateRowSpec>(&RootStateKey, state)
            .await
    }

    async fn put_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_state: &DepositState,
    ) -> Result<(), Self::Error> {
        self.put_value::<DepositStateRowSpec>(&DepositStateKey::new(*deposit_id), deposit_state)
            .await
    }

    async fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> Result<(), Self::Error> {
        for (pc_idx, commitment) in commitments.iter().enumerate() {
            self.put_value::<InputPolynomialCommitmentRowSpec>(
                &WireSubChunkKey::new(wire_idx, pc_idx as u8),
                commitment,
            )
            .await?;
        }
        Ok(())
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.put_value::<OutputPolynomialCommitmentRowSpec>(&ProtocolSingletonKey, commitment)
            .await
    }

    async fn put_input_polynomial_commitment_zeroth_coeffs(
        &mut self,
        wire_idx: u16,
        zeroth_coefficients: &WideLabelZerothPolynomialCoefficients,
    ) -> Result<(), Self::Error> {
        self.put_value::<InputPolyZerothCoeffRowSpec>(
            &WireIndexKey::new(wire_idx),
            zeroth_coefficients,
        )
        .await
    }

    async fn put_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> Result<(), Self::Error> {
        self.put_value::<GarblingTableCommitmentsRowSpec>(&ProtocolSingletonKey, commitments)
            .await
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.put_value::<ChallengeIndicesRowSpec>(&ProtocolSingletonKey, challenge_idxs)
            .await
    }

    async fn put_opened_input_shares_chunk(
        &mut self,
        opened_ckt_idx: u16,
        input_shares: &CircuitInputShares,
    ) -> Result<(), Self::Error> {
        for (wire_idx, wire_shares) in input_shares.iter().enumerate() {
            self.put_value::<OpenedInputShareRowSpec>(
                &CircuitSubChunkKey::new(opened_ckt_idx, wire_idx as u8),
                wire_shares,
            )
            .await?;
        }
        Ok(())
    }

    async fn put_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> Result<(), Self::Error> {
        self.put_value::<ReservedSetupInputSharesRowSpec>(
            &ProtocolSingletonKey,
            reserved_setup_input_shares,
        )
        .await
    }

    async fn put_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> Result<(), Self::Error> {
        self.put_value::<OpenedOutputSharesRowSpec>(&ProtocolSingletonKey, opened_output_shares)
            .await
    }

    async fn put_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> Result<(), Self::Error> {
        self.put_value::<OpenedGarblingSeedsRowSpec>(&ProtocolSingletonKey, opened_garbling_seeds)
            .await
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        self.put_value::<DepositSighashesRowSpec>(&DepositKey::new(*deposit_id), sighashes)
            .await
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        self.put_value::<DepositInputsRowSpec>(&DepositKey::new(*deposit_id), inputs)
            .await
    }

    async fn put_deposit_adaptors(
        &mut self,
        deposit_id: &DepositId,
        deposit_adaptors: &DepositAdaptors,
    ) -> Result<(), Self::Error> {
        self.put_value::<DepositAdaptorsRowSpec>(&DepositKey::new(*deposit_id), deposit_adaptors)
            .await
    }

    async fn put_withdrawal_adaptors_chunk(
        &mut self,
        deposit_id: &DepositId,
        chunk_idx: u8,
        withdrawal_adaptors: &mosaic_cac_types::WithdrawalAdaptorsChunk,
    ) -> Result<(), Self::Error> {
        for (wire_idx, wire_adaptors) in withdrawal_adaptors.iter().enumerate() {
            self.put_value::<WithdrawalAdaptorRowSpec>(
                &DepositDoubleChunkKey::new(*deposit_id, chunk_idx, wire_idx as u8),
                wire_adaptors,
            )
            .await?;
        }
        Ok(())
    }

    async fn put_withdrawal_inputs(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        self.put_value::<WithdrawalInputsRowSpec>(&DepositKey::new(*deposit_id), withdrawal_input)
            .await
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        self.put_value::<CompletedSignaturesRowSpec>(&DepositKey::new(*deposit_id), signatures)
            .await
    }

    async fn put_all_aes128_keys(
        &mut self,
        keys: &mosaic_cac_types::HeapArray<[u8; 16], { N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (idx, key) in keys.iter().enumerate() {
            let pos = idx.checked_add(1).unwrap();
            self.put_value::<Aes128KeyRowSpec>(&CircuitIndexKey::new(pos as u16), key)
                .await?;
        }
        Ok(())
    }

    async fn put_all_public_s(
        &mut self,
        values: &mosaic_cac_types::HeapArray<[u8; 16], { N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (idx, value) in values.iter().enumerate() {
            let pos = idx.checked_add(1).unwrap();
            self.put_value::<PublicSRowSpec>(&CircuitIndexKey::new(pos as u16), value)
                .await?;
        }
        Ok(())
    }

    async fn put_all_constant_zero_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (idx, label) in labels.iter().enumerate() {
            let pos = idx.checked_add(1).unwrap();
            self.put_value::<ConstantZeroLabelRowSpec>(&CircuitIndexKey::new(pos as u16), label)
                .await?;
        }
        Ok(())
    }

    async fn put_all_constant_one_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (idx, label) in labels.iter().enumerate() {
            let pos = idx.checked_add(1).unwrap();
            self.put_value::<ConstantOneLabelRowSpec>(&CircuitIndexKey::new(pos as u16), label)
                .await?;
        }
        Ok(())
    }

    async fn put_unchallenged_output_label_cts(
        &mut self,
        indices: &EvaluationIndices,
        cts: &mosaic_cac_types::HeapArray<Byte32, { N_EVAL_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (idx, ct) in indices.iter().zip(cts) {
            let pos = idx.get();
            self.put_value::<OutputLabelCtRowSpec>(&CircuitIndexKey::new(pos as u16), ct)
                .await?;
        }
        Ok(())
    }

    async fn put_fault_secret_share(&mut self, fault: &Share) -> Result<(), Self::Error> {
        self.put_value::<FaultSecretRowSpec>(&ProtocolSingletonKey, fault)
            .await?;

        Ok(())
    }
}

impl<KV> Commit for KvStoreEvaluator<KV>
where
    KV: KvStore + Commit,
    <KV as Commit>::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = StorageError;

    fn commit(self) -> impl core::future::Future<Output = Result<(), Self::Error>> {
        self.store.commit().map_err(StorageError::kvstore)
    }
}

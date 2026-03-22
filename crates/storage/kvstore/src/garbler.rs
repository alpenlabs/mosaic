//! Garbler state storage adapter backed by a generic key-value store.

use std::ops::Bound;

use futures::{Stream, StreamExt, TryFutureExt};
use mosaic_cac_types::{
    AdaptorMsgChunk, AllAes128Keys, AllConstOneLabels, AllConstZeroLabels,
    AllGarblingTableCommitments, AllOutputLabelCts, AllPublicSValues, ChallengeIndices,
    CircuitInputShares, CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, GarblingTableCommitment, HeapArray, OutputPolynomialCommitment, OutputShares,
    PolynomialCommitment, ReservedInputShares, ReservedSetupInputShares, Sighashes,
    WideLabelWireAdaptors, WideLabelWirePolynomialCommitments, WideLabelWireShares,
    WithdrawalAdaptors, WithdrawalInputs,
    state_machine::garbler::{DepositState, GarblerState, GarblingMetadata, StateMut, StateRead},
};
use mosaic_common::constants::{
    N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
    WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_storage_api::Commit;
use mosaic_vs3::Index;

use crate::{
    kvstore::KvStore,
    ops::KvStoreOps,
    row_spec::{
        KVRowSpec,
        common::{
            CircuitIndexKey, CircuitSubChunkKey, DepositChunkKey, DepositDoubleChunkKey,
            DepositKey, ProtocolSingletonKey, WireSubChunkKey,
        },
        garbler::{
            Aes128KeyRowSpec, ChallengeIndicesRowSpec, CompletedSignaturesRowSpec,
            ConstantOneLabelRowSpec, ConstantZeroLabelRowSpec, DepositAdaptorChunkRowSpec,
            DepositInputsRowSpec, DepositSighashesRowSpec, DepositStateKey, DepositStateRowSpec,
            GarblingTableCommitmentRowSpec, InputPolynomialCommitmentRowSpec, InputShareRowSpec,
            OutputLabelCtRowSpec, OutputPolynomialCommitmentRowSpec, OutputShareRowSpec,
            PublicSRowSpec, RootStateKey, RootStateRowSpec, WithdrawalAdaptorRowSpec,
            WithdrawalInputRowSpec,
        },
    },
    storage_error::StorageError,
};

/// Garbler storage implementation backed by a generic [`KvStore`].
#[derive(Debug)]
pub struct KvStoreGarbler<KV: KvStore> {
    store: KV,
}

impl<KV: KvStore> KvStoreOps for KvStoreGarbler<KV> {
    type Store = KV;

    fn store(&self) -> &KV {
        &self.store
    }

    fn store_mut(&mut self) -> &mut KV {
        &mut self.store
    }
}

impl<KV: KvStore> KvStoreGarbler<KV> {
    /// Create a garbler storage handle.
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

    fn index_to_zero_based_u16(index: mosaic_vs3::Index) -> Result<u16, StorageError> {
        let zero_based = index
            .get()
            .checked_sub(1)
            .ok_or(StorageError::UnexpectedZeroIndex)?;
        u16::try_from(zero_based)
            .map_err(|_| StorageError::state_inconsistency("index does not fit into u16"))
    }
}

impl<KV: KvStore + Sync> StateRead for KvStoreGarbler<KV> {
    type Error = StorageError;

    async fn get_root_state(&self) -> Result<Option<GarblerState>, Self::Error> {
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

    async fn get_input_polynomial_commitment_by_wire(
        &self,
        wire_idx: u16,
    ) -> Result<Option<WideLabelWirePolynomialCommitments>, Self::Error> {
        let commitments = self
            .collect_fixed_array_row::<
                InputPolynomialCommitmentRowSpec,
                PolynomialCommitment,
                _,
                WIDE_LABEL_VALUE_COUNT,
            >(
                |pc_idx| WireSubChunkKey::new(wire_idx, pc_idx as u8),
                "missing expected input poly commitment sub-chunk",
            )
            .await?;

        Ok(commitments)
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        self.get_value::<OutputPolynomialCommitmentRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_reserved_setup_input_shares(
        &self,
    ) -> Result<Option<ReservedSetupInputShares>, Self::Error> {
        let Some(root_state) = self.get_root_state().await? else {
            return Ok(None);
        };
        let Some(setup_inputs) = root_state.config.map(|c| c.setup_inputs) else {
            return Ok(None);
        };

        let reserved_ckt_idx = 0;
        let setup_input_start_idx = 0;
        let setup_input_end_idx = 32;

        let all_reserved_setup_shares = self
            .collect_row_values::<InputShareRowSpec>(
                Bound::Included(CircuitSubChunkKey::new(
                    reserved_ckt_idx,
                    setup_input_start_idx,
                )),
                Bound::Excluded(CircuitSubChunkKey::new(
                    reserved_ckt_idx,
                    setup_input_end_idx,
                )),
            )
            .await?;

        if all_reserved_setup_shares.len() != 32 {
            return Err(StorageError::StateInconsistency(
                "missing expected reserved setup shares".into(),
            ));
        }

        let reserved_setup_input_shares = ReservedSetupInputShares::new(|idx| {
            let value = setup_inputs[idx];
            all_reserved_setup_shares[idx][value as usize]
        });

        Ok(Some(reserved_setup_input_shares))
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        self.collect_fixed_array_row::<OutputShareRowSpec, CircuitOutputShare, _, { N_CIRCUITS + 1 }>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected output share",
        )
        .await
    }

    async fn get_input_shares_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitInputShares>, Self::Error> {
        let ckt_idx = Self::index_to_u16(*circuit_idx)?;
        self.collect_fixed_array_row::<InputShareRowSpec, WideLabelWireShares, _, N_INPUT_WIRES>(
            |wire_idx| CircuitSubChunkKey::new(ckt_idx, wire_idx as u8),
            "missing expected input share sub-chunk",
        )
        .await
    }

    async fn get_output_share_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitOutputShare>, Self::Error> {
        let ckt_idx = Self::index_to_u16(*circuit_idx)?;
        self.get_value::<OutputShareRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        self.collect_fixed_array_row::<InputShareRowSpec, WideLabelWireShares, _, N_INPUT_WIRES>(
            |wire_idx| CircuitSubChunkKey::new(0, wire_idx as u8),
            "missing expected reserved input share sub-chunk",
        )
        .await
    }

    async fn get_garbling_table_commitment(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<GarblingTableCommitment>, Self::Error> {
        let ckt_idx = Self::index_to_zero_based_u16(index)?;
        self.get_value::<GarblingTableCommitmentRowSpec>(&CircuitIndexKey::new(ckt_idx))
            .await
    }

    async fn get_all_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        self.collect_fixed_array_row::<
            GarblingTableCommitmentRowSpec,
            GarblingTableCommitment,
            _,
            N_CIRCUITS,
        >(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling table commitment",
        )
        .await
    }

    async fn get_all_aes128_keys(&self) -> Result<Option<AllAes128Keys>, Self::Error> {
        self.collect_fixed_array_row::<Aes128KeyRowSpec, [u8; 16], _, N_CIRCUITS>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling metadata aes128 key",
        )
        .await
    }

    async fn get_all_public_s_values(&self) -> Result<Option<AllPublicSValues>, Self::Error> {
        self.collect_fixed_array_row::<PublicSRowSpec, [u8; 16], _, N_CIRCUITS>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling metadata public S",
        )
        .await
    }

    async fn get_all_constant_zero_labels(
        &self,
    ) -> Result<Option<AllConstZeroLabels>, Self::Error> {
        self.collect_fixed_array_row::<ConstantZeroLabelRowSpec, [u8; 16], _, N_CIRCUITS>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling metadata constant-zero label",
        )
        .await
    }

    async fn get_all_constant_one_labels(&self) -> Result<Option<AllConstOneLabels>, Self::Error> {
        self.collect_fixed_array_row::<ConstantOneLabelRowSpec, [u8; 16], _, N_CIRCUITS>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling metadata constant-one label",
        )
        .await
    }

    async fn get_all_output_label_cts(&self) -> Result<Option<AllOutputLabelCts>, Self::Error> {
        self.collect_fixed_array_row::<OutputLabelCtRowSpec, mosaic_common::Byte32, _, N_CIRCUITS>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected garbling metadata output label ciphertext",
        )
        .await
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        self.get_value::<ChallengeIndicesRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        self.get_required_deposit_value::<DepositSighashesRowSpec>(deposit_id)
            .await
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        self.get_required_deposit_value::<DepositInputsRowSpec>(deposit_id)
            .await
    }

    async fn get_withdrawal_input(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        self.get_required_deposit_value::<WithdrawalInputRowSpec>(deposit_id)
            .await
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        self.ensure_deposit_exists(deposit_id).await?;

        let chunks = self
            .collect_fixed_array_row::<DepositAdaptorChunkRowSpec, mosaic_cac_types::Adaptor, _, N_ADAPTOR_MSG_CHUNKS>(
                |idx| DepositChunkKey::new(*deposit_id, idx as u8),
                "expected deposit adaptor",
            )
            .await?;

        Ok(chunks.map(|v| HeapArray::from_vec(v.to_vec())))
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
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
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<CompletedSignatures>, Self::Error> {
        self.get_required_deposit_value::<CompletedSignaturesRowSpec>(deposit_id)
            .await
    }
}

impl<KV: KvStore + Sync> StateMut for KvStoreGarbler<KV> {
    async fn put_root_state(&mut self, state: &GarblerState) -> Result<(), Self::Error> {
        self.put_value::<RootStateRowSpec>(&RootStateKey, state)
            .await
    }

    async fn put_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_state: &DepositState,
    ) -> Result<(), Self::Error> {
        self.put_value::<DepositStateRowSpec>(&DepositStateKey::new(deposit_id), deposit_state)
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
        commitments: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.put_value::<OutputPolynomialCommitmentRowSpec>(&ProtocolSingletonKey, commitments)
            .await
    }

    async fn put_shares_for_index(
        &mut self,
        index: mosaic_vs3::Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> Result<(), Self::Error> {
        let ckt_idx = Self::index_to_u16(index)?;
        for (wire_idx, wire_shares) in input_shares.iter().enumerate() {
            self.put_value::<InputShareRowSpec>(
                &CircuitSubChunkKey::new(ckt_idx, wire_idx as u8),
                wire_shares,
            )
            .await?;
        }
        self.put_value::<OutputShareRowSpec>(&CircuitIndexKey::new(ckt_idx), output_share)
            .await
    }

    async fn put_garbling_table_commitment(
        &mut self,
        index: mosaic_vs3::Index,
        commitments: &GarblingTableCommitment,
    ) -> Result<(), Self::Error> {
        let ckt_idx = Self::index_to_zero_based_u16(index)?;
        self.put_value::<GarblingTableCommitmentRowSpec>(
            &CircuitIndexKey::new(ckt_idx),
            commitments,
        )
        .await
    }

    async fn put_garbling_table_metadata(
        &mut self,
        index: Index,
        metadata: &GarblingMetadata,
    ) -> Result<(), Self::Error> {
        let ckt_idx = Self::index_to_zero_based_u16(index)?;
        let key = CircuitIndexKey::new(ckt_idx);
        self.put_value::<Aes128KeyRowSpec>(&key, &metadata.aes128_key)
            .await?;
        self.put_value::<PublicSRowSpec>(&key, &metadata.public_s)
            .await?;
        self.put_value::<ConstantZeroLabelRowSpec>(&key, &metadata.constant_zero_label)
            .await?;
        self.put_value::<ConstantOneLabelRowSpec>(&key, &metadata.constant_one_label)
            .await?;
        self.put_value::<OutputLabelCtRowSpec>(&key, &metadata.output_label_ct)
            .await
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.put_value::<ChallengeIndicesRowSpec>(&ProtocolSingletonKey, challenge_idxs)
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

    async fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> Result<(), Self::Error> {
        let key = DepositChunkKey::new(*deposit_id, adaptor_chunk.chunk_index);
        self.put_value::<DepositAdaptorChunkRowSpec>(&key, &adaptor_chunk.deposit_adaptor)
            .await?;
        for (wire_idx, wire_adaptors) in adaptor_chunk.withdrawal_adaptors.iter().enumerate() {
            self.put_value::<WithdrawalAdaptorRowSpec>(
                &DepositDoubleChunkKey::new(*deposit_id, adaptor_chunk.chunk_index, wire_idx as u8),
                wire_adaptors,
            )
            .await?;
        }
        Ok(())
    }

    async fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        self.put_value::<WithdrawalInputRowSpec>(&DepositKey::new(*deposit_id), withdrawal_input)
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
}

impl<KV> Commit for KvStoreGarbler<KV>
where
    KV: KvStore + Commit,
    <KV as Commit>::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = StorageError;

    fn commit(self) -> impl core::future::Future<Output = Result<(), Self::Error>> {
        self.store.commit().map_err(StorageError::kvstore)
    }
}

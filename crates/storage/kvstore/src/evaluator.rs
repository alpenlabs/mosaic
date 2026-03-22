//! Evaluator state storage adapter backed by a generic key-value store.

use std::ops::Bound;

use futures::{Stream, StreamExt, TryFutureExt};
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, EvaluationIndices, HeapArray,
    InputPolynomialCommitments, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares,
    OutputPolynomialCommitment, PolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WideLabelWireAdaptors, WideLabelWirePolynomialCommitments, WideLabelWireShares,
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

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        // Check presence via the first sub-chunk of the first wire.
        if self
            .get_value::<InputPolynomialCommitmentRowSpec>(&WireSubChunkKey::new(0, 0))
            .await?
            .is_none()
        {
            return Ok(None);
        }

        let mut wires = Vec::with_capacity(N_INPUT_WIRES);
        for wire_idx in 0..N_INPUT_WIRES {
            let commitments = self
                .collect_fixed_array_row::<
                    InputPolynomialCommitmentRowSpec,
                    PolynomialCommitment,
                    _,
                    WIDE_LABEL_VALUE_COUNT,
                >(
                    |pc_idx| WireSubChunkKey::new(wire_idx as u16, pc_idx as u8),
                    "missing expected input poly commitment sub-chunk",
                )
                .await?
                .ok_or_else(|| {
                    StorageError::state_inconsistency("partial input polynomial commitments")
                })?;
            wires.push(commitments);
        }
        Ok(Some(HeapArray::from_vec(wires)))
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

    async fn get_opened_input_shares(&self) -> Result<Option<OpenedInputShares>, Self::Error> {
        if !self.row_has_any::<OpenedInputShareRowSpec>().await? {
            return Ok(None);
        }

        let challenge_indices = self
            .get_challenge_indices()
            .await?
            .ok_or_else(|| StorageError::state_inconsistency("expected challenge indices"))?;

        let mut opened_input_shares = Vec::new();
        for index in challenge_indices {
            let ckt_idx = Self::index_to_u16(index)?;
            let input_shares = self
                .collect_fixed_array_row::<
                    OpenedInputShareRowSpec,
                    WideLabelWireShares,
                    _,
                    N_INPUT_WIRES,
                >(
                    |wire_idx| CircuitSubChunkKey::new(ckt_idx, wire_idx as u8),
                    "missing expected opened input share sub-chunk",
                )
                .await?
                .ok_or_else(|| {
                    StorageError::state_inconsistency("expected opened input share")
                })?;
            opened_input_shares.push(input_shares);
        }

        Ok(Some(HeapArray::from_vec(opened_input_shares)))
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
#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use mosaic_cac_types::{
        Adaptor, ChallengeIndices, CompletedSignatures, DepositAdaptors, DepositId, DepositInputs,
        OpenedInputShares, SecretKey, Seed, Sighash, Signature, WideLabelWireAdaptors,
        WideLabelWirePolynomialCommitments, WideLabelWireShares, WithdrawalAdaptors,
        WithdrawalAdaptorsChunk,
        state_machine::evaluator::{DepositStep, Step},
    };
    use mosaic_common::{
        Byte32,
        constants::{
            N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS,
            N_WITHDRAWAL_INPUT_WIRES,
        },
    };
    use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Scalar, Share, gen_mul};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;
    use crate::{btreemap::BTreeMapKvStore, kvstore::test_utils::FdbSizeGuardedKvStore};

    fn dep_id(byte: u8) -> DepositId {
        let mut bytes = [0u8; 32];
        bytes.fill(byte);
        DepositId(Byte32::from(bytes))
    }

    fn deposit_state(seed: u8) -> DepositState {
        let mut sk = [0u8; 32];
        sk.fill(seed);
        DepositState {
            step: DepositStep::default(),
            sk: SecretKey::from_raw_bytes(&sk),
        }
    }

    fn byte32(seed: u8) -> Byte32 {
        Byte32::from([seed; 32])
    }

    fn polynomial_commitment(seed: u64) -> PolynomialCommitment {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let poly = Polynomial::rand(&mut rng);
        poly.commit()
    }

    fn input_polynomial_commitments(seed: u64) -> WideLabelWirePolynomialCommitments {
        let commitment = polynomial_commitment(seed);
        WideLabelWirePolynomialCommitments::new(|_| commitment.clone())
    }

    fn output_polynomial_commitment(seed: u64) -> OutputPolynomialCommitment {
        OutputPolynomialCommitment::from_elem(polynomial_commitment(seed))
    }

    fn challenge_indices() -> ChallengeIndices {
        ChallengeIndices::new(|idx| Index::new(idx + 1).expect("valid challenge index"))
    }

    fn circuit_input_shares(index: Index, seed: u64) -> CircuitInputShares {
        CircuitInputShares::new(|wire| {
            WideLabelWireShares::new(|value| {
                Share::new(index, Scalar::from(seed + wire as u64 + value as u64 + 1))
            })
        })
    }

    fn circuit_output_share(index: Index, seed: u64) -> mosaic_cac_types::CircuitOutputShare {
        Share::new(index, Scalar::from(seed))
    }

    fn reserved_setup_input_shares(seed: u64) -> ReservedSetupInputShares {
        ReservedSetupInputShares::new(|idx| {
            Share::new(Index::reserved(), Scalar::from(seed + idx as u64 + 1))
        })
    }

    fn opened_output_shares(seed: u64) -> OpenedOutputShares {
        OpenedOutputShares::new(|idx| {
            let index = Index::new(idx + 1).expect("valid index");
            circuit_output_share(index, seed + idx as u64)
        })
    }

    fn opened_garbling_seeds(seed: u8) -> OpenedGarblingSeeds {
        OpenedGarblingSeeds::new(|idx| Seed::from([seed.wrapping_add(idx as u8); 32]))
    }

    fn sighashes(seed: u8) -> Sighashes {
        Sighashes::new(|idx| Sighash(byte32(seed.wrapping_add(idx as u8))))
    }

    fn deposit_inputs(seed: u8) -> DepositInputs {
        std::array::from_fn(|idx| seed.wrapping_add(idx as u8))
    }

    fn withdrawal_inputs(seed: u8) -> WithdrawalInputs {
        std::array::from_fn(|idx| seed.wrapping_add(idx as u8))
    }

    fn adaptor(seed: u64) -> Adaptor {
        let scalar = Scalar::from(seed + 1);
        let point = gen_mul(&scalar);
        Adaptor {
            tweaked_s: scalar,
            R_dash_commit: point,
            share_commitment: point,
        }
    }

    fn deposit_adaptors(seed: u64) -> DepositAdaptors {
        DepositAdaptors::new(|idx| adaptor(seed + idx as u64))
    }

    fn withdrawal_adaptors_chunk(seed: u64) -> WithdrawalAdaptorsChunk {
        WithdrawalAdaptorsChunk::new(|wire_idx| {
            WideLabelWireAdaptors::new(|value_idx| {
                adaptor(seed + wire_idx as u64 * 256 + value_idx as u64 + 1)
            })
        })
    }

    fn signature(seed: u8) -> Signature {
        let mut bytes = [0u8; 64];
        bytes[31] = seed.wrapping_add(1);
        bytes[63] = seed.wrapping_add(2);
        Signature::from_bytes(bytes).expect("valid test signature")
    }

    fn completed_signatures(seed: u8) -> CompletedSignatures {
        CompletedSignatures::new(|idx| signature(seed.wrapping_add(idx as u8)))
    }

    fn indexed_value(seed: u8, idx: usize) -> [u8; 16] {
        [seed.wrapping_add(idx as u8); 16]
    }

    #[tokio::test]
    async fn root_and_deposit_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let root = EvaluatorState {
            config: None,
            step: Step::SetupComplete,
        };
        storage.put_root_state(&root).await.expect("put root");
        assert_eq!(
            storage.get_root_state().await.expect("get root"),
            Some(root)
        );

        let deposit_id = dep_id(0xA1);
        let dep_state = deposit_state(7);
        storage
            .put_deposit(&deposit_id, &dep_state)
            .await
            .expect("put deposit");
        assert_eq!(
            storage.get_deposit(&deposit_id).await.expect("get deposit"),
            Some(dep_state)
        );
    }

    #[tokio::test]
    async fn input_polynomial_commitment_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_wire_commitments = input_polynomial_commitments(19);
        for wire_idx in 0..N_INPUT_WIRES {
            storage
                .put_input_polynomial_commitments_chunk(wire_idx as u16, &expected_wire_commitments)
                .await
                .expect("put input commitments chunk");
        }
        let expected_input_commitments =
            InputPolynomialCommitments::new(|_| expected_wire_commitments.clone());
        assert_eq!(
            storage
                .get_input_polynomial_commitments()
                .await
                .expect("get input commitments"),
            Some(expected_input_commitments)
        );
    }

    #[tokio::test]
    async fn input_polynomial_zeroth_coeffs_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_zeroth_coeffs = WideLabelZerothPolynomialCoefficients::new(|idx| {
            gen_mul(&Scalar::from(idx as u64 + 1))
        });

        for wire_idx in 0..N_INPUT_WIRES {
            storage
                .put_input_polynomial_commitment_zeroth_coeffs(
                    wire_idx as u16,
                    &expected_zeroth_coeffs,
                )
                .await
                .expect("put zeroth coeffs");
        }

        // Read back each wire individually
        for wire_idx in 0..N_INPUT_WIRES {
            let got = storage
                .get_value::<InputPolyZerothCoeffRowSpec>(&WireIndexKey::new(wire_idx as u16))
                .await
                .expect("get zeroth coeffs");
            assert_eq!(got, Some(expected_zeroth_coeffs.clone()));
        }

        // Read back via range getter
        let all = storage
            .get_input_polynomial_zeroth_coefficients(0..N_INPUT_WIRES)
            .await
            .expect("get zeroth coeffs range");
        assert_eq!(all.len(), N_INPUT_WIRES);
        for coeffs in &all {
            assert_eq!(coeffs, &expected_zeroth_coeffs);
        }

        // Read back a smaller subset
        let subset = storage
            .get_input_polynomial_zeroth_coefficients(1..3)
            .await
            .expect("get zeroth coeffs subset");
        assert_eq!(subset.len(), 2);
        for coeffs in &subset {
            assert_eq!(coeffs, &expected_zeroth_coeffs);
        }
    }

    #[tokio::test]
    async fn output_polynomial_commitment_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_output_commitment = output_polynomial_commitment(29);
        storage
            .put_output_polynomial_commitment(&expected_output_commitment)
            .await
            .expect("put output commitment");
        assert_eq!(
            storage
                .get_output_polynomial_commitment()
                .await
                .expect("get output commitment"),
            Some(expected_output_commitment)
        );
    }

    #[tokio::test]
    async fn garbling_table_commitments_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_gt_commitments =
            AllGarblingTableCommitments::new(|idx| byte32(0x50u8.wrapping_add(idx as u8)));
        storage
            .put_garbling_table_commitments(&expected_gt_commitments)
            .await
            .expect("put gt commitments");
        assert_eq!(
            storage
                .get_garbling_table_commitments()
                .await
                .expect("get gt commitments"),
            Some(expected_gt_commitments)
        );
    }

    #[tokio::test]
    async fn challenge_indices_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_challenge_indices = challenge_indices();
        storage
            .put_challenge_indices(&expected_challenge_indices)
            .await
            .expect("put challenge indices");
        assert_eq!(
            storage
                .get_challenge_indices()
                .await
                .expect("get challenge indices"),
            Some(expected_challenge_indices)
        );
    }

    #[tokio::test]
    async fn opened_input_shares_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_challenge_indices = challenge_indices();
        storage
            .put_challenge_indices(&expected_challenge_indices)
            .await
            .expect("put challenge indices");

        let mut expected_opened_input_shares = Vec::with_capacity(N_OPEN_CIRCUITS);
        for (i, index) in expected_challenge_indices.iter().enumerate() {
            let shares = circuit_input_shares(*index, 10_000 + i as u64);
            storage
                .put_opened_input_shares_chunk(index.get() as u16, &shares)
                .await
                .expect("put opened input shares");
            expected_opened_input_shares.push(shares);
        }
        let expected_opened_input_shares =
            OpenedInputShares::from_vec(expected_opened_input_shares);
        assert_eq!(
            storage
                .get_opened_input_shares()
                .await
                .expect("get opened input shares"),
            Some(expected_opened_input_shares)
        );
    }

    #[tokio::test]
    async fn reserved_setup_input_shares_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_reserved_setup = reserved_setup_input_shares(20_000);
        storage
            .put_reserved_setup_input_shares(&expected_reserved_setup)
            .await
            .expect("put reserved setup input shares");
        assert_eq!(
            storage
                .get_reserved_setup_input_shares()
                .await
                .expect("get reserved setup input shares"),
            Some(expected_reserved_setup)
        );
    }

    #[tokio::test]
    async fn opened_output_shares_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_opened_output = opened_output_shares(30_000);
        storage
            .put_opened_output_shares(&expected_opened_output)
            .await
            .expect("put opened output shares");
        assert_eq!(
            storage
                .get_opened_output_shares()
                .await
                .expect("get opened output shares"),
            Some(expected_opened_output)
        );
    }

    #[tokio::test]
    async fn opened_garbling_seeds_roundtrip() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let expected_opened_seeds = opened_garbling_seeds(0x61);
        storage
            .put_opened_garbling_seeds(&expected_opened_seeds)
            .await
            .expect("put opened garbling seeds");
        assert_eq!(
            storage
                .get_opened_garbling_seeds()
                .await
                .expect("get opened garbling seeds"),
            Some(expected_opened_seeds)
        );
    }

    #[tokio::test]
    async fn deposit_scoped_roundtrip_all_pairs() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let deposit_id = dep_id(0xC1);
        storage
            .put_deposit(&deposit_id, &deposit_state(9))
            .await
            .expect("put deposit");

        let expected_sighashes = sighashes(0x31);
        storage
            .put_sighashes_for_deposit(&deposit_id, &expected_sighashes)
            .await
            .expect("put sighashes");
        assert_eq!(
            storage
                .get_deposit_sighashes(&deposit_id)
                .await
                .expect("get sighashes"),
            Some(expected_sighashes)
        );

        let expected_deposit_inputs = deposit_inputs(0x41);
        storage
            .put_inputs_for_deposit(&deposit_id, &expected_deposit_inputs)
            .await
            .expect("put deposit inputs");
        assert_eq!(
            storage
                .get_deposit_inputs(&deposit_id)
                .await
                .expect("get deposit inputs"),
            Some(expected_deposit_inputs)
        );

        let expected_withdrawal_inputs = withdrawal_inputs(0x51);
        storage
            .put_withdrawal_inputs(&deposit_id, &expected_withdrawal_inputs)
            .await
            .expect("put withdrawal inputs");
        assert_eq!(
            storage
                .get_withdrawal_inputs(&deposit_id)
                .await
                .expect("get withdrawal inputs"),
            Some(expected_withdrawal_inputs)
        );

        let expected_deposit_adaptors = deposit_adaptors(0x1000);
        storage
            .put_deposit_adaptors(&deposit_id, &expected_deposit_adaptors)
            .await
            .expect("put deposit adaptors");
        assert_eq!(
            storage
                .get_deposit_adaptors(&deposit_id)
                .await
                .expect("get deposit adaptors"),
            Some(expected_deposit_adaptors)
        );

        let mut expected_withdrawal_adaptors = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = withdrawal_adaptors_chunk(0x2000 + chunk_idx as u64);
            storage
                .put_withdrawal_adaptors_chunk(&deposit_id, chunk_idx as u8, &chunk)
                .await
                .expect("put withdrawal adaptor chunk");
            expected_withdrawal_adaptors.extend(chunk.to_vec());
        }
        assert_eq!(
            storage
                .get_withdrawal_adaptors(&deposit_id)
                .await
                .expect("get withdrawal adaptors"),
            Some(WithdrawalAdaptors::from_vec(expected_withdrawal_adaptors))
        );

        let expected_completed_signatures = completed_signatures(0x61);
        storage
            .put_completed_signatures(&deposit_id, &expected_completed_signatures)
            .await
            .expect("put completed signatures");
        assert_eq!(
            storage
                .get_completed_signatures(&deposit_id)
                .await
                .expect("get completed signatures"),
            Some(expected_completed_signatures)
        );
    }

    #[tokio::test]
    async fn metadata_roundtrip_all_pairs() {
        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        let all_aes128_keys = mosaic_cac_types::HeapArray::new(|idx| indexed_value(0x01, idx));
        let all_public_s = mosaic_cac_types::HeapArray::new(|idx| indexed_value(0x11, idx));
        let all_constant_zero_labels =
            mosaic_cac_types::HeapArray::new(|idx| indexed_value(0x21, idx));
        let all_constant_one_labels =
            mosaic_cac_types::HeapArray::new(|idx| indexed_value(0x31, idx));
        let output_label_cts =
            mosaic_cac_types::HeapArray::new(|idx| byte32(0x41u8.wrapping_add(idx as u8)));
        let indices = std::array::from_fn(|idx| {
            if idx == 0 {
                Index::reserved()
            } else {
                Index::new(idx).expect("valid index")
            }
        });
        storage
            .put_all_aes128_keys(&all_aes128_keys)
            .await
            .expect("put aes128 keys");
        storage
            .put_all_public_s(&all_public_s)
            .await
            .expect("put public s");
        storage
            .put_all_constant_zero_labels(&all_constant_zero_labels)
            .await
            .expect("put constant zero labels");
        storage
            .put_all_constant_one_labels(&all_constant_one_labels)
            .await
            .expect("put constant one labels");
        storage
            .put_unchallenged_output_label_cts(&indices, &output_label_cts)
            .await
            .expect("put output label cts");

        for idx in 0..N_CIRCUITS {
            let index = Index::new(idx + 1).expect("valid index");
            assert_eq!(
                storage.get_aes128_key(index).await.expect("get aes key"),
                Some(all_aes128_keys[idx])
            );
            assert_eq!(
                storage.get_public_s(index).await.expect("get public s"),
                Some(all_public_s[idx])
            );
            assert_eq!(
                storage
                    .get_constant_zero_label(index)
                    .await
                    .expect("get constant zero label"),
                Some(all_constant_zero_labels[idx])
            );
            assert_eq!(
                storage
                    .get_constant_one_label(index)
                    .await
                    .expect("get constant one label"),
                Some(all_constant_one_labels[idx])
            );
        }

        for idx in 0..N_EVAL_CIRCUITS {
            let index = if idx == 0 {
                Index::reserved()
            } else {
                Index::new(idx).expect("valid index")
            };
            assert_eq!(
                storage
                    .get_output_label_ct(index)
                    .await
                    .expect("get output label ct"),
                Some(output_label_cts[idx])
            );
        }
    }

    #[tokio::test]
    async fn stream_all_deposits_scopes_to_deposit_state_row() {
        let dep1_id = dep_id(0x01);
        let dep2_id = dep_id(0x02);
        let dep1 = deposit_state(1);
        let dep2 = deposit_state(2);

        let mut storage = KvStoreEvaluator::new(FdbSizeGuardedKvStore(BTreeMapKvStore::new()));

        storage.put_deposit(&dep1_id, &dep1).await.unwrap();
        storage.put_deposit(&dep2_id, &dep2).await.unwrap();

        // also write a root state; stream_all_deposits must not return it
        storage
            .put_root_state(&EvaluatorState {
                config: None,
                step: Step::SetupComplete,
            })
            .await
            .unwrap();

        let mut got = storage
            .stream_all_deposits()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|item| item.expect("stream item"))
            .collect::<Vec<_>>();
        got.sort_by_key(|(id, _)| id.0);

        assert_eq!(got, vec![(dep1_id, dep1), (dep2_id, dep2)]);
    }
}

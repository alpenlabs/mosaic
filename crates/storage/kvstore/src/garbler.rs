//! Garbler state storage adapter backed by a generic key-value store.

use std::ops::Bound;

use futures::{Stream, StreamExt, stream};
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares,
    CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId, DepositInputs,
    GarblingTableCommitment, HeapArray, InputPolynomialCommitments, InputShares,
    OutputPolynomialCommitment, OutputShares, ReservedInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalInputs,
    state_machine::{
        StateMachineId,
        garbler::{DepositState, GarblerState, StateMut, StateRead},
    },
};
use mosaic_common::constants::{N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_INPUT_WIRES};

use crate::{
    keyspace,
    kvstore::KvStore,
    row_spec::{
        KVRowSpec, SerializableValue,
        common::{
            CircuitIndexKey, DepositChunkKey, DepositKey, ProtocolSingletonKey, WireIndexKey,
        },
        garbler::{
            ChallengeIndicesRowSpec, CompletedSignaturesRowSpec, DepositAdaptorChunkRowSpec,
            DepositInputsRowSpec, DepositSighashesRowSpec, DepositStateKey, DepositStateRowSpec,
            GarblingTableCommitmentRowSpec, InputPolynomialCommitmentChunkRowSpec,
            InputShareRowSpec, OutputPolynomialCommitmentRowSpec, OutputShareRowSpec, RootStateKey,
            RootStateRowSpec, WithdrawalAdaptorChunkRowSpec, WithdrawalInputRowSpec,
        },
    },
    storage_error::StorageError,
};

/// Garbler storage implementation backed by a generic [`KvStore`].
#[derive(Debug)]
pub struct KvStoreGarbler<KV: KvStore> {
    statemachine_id: StateMachineId,
    store: KV,
}

impl<KV: KvStore> KvStoreGarbler<KV> {
    /// Create a garbler storage handle bound to one state machine.
    pub fn new(statemachine_id: StateMachineId, store: KV) -> Self {
        Self {
            statemachine_id,
            store,
        }
    }

    fn bound_vec_to_slice(bound: &Bound<Vec<u8>>) -> Bound<&[u8]> {
        match bound {
            Bound::Included(bytes) => Bound::Included(bytes.as_slice()),
            Bound::Excluded(bytes) => Bound::Excluded(bytes.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        }
    }

    async fn get_value<R: KVRowSpec>(
        &self,
        key: &R::Key,
    ) -> Result<Option<R::Value>, StorageError> {
        let key_bytes =
            keyspace::full_key::<R>(self.statemachine_id, key).map_err(StorageError::key_pack)?;
        let Some(value_bytes) = self
            .store
            .get(key_bytes.as_ref())
            .await
            .map_err(StorageError::kvstore)?
        else {
            return Ok(None);
        };
        <R::Value as SerializableValue>::deserialize(&value_bytes)
            .map_err(StorageError::value_deserialize)
            .map(Some)
    }

    async fn put_value<R: KVRowSpec>(
        &mut self,
        key: &R::Key,
        value: &R::Value,
    ) -> Result<(), StorageError> {
        let key_bytes =
            keyspace::full_key::<R>(self.statemachine_id, key).map_err(StorageError::key_pack)?;
        let value_bytes = value.serialize().map_err(StorageError::value_serialize)?;

        self.store
            .set(key_bytes.as_ref(), value_bytes.as_ref())
            .await
            .map_err(StorageError::kvstore)
    }

    fn stream_row<R: KVRowSpec>(
        &self,
    ) -> impl Stream<Item = Result<(R::Key, R::Value), StorageError>> + Send + '_ {
        let statemachine_id = self.statemachine_id;
        let row_prefix = keyspace::row_prefix::<R>(statemachine_id);
        let (start, end) = keyspace::prefix_range(&row_prefix);
        let kv_stream = self.store.range(
            Self::bound_vec_to_slice(&start),
            Self::bound_vec_to_slice(&end),
            false,
        );

        stream::try_unfold(kv_stream, move |current| async move {
            match current.next().await.map_err(StorageError::kvstore)? {
                Some((pair, next)) => {
                    let key = keyspace::split_row_key::<R>(statemachine_id, &pair.key)
                        .map_err(StorageError::key_unpack)?;
                    let value = <R::Value as SerializableValue>::deserialize(&pair.value)
                        .map_err(StorageError::value_deserialize)?;
                    Ok(Some(((key, value), next)))
                }
                None => Ok(None),
            }
        })
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

    async fn collect_fixed_array_row<R, T, F, const N: usize>(
        &self,
        mut key_for: F,
        missing_message: &'static str,
    ) -> Result<Option<HeapArray<T, N>>, StorageError>
    where
        R: KVRowSpec<Value = T>,
        F: FnMut(usize) -> R::Key,
    {
        let mut values = Vec::with_capacity(N);
        let mut any_present = false;
        let mut any_missing = false;

        for idx in 0..N {
            match self.get_value::<R>(&key_for(idx)).await? {
                Some(value) => {
                    any_present = true;
                    values.push(value);
                }
                None => {
                    any_missing = true;
                }
            }
        }

        if !any_present {
            return Ok(None);
        }
        if any_missing {
            return Err(StorageError::state_inconsistency(missing_message));
        }

        Ok(Some(HeapArray::from_vec(values)))
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

    #[cfg(test)]
    fn full_key<R: KVRowSpec>(&self, key: &R::Key) -> Result<Vec<u8>, StorageError> {
        keyspace::full_key::<R>(self.statemachine_id, key).map_err(StorageError::key_pack)
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
        self.stream_row::<DepositStateRowSpec>()
            .map(|item| item.map(|(key, value)| (key.deposit_id, value)))
    }

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        self.collect_fixed_array_row::<
            InputPolynomialCommitmentChunkRowSpec,
            WideLabelWirePolynomialCommitments,
            _,
            N_INPUT_WIRES,
        >(
            |idx| WireIndexKey::new(idx as u16),
            "missing expected input commitment",
        )
        .await
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        self.get_value::<OutputPolynomialCommitmentRowSpec>(&ProtocolSingletonKey)
            .await
    }

    async fn get_input_shares(&self) -> Result<Option<InputShares>, Self::Error> {
        self.collect_fixed_array_row::<InputShareRowSpec, CircuitInputShares, _, { N_CIRCUITS + 1 }>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected input share",
        )
        .await
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        self.collect_fixed_array_row::<OutputShareRowSpec, CircuitOutputShare, _, { N_CIRCUITS + 1 }>(
            |idx| CircuitIndexKey::new(idx as u16),
            "missing expected output share",
        )
        .await
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        self.get_value::<InputShareRowSpec>(&CircuitIndexKey::new(0))
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

        let chunks = self
            .collect_fixed_array_row::<
                WithdrawalAdaptorChunkRowSpec,
                mosaic_cac_types::WithdrawalAdaptorsChunk,
                _,
                N_ADAPTOR_MSG_CHUNKS,
            >(
                |idx| DepositChunkKey::new(*deposit_id, idx as u8),
                "expected withdrawal adaptor chunk",
            )
            .await?;

        let Some(chunks) = chunks else {
            return Ok(None);
        };

        let mut withdrawal_adaptors = Vec::new();
        for chunk in chunks {
            withdrawal_adaptors.extend(chunk.to_vec());
        }

        Ok(Some(HeapArray::from_vec(withdrawal_adaptors)))
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<CompletedSignatures, Self::Error> {
        let signatures = self
            .get_required_deposit_value::<CompletedSignaturesRowSpec>(deposit_id)
            .await?;
        signatures.ok_or_else(|| StorageError::state_inconsistency("expected completed signatures"))
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
        self.put_value::<InputPolynomialCommitmentChunkRowSpec>(
            &WireIndexKey::new(wire_idx),
            commitments,
        )
        .await
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
        self.put_value::<InputShareRowSpec>(&CircuitIndexKey::new(ckt_idx), input_shares)
            .await?;
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
        self.put_value::<WithdrawalAdaptorChunkRowSpec>(&key, &adaptor_chunk.withdrawal_adaptors)
            .await
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

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use mosaic_cac_types::{
        Adaptor, AdaptorMsgChunk, ChallengeIndices, CompletedSignatures, DepositAdaptors,
        DepositId, DepositInputs, InputPolynomialCommitments, SecretKey, Sighash, Signature,
        WideLabelWireAdaptors, WideLabelWirePolynomialCommitments, WideLabelWireShares,
        WithdrawalAdaptors, WithdrawalAdaptorsChunk, WithdrawalInputs,
        state_machine::garbler::DepositStep,
    };
    use mosaic_common::{
        Byte32,
        constants::{
            N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES,
            N_WITHDRAWAL_INPUT_WIRES,
        },
    };
    use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Scalar, Share, gen_mul};
    use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

    use super::*;
    use crate::{btreemap::BTreeMapKvStore, row_spec::garbler::DepositStateRowSpec};

    fn sm_id(byte: u8) -> StateMachineId {
        StateMachineId::from([byte; 32])
    }

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
            pk: SecretKey::from_raw_bytes(&sk).to_pubkey(),
        }
    }

    fn byte32(seed: u8) -> Byte32 {
        Byte32::from([seed; 32])
    }

    fn polynomial_commitment(seed: u64) -> PolynomialCommitment {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let poly = Polynomial::rand(&mut rng);
        poly.commit()
    }

    fn input_polymonial_commitments(seed: u64) -> WideLabelWirePolynomialCommitments {
        let commitment = polynomial_commitment(seed);
        WideLabelWirePolynomialCommitments::new(|_| commitment.clone())
    }

    fn output_polynomial_commitment(seed: u64) -> OutputPolynomialCommitment {
        OutputPolynomialCommitment::from_elem(polynomial_commitment(seed))
    }

    fn circuit_input_shares(index: Index, seed: u64) -> CircuitInputShares {
        CircuitInputShares::new(|wire| {
            WideLabelWireShares::new(|value| {
                Share::new(index, Scalar::from(seed + wire as u64 + value as u64 + 1))
            })
        })
    }

    fn circuit_output_share(index: Index, seed: u64) -> CircuitOutputShare {
        Share::new(index, Scalar::from(seed))
    }

    fn challenge_indices() -> ChallengeIndices {
        ChallengeIndices::new(|idx| Index::new(idx + 1).expect("valid challenge index"))
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

    fn adaptor_msg_chunk(chunk_index: u8, seed: u64) -> AdaptorMsgChunk {
        AdaptorMsgChunk {
            chunk_index,
            deposit_adaptor: adaptor(seed + chunk_index as u64),
            withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|wire_idx| {
                WideLabelWireAdaptors::new(|value_idx| {
                    adaptor(
                        seed + chunk_index as u64 + wire_idx as u64 * 256 + value_idx as u64 + 1,
                    )
                })
            }),
        }
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

    #[tokio::test]
    async fn root_and_deposit_roundtrip() {
        let sm = sm_id(0x11);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

        let root = GarblerState::default();
        storage.put_root_state(&root).await.expect("put root");
        assert_eq!(
            storage.get_root_state().await.expect("get root"),
            Some(root)
        );

        let dep_id = dep_id(0xA1);
        let dep_state = deposit_state(7);
        storage
            .put_deposit(dep_id, &dep_state)
            .await
            .expect("put deposit");
        assert_eq!(
            storage.get_deposit(&dep_id).await.expect("get deposit"),
            Some(dep_state)
        );
    }

    #[tokio::test]
    async fn input_polynomial_commitment_roundtrip() {
        let sm = sm_id(0x66);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

        let expected_wire_commitments = input_polymonial_commitments(19);

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
    async fn output_polynomial_commitment_roundtrip() {
        let sm = sm_id(0x66);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

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
    async fn shares_roundtrip() {
        let sm = sm_id(0x66);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());
        let mut expected_input_shares = Vec::with_capacity(N_CIRCUITS + 1);
        let mut expected_output_shares = Vec::with_capacity(N_CIRCUITS + 1);
        for ckt_idx in 0..=N_CIRCUITS {
            let index = if ckt_idx == 0 {
                Index::reserved()
            } else {
                Index::new(ckt_idx).expect("valid index")
            };
            let input_shares = circuit_input_shares(index, 10_000 + ckt_idx as u64);
            let output_share = circuit_output_share(index, 20_000 + ckt_idx as u64);
            storage
                .put_shares_for_index(index, &input_shares, &output_share)
                .await
                .expect("put shares");
            expected_input_shares.push(input_shares);
            expected_output_shares.push(output_share);
        }
        let expected_input_shares = InputShares::from_vec(expected_input_shares);
        let expected_output_shares = OutputShares::from_vec(expected_output_shares);
        let expected_reserved = expected_input_shares[0].clone();

        assert_eq!(
            storage.get_input_shares().await.expect("get input shares"),
            Some(expected_input_shares)
        );
        assert_eq!(
            storage
                .get_output_shares()
                .await
                .expect("get output shares"),
            Some(expected_output_shares)
        );
        assert_eq!(
            storage
                .get_reserved_input_shares()
                .await
                .expect("get reserved input shares"),
            Some(expected_reserved)
        );
    }

    #[tokio::test]
    async fn gt_commitment_roundtrip() {
        let sm = sm_id(0x66);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

        let mut expected_gt_commitments = Vec::with_capacity(N_CIRCUITS);
        for ckt_idx in 1..=N_CIRCUITS {
            let index = Index::new(ckt_idx).expect("valid index");
            let commitment = byte32(ckt_idx as u8);
            storage
                .put_garbling_table_commitment(index, &commitment)
                .await
                .expect("put garbling table commitment");
            expected_gt_commitments.push(commitment);
        }
        let expected_all_gt_commitments =
            AllGarblingTableCommitments::from_vec(expected_gt_commitments);
        assert_eq!(
            storage
                .get_garbling_table_commitment(Index::new(7).expect("valid index"))
                .await
                .expect("get garbling table commitment"),
            Some(byte32(7))
        );
        assert_eq!(
            storage
                .get_all_garbling_table_commitments()
                .await
                .expect("get all garbling table commitments"),
            Some(expected_all_gt_commitments)
        );
    }

    #[tokio::test]
    async fn protocol_state_roundtrip_all_pairs() {
        let sm = sm_id(0x66);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

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
    async fn deposit_scoped_roundtrip_all_pairs() {
        let sm = sm_id(0x77);
        let mut storage = KvStoreGarbler::new(sm, BTreeMapKvStore::new());

        let deposit_id = dep_id(0xC1);
        storage
            .put_deposit(deposit_id, &deposit_state(9))
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
            .put_withdrawal_input(&deposit_id, &expected_withdrawal_inputs)
            .await
            .expect("put withdrawal input");
        assert_eq!(
            storage
                .get_withdrawal_input(&deposit_id)
                .await
                .expect("get withdrawal input"),
            Some(expected_withdrawal_inputs)
        );

        let mut expected_deposit_adaptors = Vec::with_capacity(N_DEPOSIT_INPUT_WIRES);
        let mut expected_withdrawal_adaptors = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = adaptor_msg_chunk(chunk_idx as u8, 0x1000);
            storage
                .put_adaptor_msg_chunk_for_deposit(&deposit_id, &chunk)
                .await
                .expect("put adaptor chunk");
            expected_deposit_adaptors.push(chunk.deposit_adaptor);
            expected_withdrawal_adaptors.extend(chunk.withdrawal_adaptors.to_vec());
        }

        assert_eq!(
            storage
                .get_deposit_adaptors(&deposit_id)
                .await
                .expect("get deposit adaptors"),
            Some(DepositAdaptors::from_vec(expected_deposit_adaptors))
        );
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
            expected_completed_signatures
        );
    }

    #[tokio::test]
    async fn stream_all_deposits_scopes_to_row_and_state_machine() {
        let sm = sm_id(0x22);
        let other_sm = sm_id(0x33);

        let dep1_id = dep_id(0x01);
        let dep2_id = dep_id(0x02);
        let dep3_id = dep_id(0x03);
        let dep1 = deposit_state(1);
        let dep2 = deposit_state(2);
        let dep3 = deposit_state(3);

        let kv = BTreeMapKvStore::new();

        let mut storage = KvStoreGarbler::new(sm, kv.clone());
        let mut other_storage = KvStoreGarbler::new(other_sm, kv.clone());

        storage.put_deposit(dep1_id, &dep1).await.unwrap();
        storage.put_deposit(dep2_id, &dep2).await.unwrap();
        other_storage.put_deposit(dep3_id, &dep3).await.unwrap();

        // ensure that all keys are in the same kvstore
        let k1 = storage
            .full_key::<DepositStateRowSpec>(&DepositStateKey::new(dep1_id))
            .unwrap();
        let k2 = storage
            .full_key::<DepositStateRowSpec>(&DepositStateKey::new(dep2_id))
            .unwrap();
        let k3 = other_storage
            .full_key::<DepositStateRowSpec>(&DepositStateKey::new(dep3_id))
            .unwrap();

        assert!(kv.get(&k1).await.unwrap().is_some());
        assert!(kv.get(&k2).await.unwrap().is_some());
        assert!(kv.get(&k3).await.unwrap().is_some());

        // ensure stream only returns deposits for correct statemachine
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

//! Garbler state storage adapter backed by a generic key-value store.

use std::{error::Error, ops::Bound};

use futures::{Stream, StreamExt, stream};
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares,
    CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId, DepositInputs,
    GarblingTableCommitment, InputPolynomialCommitments, InputShares, OutputPolynomialCommitment,
    OutputShares, ReservedInputShares, Sighashes, WideLabelWirePolynomialCommitments,
    WithdrawalAdaptors, WithdrawalInputs,
    state_machine::{
        StateMachineId,
        garbler::{DepositState, GarblerState, StateMut, StateRead},
    },
};
use thiserror::Error;

use crate::{
    keyspace,
    kvstore::KvStore,
    row_spec::{
        KVRowSpec, SerializableValue,
        garbler::{DepositStateKey, DepositStateRowSpec, RootStateKey, RootStateRowSpec},
    },
};

#[derive(Debug, Error)]
/// Errors returned by [`KvStoreGarbler`].
pub enum StorageError {
    /// Failed to pack a typed key into raw bytes.
    #[error("keypack: {0}")]
    KeyPack(Box<dyn Error + Send + Sync>),
    /// Failed to unpack a raw key into a typed key.
    #[error("keyunpack: {0}")]
    KeyUnpack(Box<dyn Error + Send + Sync>),
    /// Failed to serialize a typed value into bytes.
    #[error("valueserialize: {0}")]
    ValueSerialize(Box<dyn Error + Send + Sync>),
    /// Failed to deserialize bytes into a typed value.
    #[error("valuedeserialize: {0}")]
    ValueDeserialize(Box<dyn Error + Send + Sync>),
    /// Underlying KV backend error.
    #[error("kvstore: {0}")]
    KvStore(Box<dyn Error + Send + Sync>),
}

impl StorageError {
    fn key_pack(err: impl Error + Send + Sync + 'static) -> Self {
        Self::KeyPack(Box::new(err))
    }
    fn key_unpack(err: impl Error + Send + Sync + 'static) -> Self {
        Self::KeyUnpack(Box::new(err))
    }

    fn value_serialize(err: impl Error + Send + Sync + 'static) -> Self {
        Self::ValueSerialize(Box::new(err))
    }
    fn value_deserialize(err: impl Error + Send + Sync + 'static) -> Self {
        Self::ValueDeserialize(Box::new(err))
    }

    fn kvstore(err: impl Error + Send + Sync + 'static) -> Self {
        Self::KvStore(Box::new(err))
    }
}

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
}

#[expect(unused_variables, reason = "wip")]
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
        todo!()
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        todo!()
    }

    async fn get_input_shares(&self) -> Result<Option<InputShares>, Self::Error> {
        todo!()
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        todo!()
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        todo!()
    }

    async fn get_garbling_table_commitment(
        &self,
        index: mosaic_vs3::Index,
    ) -> Result<Option<GarblingTableCommitment>, Self::Error> {
        todo!()
    }

    async fn get_all_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        todo!()
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        todo!()
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        todo!()
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        todo!()
    }

    async fn get_withdrawal_input(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        todo!()
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        todo!()
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        todo!()
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &mosaic_cac_types::DepositId,
    ) -> Result<CompletedSignatures, Self::Error> {
        todo!()
    }
}

#[expect(unused_variables, reason = "wip")]
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
        todo!()
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitments: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_shares_for_index(
        &mut self,
        index: mosaic_vs3::Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_garbling_table_commitment(
        &mut self,
        index: mosaic_vs3::Index,
        commitments: &GarblingTableCommitment,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt as _, pin_mut};
    use mosaic_cac_types::{DepositId, SecretKey, state_machine::garbler::DepositStep};
    use mosaic_common::Byte32;

    use super::*;
    use crate::{
        btreemap::BTreeMapKvStore,
        row_spec::garbler::{DepositStateRowSpec, RootStateKey, RootStateRowSpec},
    };

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

    #[test]
    fn root_and_deposit_roundtrip() {
        futures::executor::block_on(async {
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
        });
    }

    #[test]
    fn stream_all_deposits_scopes_to_row_and_state_machine() {
        futures::executor::block_on(async {
            let sm = sm_id(0x22);
            let other_sm = sm_id(0x33);

            let dep1_id = dep_id(0x01);
            let dep2_id = dep_id(0x02);
            let dep3_id = dep_id(0x03);
            let dep1 = deposit_state(1);
            let dep2 = deposit_state(2);
            let dep3 = deposit_state(3);

            let mut kv = BTreeMapKvStore::new();
            kv.set(
                &keyspace::full_key::<DepositStateRowSpec>(sm, &DepositStateKey::new(dep1_id))
                    .expect("encode dep1 key"),
                &<DepositState as crate::row_spec::SerializableValue>::serialize(&dep1)
                    .expect("serialize dep1"),
            )
            .await
            .expect("insert dep1");
            kv.set(
                &keyspace::full_key::<DepositStateRowSpec>(sm, &DepositStateKey::new(dep2_id))
                    .expect("encode dep2 key"),
                &<DepositState as crate::row_spec::SerializableValue>::serialize(&dep2)
                    .expect("serialize dep2"),
            )
            .await
            .expect("insert dep2");
            kv.set(
                &keyspace::full_key::<DepositStateRowSpec>(
                    other_sm,
                    &DepositStateKey::new(dep3_id),
                )
                .expect("encode dep3 key"),
                &<DepositState as crate::row_spec::SerializableValue>::serialize(&dep3)
                    .expect("serialize dep3"),
            )
            .await
            .expect("insert dep3");

            let root = GarblerState::default();
            kv.set(
                &keyspace::full_key::<RootStateRowSpec>(sm, &RootStateKey)
                    .expect("encode root key"),
                &<GarblerState as crate::row_spec::SerializableValue>::serialize(&root)
                    .expect("serialize root"),
            )
            .await
            .expect("insert root");

            let storage = KvStoreGarbler::new(sm, kv);
            let mut got = storage
                .stream_all_deposits()
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .map(|item| item.expect("stream item"))
                .collect::<Vec<_>>();
            got.sort_by_key(|(id, _)| id.0);

            assert_eq!(got, vec![(dep1_id, dep1), (dep2_id, dep2)]);
        });
    }

    #[test]
    fn stream_all_deposits_is_lazy() {
        futures::executor::block_on(async {
            let sm = sm_id(0x44);
            let dep1_id = dep_id(0x10);
            let dep2_id = dep_id(0x11);
            let dep1 = deposit_state(10);
            let dep2 = deposit_state(11);

            let mut kv = BTreeMapKvStore::new();
            kv.set(
                &keyspace::full_key::<DepositStateRowSpec>(sm, &DepositStateKey::new(dep1_id))
                    .expect("encode dep1 key"),
                &<DepositState as crate::row_spec::SerializableValue>::serialize(&dep1)
                    .expect("serialize dep1"),
            )
            .await
            .expect("insert dep1");
            kv.set(
                &keyspace::full_key::<DepositStateRowSpec>(sm, &DepositStateKey::new(dep2_id))
                    .expect("encode dep2 key"),
                &<DepositState as crate::row_spec::SerializableValue>::serialize(&dep2)
                    .expect("serialize dep2"),
            )
            .await
            .expect("insert dep2");

            let storage = KvStoreGarbler::new(sm, kv);
            let stream = storage.stream_all_deposits();
            pin_mut!(stream);

            let first = stream.next().await.expect("item").expect("ok item");
            assert_eq!(first.0, dep1_id);
            assert_eq!(first.1, dep1);

            let second = stream.next().await.expect("item").expect("ok item");
            assert_eq!(second.0, dep2_id);
            assert_eq!(second.1, dep2);
        });
    }

    #[test]
    fn deserialize_error_maps_to_storage_error_variant() {
        futures::executor::block_on(async {
            let sm = sm_id(0x55);
            let mut kv = BTreeMapKvStore::new();
            kv.set(
                &keyspace::full_key::<RootStateRowSpec>(sm, &RootStateKey)
                    .expect("encode root key"),
                b"not-valid-postcard",
            )
            .await
            .expect("insert invalid root state");
            let storage = KvStoreGarbler::new(sm, kv);

            let err = storage
                .get_root_state()
                .await
                .expect_err("expected deserialize error");
            assert!(matches!(err, StorageError::ValueDeserialize(_)));
        });
    }
}

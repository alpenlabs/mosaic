//! KvStore based implementation for StorageProvider.
use mosaic_cac_types::state_machine::StateMachineId;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;

use crate::{evaluator::KvStoreEvaluator, garbler::KvStoreGarbler, kvstore::KvStore};

/// KvStore based implementation for StorageProvider.
#[derive(Debug)]
pub struct KvStoreProvider<KV> {
    store: KV,
}

impl<KV: KvStore> KvStoreProvider<KV> {
    /// Create new instance of [`KvStoreProvider`] with the given [`KvStore`].
    pub fn new(store: KV) -> Self {
        Self { store }
    }
}

impl<KV: KvStore + Clone + Send + Sync + 'static> StorageProvider for KvStoreProvider<KV> {
    type GarblerState = KvStoreGarbler<KV>;

    type EvaluatorState = KvStoreEvaluator<KV>;

    fn garbler_state(&self, peer_id: &PeerId) -> Self::GarblerState {
        KvStoreGarbler::<KV>::new(peer_id_to_statemachine_id_raw(peer_id), self.store.clone())
    }

    fn evaluator_state(&self, peer_id: &PeerId) -> Self::EvaluatorState {
        KvStoreEvaluator::<KV>::new(peer_id_to_statemachine_id_raw(peer_id), self.store.clone())
    }
}

fn peer_id_to_statemachine_id_raw(peer_id: &PeerId) -> StateMachineId {
    StateMachineId::from(peer_id.to_bytes())
}

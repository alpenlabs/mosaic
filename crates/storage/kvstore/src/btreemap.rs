//! In-memory [`KvStore`] backed by [`std::collections::BTreeMap`].
//!
//! This implementation is intended for tests, local development, and simple
//! single-process execution.
//!
//! ## Characteristics
//! - In-memory only (data is lost when dropped)
//! - Deterministic key ordering
//! - Error type indicates lock poisoning

use std::{
    collections::BTreeMap,
    future::{Future, ready},
    ops::Bound,
    sync::{Arc, RwLock},
};

use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut};

use crate::{
    evaluator::KvStoreEvaluator,
    garbler::KvStoreGarbler,
    keyspace::{KEY_SCHEMA_VERSION, KeyDomain, next_prefix},
    kvstore::{KvPair, KvStore, KvStream},
};

/// Errors returned by [`BTreeMapKvStore`] and [`BTreeMapScopedKvStore`].
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum BTreeMapKvStoreError {
    /// The underlying lock was poisoned by a panic while held.
    #[error("btreemap store lock was poisoned")]
    PoisonedLock,
}

/// In-memory key-value store using a `BTreeMap<Vec<u8>, Vec<u8>>`.
#[derive(Debug, Default, Clone)]
pub struct BTreeMapKvStore {
    data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl BTreeMapKvStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn owned_bound(bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
        match bound {
            Bound::Included(bytes) => Bound::Included(bytes.to_vec()),
            Bound::Excluded(bytes) => Bound::Excluded(bytes.to_vec()),
            Bound::Unbounded => Bound::Unbounded,
        }
    }

    fn stream_from_pairs<'a>(pairs: Vec<KvPair>, idx: usize) -> KvStream<'a, BTreeMapKvStoreError> {
        KvStream::new(async move {
            match pairs.get(idx).cloned() {
                Some(pair) => Ok(Some((pair, Self::stream_from_pairs(pairs, idx + 1)))),
                None => Ok(None),
            }
        })
    }
}

#[async_trait::async_trait]
impl KvStore for BTreeMapKvStore {
    type Error = BTreeMapKvStoreError;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let data = self
            .data
            .read()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        Ok(data.get(key).cloned())
    }

    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        data.remove(key);
        Ok(())
    }

    fn range<'a>(
        &'a self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        reverse: bool,
    ) -> KvStream<'a, Self::Error> {
        let start = Self::owned_bound(start);
        let end = Self::owned_bound(end);
        let data = self
            .data
            .read()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock);
        let data = match data {
            Ok(data) => data,
            Err(err) => return KvStream::new(async move { Err(err) }),
        };
        let mut pairs: Vec<KvPair> = data
            .range((start, end))
            .map(|(key, value)| KvPair {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();

        if reverse {
            pairs.reverse();
        }

        Self::stream_from_pairs(pairs, 0)
    }

    async fn clear_range(
        &mut self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
    ) -> Result<(), Self::Error> {
        let start = Self::owned_bound(start);
        let end = Self::owned_bound(end);
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        let keys_to_remove: Vec<Vec<u8>> =
            data.range((start, end)).map(|(k, _)| k.clone()).collect();

        for key in keys_to_remove {
            data.remove(&key);
        }

        Ok(())
    }
}

/// A prefix-scoped view of a [`BTreeMapKvStore`].
///
/// All key operations are transparently namespaced under the given prefix. The
/// caller sees only the key bytes after the prefix; the prefix is never exposed
/// through the [`KvStore`] interface.
#[derive(Debug, Clone)]
pub struct BTreeMapScopedKvStore {
    data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
    prefix: Vec<u8>,
}

impl BTreeMapScopedKvStore {
    pub(crate) fn new(data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>, prefix: Vec<u8>) -> Self {
        Self { data, prefix }
    }

    fn prefixed_key(&self, key: &[u8]) -> Vec<u8> {
        let mut full = Vec::with_capacity(self.prefix.len() + key.len());
        full.extend_from_slice(&self.prefix);
        full.extend_from_slice(key);
        full
    }

    fn prefix_start_bound(&self, bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
        match bound {
            Bound::Included(k) => Bound::Included(self.prefixed_key(k)),
            Bound::Excluded(k) => Bound::Excluded(self.prefixed_key(k)),
            // Unbounded start → first key in this prefix namespace
            Bound::Unbounded => Bound::Included(self.prefix.clone()),
        }
    }

    fn prefix_end_bound(&self, bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
        match bound {
            Bound::Included(k) => Bound::Included(self.prefixed_key(k)),
            Bound::Excluded(k) => Bound::Excluded(self.prefixed_key(k)),
            // Unbounded end → one past the last key in this prefix namespace
            Bound::Unbounded => match next_prefix(&self.prefix) {
                Some(next) => Bound::Excluded(next),
                None => Bound::Unbounded,
            },
        }
    }

    fn stream_from_pairs<'a>(pairs: Vec<KvPair>, idx: usize) -> KvStream<'a, BTreeMapKvStoreError> {
        KvStream::new(async move {
            match pairs.get(idx).cloned() {
                Some(pair) => Ok(Some((pair, Self::stream_from_pairs(pairs, idx + 1)))),
                None => Ok(None),
            }
        })
    }
}

#[async_trait::async_trait]
impl KvStore for BTreeMapScopedKvStore {
    type Error = BTreeMapKvStoreError;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let full_key = self.prefixed_key(key);
        let data = self
            .data
            .read()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        Ok(data.get(&full_key).cloned())
    }

    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let full_key = self.prefixed_key(key);
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        data.insert(full_key, value.to_vec());
        Ok(())
    }

    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        let full_key = self.prefixed_key(key);
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        data.remove(&full_key);
        Ok(())
    }

    fn range<'a>(
        &'a self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        reverse: bool,
    ) -> KvStream<'a, Self::Error> {
        let start = self.prefix_start_bound(start);
        let end = self.prefix_end_bound(end);
        let prefix_len = self.prefix.len();

        let data = self
            .data
            .read()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock);
        let data = match data {
            Ok(data) => data,
            Err(err) => return KvStream::new(async move { Err(err) }),
        };

        let mut pairs: Vec<KvPair> = data
            .range((start, end))
            .map(|(key, value)| KvPair {
                // Strip prefix from returned keys
                key: key[prefix_len..].to_vec(),
                value: value.clone(),
            })
            .collect();

        if reverse {
            pairs.reverse();
        }

        Self::stream_from_pairs(pairs, 0)
    }

    async fn clear_range(
        &mut self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
    ) -> Result<(), Self::Error> {
        let start = self.prefix_start_bound(start);
        let end = self.prefix_end_bound(end);
        let mut data = self
            .data
            .write()
            .map_err(|_| BTreeMapKvStoreError::PoisonedLock)?;
        let keys_to_remove: Vec<Vec<u8>> =
            data.range((start, end)).map(|(k, _)| k.clone()).collect();
        for key in keys_to_remove {
            data.remove(&key);
        }
        Ok(())
    }
}

/// Builds a namespacing prefix from a peer identity and domain.
///
/// Format: `[KEY_SCHEMA_VERSION][domain_byte][peer_id_bytes (32)]` = 34 bytes.
fn build_prefix(peer_id: &PeerId, domain: KeyDomain) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(34);
    prefix.push(KEY_SCHEMA_VERSION);
    prefix.push(domain.to_u8());
    prefix.extend_from_slice(&peer_id.to_bytes());
    prefix
}

/// In-memory [`StorageProvider`] and [`StorageProviderMut`] backed by a
/// shared [`BTreeMapKvStore`].
///
/// Each peer's garbler and evaluator state is isolated under a unique prefix
/// derived from the peer identity and domain.
#[derive(Debug, Default, Clone)]
pub struct BTreeMapStorageProvider {
    store: BTreeMapKvStore,
}

impl BTreeMapStorageProvider {
    /// Create a new empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    fn scoped_garbler(&self, peer_id: &PeerId) -> KvStoreGarbler<BTreeMapScopedKvStore> {
        let prefix = build_prefix(peer_id, KeyDomain::Garbler);
        KvStoreGarbler::new(BTreeMapScopedKvStore::new(self.store.data.clone(), prefix))
    }

    fn scoped_evaluator(&self, peer_id: &PeerId) -> KvStoreEvaluator<BTreeMapScopedKvStore> {
        let prefix = build_prefix(peer_id, KeyDomain::Evaluator);
        KvStoreEvaluator::new(BTreeMapScopedKvStore::new(self.store.data.clone(), prefix))
    }
}

impl StorageProvider for BTreeMapStorageProvider {
    type GarblerState = KvStoreGarbler<BTreeMapScopedKvStore>;
    type EvaluatorState = KvStoreEvaluator<BTreeMapScopedKvStore>;

    fn garbler_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>> + Send {
        ready(Ok(self.scoped_garbler(peer_id)))
    }

    fn evaluator_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>> + Send {
        ready(Ok(self.scoped_evaluator(peer_id)))
    }
}

impl StorageProviderMut for BTreeMapStorageProvider {
    type GarblerState = KvStoreGarbler<BTreeMapScopedKvStore>;
    type EvaluatorState = KvStoreEvaluator<BTreeMapScopedKvStore>;

    fn garbler_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>> {
        ready(Ok(self.scoped_garbler(peer_id)))
    }

    fn evaluator_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>> {
        ready(Ok(self.scoped_evaluator(peer_id)))
    }
}

impl Commit for BTreeMapKvStore {
    type Error = BTreeMapKvStoreError;

    fn commit(self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

impl Commit for BTreeMapScopedKvStore {
    type Error = BTreeMapKvStoreError;

    fn commit(self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use super::*;

    #[test]
    fn basic_crud_and_exists() {
        futures::executor::block_on(async {
            let mut store = BTreeMapKvStore::new();
            assert!(!store.exists(b"k1").await.expect("exists"));

            store.set(b"k1", b"v1").await.expect("set");
            assert_eq!(store.get(b"k1").await.expect("get"), Some(b"v1".to_vec()));
            assert!(store.exists(b"k1").await.expect("exists"));

            store.delete(b"k1").await.expect("delete");
            assert_eq!(store.get(b"k1").await.expect("get"), None);
        });
    }

    #[test]
    fn range_orders_and_respects_bounds() {
        futures::executor::block_on(async {
            let mut store = BTreeMapKvStore::new();
            store.set(b"a", b"1").await.expect("set a");
            store.set(b"b", b"2").await.expect("set b");
            store.set(b"c", b"3").await.expect("set c");

            let fwd = store
                .range(Bound::Included(b"a"), Bound::Excluded(b"c"), false)
                .collect()
                .await
                .expect("collect fwd");
            assert_eq!(fwd.len(), 2);
            assert_eq!(fwd[0].key, b"a".to_vec());
            assert_eq!(fwd[1].key, b"b".to_vec());

            let rev = store
                .range(Bound::Included(b"a"), Bound::Excluded(b"c"), true)
                .collect()
                .await
                .expect("collect rev");
            assert_eq!(rev.len(), 2);
            assert_eq!(rev[0].key, b"b".to_vec());
            assert_eq!(rev[1].key, b"a".to_vec());
        });
    }

    #[test]
    fn clear_range_removes_only_targeted_keys() {
        futures::executor::block_on(async {
            let mut store = BTreeMapKvStore::new();
            store.set(b"a", b"1").await.expect("set a");
            store.set(b"b", b"2").await.expect("set b");
            store.set(b"c", b"3").await.expect("set c");

            store
                .clear_range(Bound::Included(b"b"), Bound::Unbounded)
                .await
                .expect("clear range");

            assert_eq!(store.get(b"a").await.expect("get a"), Some(b"1".to_vec()));
            assert_eq!(store.get(b"b").await.expect("get b"), None);
            assert_eq!(store.get(b"c").await.expect("get c"), None);
        });
    }

    #[test]
    fn scoped_store_isolates_namespaces() {
        futures::executor::block_on(async {
            let base = BTreeMapKvStore::new();
            let mut scope1 = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x01]);
            let mut scope2 = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x02]);

            scope1.set(b"key", b"val1").await.expect("set scope1");
            scope2.set(b"key", b"val2").await.expect("set scope2");

            assert_eq!(
                scope1.get(b"key").await.expect("get scope1"),
                Some(b"val1".to_vec())
            );
            assert_eq!(
                scope2.get(b"key").await.expect("get scope2"),
                Some(b"val2".to_vec())
            );

            // The raw store should have both keys under their respective prefixes
            assert!(
                base.get(&[0x01, b'k', b'e', b'y'])
                    .await
                    .expect("raw1")
                    .is_some()
            );
            assert!(
                base.get(&[0x02, b'k', b'e', b'y'])
                    .await
                    .expect("raw2")
                    .is_some()
            );
        });
    }

    #[test]
    fn scoped_range_strips_prefix_and_stays_in_namespace() {
        futures::executor::block_on(async {
            let base = BTreeMapKvStore::new();
            let mut scope = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x10]);
            let mut other = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x20]);

            scope.set(b"a", b"1").await.expect("set a");
            scope.set(b"b", b"2").await.expect("set b");
            other.set(b"a", b"X").await.expect("set other a");

            // Unbounded range should only return keys in this scope
            let pairs = scope
                .range(Bound::Unbounded, Bound::Unbounded, false)
                .collect()
                .await
                .expect("collect");

            assert_eq!(pairs.len(), 2);
            // Keys returned must be without prefix
            assert_eq!(pairs[0].key, b"a".to_vec());
            assert_eq!(pairs[1].key, b"b".to_vec());
        });
    }

    #[test]
    fn scoped_clear_range_stays_in_namespace() {
        futures::executor::block_on(async {
            let base = BTreeMapKvStore::new();
            let mut scope = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x10]);
            let mut other = BTreeMapScopedKvStore::new(base.data.clone(), vec![0x20]);

            scope.set(b"a", b"1").await.expect("set scope a");
            other.set(b"a", b"X").await.expect("set other a");

            scope
                .clear_range(Bound::Unbounded, Bound::Unbounded)
                .await
                .expect("clear");

            assert_eq!(scope.get(b"a").await.expect("get scope"), None);
            // Other namespace is untouched
            assert_eq!(
                other.get(b"a").await.expect("get other"),
                Some(b"X".to_vec())
            );
        });
    }
}

//! In-memory [`KvStore`] backed by [`std::collections::BTreeMap`].
//!
//! This implementation is intended for tests, local development, and simple
//! single-process execution.
//!
//! ## Characteristics
//! - In-memory only (data is lost when dropped)
//! - Deterministic key ordering
//! - Error type is [`std::convert::Infallible`]

use std::{
    collections::BTreeMap,
    convert::Infallible,
    ops::Bound,
    sync::{Arc, RwLock},
};

use crate::kvstore::{KvPair, KvStore, KvStream};

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

    fn stream_from_pairs<'a>(pairs: Vec<KvPair>, idx: usize) -> KvStream<'a, Infallible> {
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
    type Error = Infallible;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let data = self
            .data
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(data.get(key).cloned())
    }

    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut data = self
            .data
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        let mut data = self
            .data
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys_to_remove: Vec<Vec<u8>> =
            data.range((start, end)).map(|(k, _)| k.clone()).collect();

        for key in keys_to_remove {
            data.remove(&key);
        }

        Ok(())
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
}

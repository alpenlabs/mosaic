//! FoundationDB-backed state storage.
//!
//! This backend uses the FoundationDB directory layer to allocate per-peer,
//! per-role keyspaces and then scopes all row-level SM keys under the resolved
//! directory prefix.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    ops::Bound,
    sync::{Arc, Mutex},
};

use foundationdb::{
    Database, FdbError, KeySelector, RangeOption, Transaction, TransactionCommitError,
    directory::{Directory, DirectoryError, DirectoryLayer, DirectoryOutput},
    options,
};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut};
use mosaic_storage_kvstore::{
    evaluator::KvStoreEvaluator,
    garbler::KvStoreGarbler,
    kvstore::{KvPair, KvStore, KvStream},
};

const ROOT_PATH_APP: &str = "mosaic";
const ROOT_PATH_VERSION: &str = "v1";
const ROOT_LAYER: &[u8] = b"mosaic";
const GARBLER_LAYER: &[u8] = b"garbler";
const EVALUATOR_LAYER: &[u8] = b"evaluator";

type PrefixCache = Arc<Mutex<HashMap<(PeerId, RoleKeyspace), Vec<u8>>>>;

/// Configuration for the FoundationDB-backed storage provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FdbStorageConfig {
    /// Optional operator-specific prefix path components.
    pub global_path: Vec<String>,
}

/// Errors surfaced by the FoundationDB storage provider and transaction.
#[derive(Debug, thiserror::Error)]
pub enum FdbStorageError {
    /// FoundationDB API error.
    #[error("foundationdb: {0}")]
    Fdb(#[from] FdbError),
    /// Directory layer error.
    #[error("directory: {0}")]
    Directory(String),
    /// FoundationDB commit error.
    #[error("transaction commit: {0}")]
    Commit(#[from] TransactionCommitError),
    /// Returned key escaped the scoped directory prefix.
    #[error("scoped range returned a key outside the expected directory prefix")]
    PrefixViolation,
}

/// FoundationDB-backed provider for garbler and evaluator state.
#[derive(Clone)]
pub struct FdbStorageProvider {
    db: Arc<Database>,
    root: Arc<DirectoryOutput>,
    prefix_cache: PrefixCache,
}

impl fmt::Debug for FdbStorageProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FdbStorageProvider").finish_non_exhaustive()
    }
}

impl FdbStorageProvider {
    /// Open the provider and initialize the global Mosaic directory tree.
    pub async fn open(db: Database, config: FdbStorageConfig) -> Result<Self, FdbStorageError> {
        let directory_layer = DirectoryLayer::default();
        let root_path = root_path(&config);
        let trx = db.create_trx()?;
        let root = directory_layer
            .create_or_open(&trx, &root_path, None, Some(ROOT_LAYER))
            .await
            .map_err(|err| FdbStorageError::Directory(directory_error_to_string(err)))?;
        trx.commit().await?;

        Ok(Self {
            db: Arc::new(db),
            root: Arc::new(root),
            prefix_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn garbler_state_handle(
        &self,
        peer_id: PeerId,
    ) -> Result<KvStoreGarbler<FdbTransaction>, FdbStorageError> {
        let prefix = self
            .ensure_role_keyspace(peer_id, RoleKeyspace::Garbler)
            .await?;
        let tx = self.db.create_trx()?;
        Ok(KvStoreGarbler::new(FdbTransaction::new(tx, prefix)))
    }

    async fn evaluator_state_handle(
        &self,
        peer_id: PeerId,
    ) -> Result<KvStoreEvaluator<FdbTransaction>, FdbStorageError> {
        let prefix = self
            .ensure_role_keyspace(peer_id, RoleKeyspace::Evaluator)
            .await?;
        let tx = self.db.create_trx()?;
        Ok(KvStoreEvaluator::new(FdbTransaction::new(tx, prefix)))
    }

    async fn ensure_role_keyspace(
        &self,
        peer_id: PeerId,
        role: RoleKeyspace,
    ) -> Result<Vec<u8>, FdbStorageError> {
        let cache_key = (peer_id, role);
        {
            let cache = self
                .prefix_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(prefix) = cache.get(&cache_key) {
                return Ok(prefix.clone());
            }
        }

        let path = role_path(peer_id, role);
        let trx = self.db.create_trx()?;
        let directory = self
            .root
            .create_or_open(&trx, &path, None, Some(role.layer()))
            .await
            .map_err(|err| FdbStorageError::Directory(directory_error_to_string(err)))?;
        let prefix = directory
            .bytes()
            .map_err(|err| FdbStorageError::Directory(directory_error_to_string(err)))?
            .to_vec();
        trx.commit().await?;
        self.prefix_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(cache_key, prefix.clone());
        Ok(prefix)
    }
}

impl StorageProvider for FdbStorageProvider {
    type GarblerState = KvStoreGarbler<FdbTransaction>;
    type EvaluatorState = KvStoreEvaluator<FdbTransaction>;

    fn garbler_state(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>> + Send
    {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .garbler_state_handle(peer_id)
                .await
                .map_err(|err| mosaic_storage_api::StorageError::Other(err.to_string()))
        }
    }

    fn evaluator_state(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>> + Send
    {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .evaluator_state_handle(peer_id)
                .await
                .map_err(|err| mosaic_storage_api::StorageError::Other(err.to_string()))
        }
    }
}

impl StorageProviderMut for FdbStorageProvider {
    type GarblerState = KvStoreGarbler<FdbTransaction>;
    type EvaluatorState = KvStoreEvaluator<FdbTransaction>;

    fn garbler_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<Output = mosaic_storage_api::StorageResult<Self::GarblerState>>
    {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .garbler_state_handle(peer_id)
                .await
                .map_err(|err| mosaic_storage_api::StorageError::Other(err.to_string()))
        }
    }

    fn evaluator_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<Output = mosaic_storage_api::StorageResult<Self::EvaluatorState>>
    {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .evaluator_state_handle(peer_id)
                .await
                .map_err(|err| mosaic_storage_api::StorageError::Other(err.to_string()))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RoleKeyspace {
    Garbler,
    Evaluator,
}

impl RoleKeyspace {
    const fn path_component(self) -> &'static str {
        match self {
            Self::Garbler => "garbler",
            Self::Evaluator => "evaluator",
        }
    }

    const fn layer(self) -> &'static [u8] {
        match self {
            Self::Garbler => GARBLER_LAYER,
            Self::Evaluator => EVALUATOR_LAYER,
        }
    }
}

/// Transaction-scoped KV view over one resolved directory prefix.
#[derive(Debug)]
pub struct FdbTransaction {
    tx: Transaction,
    prefix: Vec<u8>,
}

#[derive(Debug)]
struct RangeCursor {
    opt: Option<RangeOption<'static>>,
    iteration: usize,
    buffered: VecDeque<KvPair>,
}

impl FdbTransaction {
    fn new(tx: Transaction, prefix: Vec<u8>) -> Self {
        Self { tx, prefix }
    }

    fn prefix_key(&self, key: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::with_capacity(self.prefix.len() + key.len());
        prefixed.extend_from_slice(&self.prefix);
        prefixed.extend_from_slice(key);
        prefixed
    }

    fn owned_bound(bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
        match bound {
            Bound::Included(key) => Bound::Included(key.to_vec()),
            Bound::Excluded(key) => Bound::Excluded(key.to_vec()),
            Bound::Unbounded => Bound::Unbounded,
        }
    }

    fn start_selector(&self, bound: Bound<Vec<u8>>) -> KeySelector<'static> {
        match bound {
            Bound::Included(key) => KeySelector::first_greater_or_equal(self.prefix_key(&key)),
            Bound::Excluded(key) => KeySelector::first_greater_than(self.prefix_key(&key)),
            Bound::Unbounded => KeySelector::first_greater_or_equal(self.prefix.clone()),
        }
    }

    fn end_selector(&self, bound: Bound<Vec<u8>>) -> KeySelector<'static> {
        match bound {
            Bound::Included(key) => KeySelector::first_greater_than(self.prefix_key(&key)),
            Bound::Excluded(key) => KeySelector::first_greater_or_equal(self.prefix_key(&key)),
            Bound::Unbounded => {
                let next = next_prefix(&self.prefix).unwrap_or_else(|| vec![0xFF]);
                KeySelector::first_greater_or_equal(next)
            }
        }
    }

    fn first_greater_than_key(key: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(key.len() + 1);
        out.extend_from_slice(key);
        out.push(0x00);
        out
    }

    fn clear_range_start_key(&self, bound: Bound<Vec<u8>>) -> Vec<u8> {
        match bound {
            Bound::Included(key) => self.prefix_key(&key),
            Bound::Excluded(key) => Self::first_greater_than_key(&self.prefix_key(&key)),
            Bound::Unbounded => self.prefix.clone(),
        }
    }

    fn clear_range_end_key(&self, bound: Bound<Vec<u8>>) -> Vec<u8> {
        match bound {
            Bound::Included(key) => Self::first_greater_than_key(&self.prefix_key(&key)),
            Bound::Excluded(key) => self.prefix_key(&key),
            Bound::Unbounded => next_prefix(&self.prefix).unwrap_or_else(|| vec![0xFF]),
        }
    }

    fn make_cursor(
        &self,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        reverse: bool,
    ) -> RangeCursor {
        let mut opt = RangeOption::from((self.start_selector(start), self.end_selector(end)));
        opt.reverse = reverse;
        opt.mode = options::StreamingMode::Iterator;

        RangeCursor {
            opt: Some(opt),
            iteration: 1,
            buffered: VecDeque::new(),
        }
    }

    fn stream_from_cursor<'a>(&'a self, mut cursor: RangeCursor) -> KvStream<'a, FdbStorageError> {
        KvStream::new(async move {
            loop {
                if let Some(pair) = cursor.buffered.pop_front() {
                    return Ok(Some((pair, self.stream_from_cursor(cursor))));
                }

                let Some(opt) = cursor.opt.take() else {
                    return Ok(None);
                };
                let values = self.tx.get_range(&opt, cursor.iteration, false).await?;
                cursor.iteration += 1;
                cursor.opt = opt.next_range(&values);

                for kv in values.into_iter() {
                    let key = kv
                        .key()
                        .strip_prefix(self.prefix.as_slice())
                        .ok_or(FdbStorageError::PrefixViolation)?
                        .to_vec();
                    cursor.buffered.push_back(KvPair {
                        key,
                        value: kv.value().to_vec(),
                    });
                }
            }
        })
    }
}

#[async_trait::async_trait]
impl KvStore for FdbTransaction {
    type Error = FdbStorageError;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = self.prefix_key(key);
        Ok(self.tx.get(&key, false).await?.map(|value| value.to_vec()))
    }

    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let key = self.prefix_key(key);
        self.tx.set(&key, value);
        Ok(())
    }

    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        let key = self.prefix_key(key);
        self.tx.clear(&key);
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
        self.stream_from_cursor(self.make_cursor(start, end, reverse))
    }

    async fn clear_range(
        &mut self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
    ) -> Result<(), Self::Error> {
        let start = Self::owned_bound(start);
        let end = Self::owned_bound(end);
        let begin = self.clear_range_start_key(start);
        let end = self.clear_range_end_key(end);
        self.tx.clear_range(&begin, &end);
        Ok(())
    }
}

impl Commit for FdbTransaction {
    type Error = FdbStorageError;

    async fn commit(self) -> Result<(), Self::Error> {
        self.tx.commit().await?;
        Ok(())
    }
}

fn root_path(config: &FdbStorageConfig) -> Vec<String> {
    let mut path = config.global_path.clone();
    path.push(ROOT_PATH_APP.to_owned());
    path.push(ROOT_PATH_VERSION.to_owned());
    path
}

fn role_path(peer_id: PeerId, role: RoleKeyspace) -> Vec<String> {
    vec![peer_id.to_hex(), role.path_component().to_owned()]
}

fn directory_error_to_string(err: DirectoryError) -> String {
    format!("{err:?}")
}

fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next = prefix.to_vec();
    for idx in (0..next.len()).rev() {
        if next[idx] != 0xFF {
            next[idx] += 1;
            next.truncate(idx + 1);
            return Some(next);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_path_appends_mosaic_namespace() {
        let config = FdbStorageConfig {
            global_path: vec!["operator-a".into(), "shared".into()],
        };
        assert_eq!(
            root_path(&config),
            vec![
                "operator-a".to_owned(),
                "shared".to_owned(),
                "mosaic".to_owned(),
                "v1".to_owned(),
            ]
        );
    }

    #[test]
    fn role_path_uses_peer_hex_and_role_component() {
        let path = role_path(PeerId::from([0xAB; 32]), RoleKeyspace::Garbler);
        assert_eq!(
            path[0],
            "abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(path[1], "garbler");
    }

    #[test]
    fn next_prefix_advances_last_non_ff_byte() {
        assert_eq!(next_prefix(&[0x10, 0x20]), Some(vec![0x10, 0x21]));
        assert_eq!(next_prefix(&[0x10, 0xFF]), Some(vec![0x11]));
        assert_eq!(next_prefix(&[0xFF, 0xFF]), None);
    }
}

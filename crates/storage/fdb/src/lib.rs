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
    Database, FdbError, KeySelector, RangeOption, TransactOption, Transaction,
    TransactionCommitError,
    directory::{Directory, DirectoryError, DirectoryLayer, DirectoryOutput},
    options,
};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderError, StorageProviderMut};
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
    /// A mutation was attempted through a read-only handle.
    #[error("mutation attempted through read-only foundationdb state handle")]
    ReadOnlyMutation,
}

impl TryFrom<FdbStorageError> for FdbError {
    type Error = FdbStorageError;

    fn try_from(value: FdbStorageError) -> Result<Self, Self::Error> {
        match value {
            FdbStorageError::Fdb(err) => Ok(err),
            other => Err(other),
        }
    }
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
        let root = Self::create_or_open_root(&db, &directory_layer, &root_path).await?;

        Ok(Self {
            db: Arc::new(db),
            root: Arc::new(root),
            prefix_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create or open the root directory, retrying on transaction conflicts.
    async fn create_or_open_root(
        db: &Database,
        directory_layer: &DirectoryLayer,
        root_path: &[String],
    ) -> Result<DirectoryOutput, FdbStorageError> {
        loop {
            let trx = db.create_trx()?;
            let root = directory_layer
                .create_or_open(&trx, root_path, None, Some(ROOT_LAYER))
                .await
                .map_err(|err| FdbStorageError::Directory(directory_error_to_string(err)))?;
            match trx.commit().await {
                Ok(_) => return Ok(root),
                Err(err) => {
                    // on_error implements FDB's recommended retry backoff; it returns
                    // Err if the error is not retryable.
                    err.on_error().await?;
                }
            }
        }
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

    async fn garbler_state_read_handle(
        &self,
        peer_id: PeerId,
    ) -> Result<KvStoreGarbler<FdbReadOnlyStore>, FdbStorageError> {
        let prefix = self
            .ensure_role_keyspace(peer_id, RoleKeyspace::Garbler)
            .await?;
        Ok(KvStoreGarbler::new(FdbReadOnlyStore::new(
            self.db.clone(),
            prefix,
        )))
    }

    async fn evaluator_state_read_handle(
        &self,
        peer_id: PeerId,
    ) -> Result<KvStoreEvaluator<FdbReadOnlyStore>, FdbStorageError> {
        let prefix = self
            .ensure_role_keyspace(peer_id, RoleKeyspace::Evaluator)
            .await?;
        Ok(KvStoreEvaluator::new(FdbReadOnlyStore::new(
            self.db.clone(),
            prefix,
        )))
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
        let prefix = loop {
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
            match trx.commit().await {
                Ok(_) => break prefix,
                Err(err) => {
                    err.on_error().await?;
                }
            }
        };
        self.prefix_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(cache_key, prefix.clone());
        Ok(prefix)
    }
}

impl StorageProvider for FdbStorageProvider {
    type GarblerState = KvStoreGarbler<FdbReadOnlyStore>;
    type EvaluatorState = KvStoreEvaluator<FdbReadOnlyStore>;

    fn garbler_state(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<
        Output = mosaic_storage_api::StorageProviderResult<Self::GarblerState>,
    > + Send {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .garbler_state_read_handle(peer_id)
                .await
                .map_err(|err| StorageProviderError::Other(err.to_string()))
        }
    }

    fn evaluator_state(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<
        Output = mosaic_storage_api::StorageProviderResult<Self::EvaluatorState>,
    > + Send {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .evaluator_state_read_handle(peer_id)
                .await
                .map_err(|err| StorageProviderError::Other(err.to_string()))
        }
    }
}

impl StorageProviderMut for FdbStorageProvider {
    type GarblerState = KvStoreGarbler<FdbTransaction>;
    type EvaluatorState = KvStoreEvaluator<FdbTransaction>;

    fn garbler_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<Output = mosaic_storage_api::StorageProviderResult<Self::GarblerState>>
    {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .garbler_state_handle(peer_id)
                .await
                .map_err(|err| StorageProviderError::Other(err.to_string()))
        }
    }

    fn evaluator_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl core::future::Future<
        Output = mosaic_storage_api::StorageProviderResult<Self::EvaluatorState>,
    > {
        let peer_id = *peer_id;
        let provider = self.clone();
        async move {
            provider
                .evaluator_state_handle(peer_id)
                .await
                .map_err(|err| StorageProviderError::Other(err.to_string()))
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

#[derive(Clone)]
/// Read-only KV view that opens a fresh FoundationDB transaction per method call.
pub struct FdbReadOnlyStore {
    db: Arc<Database>,
    prefix: Vec<u8>,
}

impl fmt::Debug for FdbReadOnlyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FdbReadOnlyStore").finish_non_exhaustive()
    }
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

    fn make_cursor(
        &self,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        reverse: bool,
    ) -> RangeCursor {
        let mut opt = RangeOption::from((
            start_selector(&self.prefix, start),
            end_selector(&self.prefix, end),
        ));
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

impl FdbReadOnlyStore {
    fn new(db: Arc<Database>, prefix: Vec<u8>) -> Self {
        Self { db, prefix }
    }

    async fn collect_range(
        &self,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        reverse: bool,
    ) -> Result<Vec<KvPair>, FdbStorageError> {
        self.db
            .transact_boxed(
                RangeRequest {
                    prefix: self.prefix.clone(),
                    start,
                    end,
                    reverse,
                },
                |tx, request| {
                    Box::pin(async move {
                        let mut cursor = make_cursor(
                            &request.prefix,
                            request.start.clone(),
                            request.end.clone(),
                            request.reverse,
                        );
                        let mut out = Vec::new();

                        loop {
                            let Some(opt) = cursor.opt.take() else {
                                return Ok(out);
                            };
                            let values = tx.get_range(&opt, cursor.iteration, false).await?;
                            cursor.iteration += 1;
                            cursor.opt = opt.next_range(&values);

                            for kv in values {
                                let key = kv
                                    .key()
                                    .strip_prefix(request.prefix.as_slice())
                                    .ok_or(FdbStorageError::PrefixViolation)?
                                    .to_vec();
                                out.push(KvPair {
                                    key,
                                    value: kv.value().to_vec(),
                                });
                            }
                        }
                    })
                },
                TransactOption::idempotent(),
            )
            .await
    }

    fn stream_from_pairs<'a>(mut pairs: VecDeque<KvPair>) -> KvStream<'a, FdbStorageError> {
        KvStream::new(async move {
            match pairs.pop_front() {
                Some(pair) => Ok(Some((pair, Self::stream_from_pairs(pairs)))),
                None => Ok(None),
            }
        })
    }
}

#[derive(Debug, Clone)]
struct RangeRequest {
    prefix: Vec<u8>,
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    reverse: bool,
}

fn prefix_key(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(prefix.len() + key.len());
    prefixed.extend_from_slice(prefix);
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

fn start_selector(prefix: &[u8], bound: Bound<Vec<u8>>) -> KeySelector<'static> {
    match bound {
        Bound::Included(key) => KeySelector::first_greater_or_equal(prefix_key(prefix, &key)),
        Bound::Excluded(key) => KeySelector::first_greater_than(prefix_key(prefix, &key)),
        Bound::Unbounded => KeySelector::first_greater_or_equal(prefix.to_vec()),
    }
}

fn end_selector(prefix: &[u8], bound: Bound<Vec<u8>>) -> KeySelector<'static> {
    match bound {
        Bound::Included(key) => KeySelector::first_greater_than(prefix_key(prefix, &key)),
        Bound::Excluded(key) => KeySelector::first_greater_or_equal(prefix_key(prefix, &key)),
        Bound::Unbounded => {
            let next = next_prefix(prefix).unwrap_or_else(|| vec![0xFF]);
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

fn clear_range_start_key(prefix: &[u8], bound: Bound<Vec<u8>>) -> Vec<u8> {
    match bound {
        Bound::Included(key) => prefix_key(prefix, &key),
        Bound::Excluded(key) => first_greater_than_key(&prefix_key(prefix, &key)),
        Bound::Unbounded => prefix.to_vec(),
    }
}

fn clear_range_end_key(prefix: &[u8], bound: Bound<Vec<u8>>) -> Vec<u8> {
    match bound {
        Bound::Included(key) => first_greater_than_key(&prefix_key(prefix, &key)),
        Bound::Excluded(key) => prefix_key(prefix, &key),
        Bound::Unbounded => next_prefix(prefix).unwrap_or_else(|| vec![0xFF]),
    }
}

fn make_cursor(
    prefix: &[u8],
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    reverse: bool,
) -> RangeCursor {
    let mut opt = RangeOption::from((start_selector(prefix, start), end_selector(prefix, end)));
    opt.reverse = reverse;
    opt.mode = options::StreamingMode::Iterator;

    RangeCursor {
        opt: Some(opt),
        iteration: 1,
        buffered: VecDeque::new(),
    }
}

#[async_trait::async_trait]
impl KvStore for FdbTransaction {
    type Error = FdbStorageError;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = prefix_key(&self.prefix, key);
        Ok(self.tx.get(&key, false).await?.map(|value| value.to_vec()))
    }

    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let key = prefix_key(&self.prefix, key);
        self.tx.set(&key, value);
        Ok(())
    }

    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        let key = prefix_key(&self.prefix, key);
        self.tx.clear(&key);
        Ok(())
    }

    fn range<'a>(
        &'a self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        reverse: bool,
    ) -> KvStream<'a, Self::Error> {
        let start = owned_bound(start);
        let end = owned_bound(end);
        self.stream_from_cursor(self.make_cursor(start, end, reverse))
    }

    async fn clear_range(
        &mut self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
    ) -> Result<(), Self::Error> {
        let start = owned_bound(start);
        let end = owned_bound(end);
        let begin = clear_range_start_key(&self.prefix, start);
        let end = clear_range_end_key(&self.prefix, end);
        self.tx.clear_range(&begin, &end);
        Ok(())
    }
}

#[async_trait::async_trait]
impl KvStore for FdbReadOnlyStore {
    type Error = FdbStorageError;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.db
            .transact_boxed(
                (self.prefix.clone(), key.to_vec()),
                |tx, data| {
                    Box::pin(async move {
                        let key = prefix_key(&data.0, &data.1);
                        Ok(tx.get(&key, false).await?.map(|value| value.to_vec()))
                    })
                },
                TransactOption::idempotent(),
            )
            .await
    }

    async fn set(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Err(FdbStorageError::ReadOnlyMutation)
    }

    async fn delete(&mut self, _key: &[u8]) -> Result<(), Self::Error> {
        Err(FdbStorageError::ReadOnlyMutation)
    }

    fn range<'a>(
        &'a self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        reverse: bool,
    ) -> KvStream<'a, Self::Error> {
        let store = self.clone();
        let start = owned_bound(start);
        let end = owned_bound(end);
        KvStream::new(async move {
            let mut pairs = VecDeque::from(store.collect_range(start, end, reverse).await?);
            match pairs.pop_front() {
                Some(pair) => Ok(Some((pair, FdbReadOnlyStore::stream_from_pairs(pairs)))),
                None => Ok(None),
            }
        })
    }

    async fn clear_range(
        &mut self,
        _start: Bound<&[u8]>,
        _end: Bound<&[u8]>,
    ) -> Result<(), Self::Error> {
        Err(FdbStorageError::ReadOnlyMutation)
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

#[cfg(all(test, feature = "fdb-storage-tests"))]
mod test_utils {
    use std::sync::{
        Once,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static FDB_BOOT: Once = Once::new();
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    static RUN_ID: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });

    /// Initialize the FoundationDB network thread (idempotent).
    ///
    /// The returned `NetworkAutoStop` is intentionally leaked so the FDB network
    /// thread stays alive for the duration of the test process.
    pub(crate) fn fdb_boot() {
        FDB_BOOT.call_once(|| {
            // SAFETY: Must be called at most once before any FDB operations.
            // `Once` guarantees single execution. We leak the handle so the
            // network thread is never torn down mid-test.
            let handle = unsafe { foundationdb::boot() };
            std::mem::forget(handle);
        });
    }

    /// Create an [`FdbStorageProvider`] with a unique directory path for test isolation.
    ///
    /// The provider's garbler and evaluator keyspaces for the test peer are
    /// pre-warmed (with retry) so that directory-layer conflicts don't surface
    /// during the actual test body.
    pub(crate) async fn create_provider() -> FdbStorageProvider {
        fdb_boot();
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let config = FdbStorageConfig {
            global_path: vec![format!("test-provider-{}-{id}", *RUN_ID)],
        };
        let mut last_err = String::new();
        for _ in 0..5 {
            let db = Database::default().expect("failed to open FDB database");
            let p = match FdbStorageProvider::open(db, config.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    last_err = e.to_string();
                    continue;
                }
            };
            // Pre-warm both keyspaces so ensure_role_keyspace() won't need
            // to hit the directory layer during tests.
            let peer = PeerId::from([0x01; 32]);
            if let Err(e) = p.ensure_role_keyspace(peer, RoleKeyspace::Garbler).await {
                last_err = e.to_string();
                continue;
            }
            if let Err(e) = p.ensure_role_keyspace(peer, RoleKeyspace::Evaluator).await {
                last_err = e.to_string();
                continue;
            }
            return p;
        }
        panic!("failed to open FDB storage provider after 5 attempts: {last_err}")
    }
}

#[cfg(all(test, feature = "fdb-storage-tests"))]
mod garbler_tests {
    use super::test_utils::create_provider;

    mosaic_storage_api::garbler_store_tests!(create_provider().await);
}

#[cfg(all(test, feature = "fdb-storage-tests"))]
mod evaluator_tests {
    use super::test_utils::create_provider;

    mosaic_storage_api::evaluator_store_tests!(create_provider().await);
}

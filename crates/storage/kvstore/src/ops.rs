//! Shared key-value store operations for evaluator and garbler storage adapters.

use std::ops::Bound;

use futures::{Stream, StreamExt, stream};
use mosaic_cac_types::HeapArray;

use crate::{
    keyspace::{self, end_bound, start_bound},
    kvstore::KvStore,
    row_spec::{KVRowSpec, SerializableValue},
    storage_error::StorageError,
};

/// Extension trait providing common KV helpers to both evaluator and garbler
/// storage structs.
///
/// Implementors only need to provide [`store`](Self::store) and
/// [`store_mut`](Self::store_mut); all other methods have default
/// implementations.
pub(crate) trait KvStoreOps {
    type Store: KvStore;

    fn store(&self) -> &Self::Store;
    fn store_mut(&mut self) -> &mut Self::Store;

    async fn get_value<R: KVRowSpec>(
        &self,
        key: &R::Key,
    ) -> Result<Option<R::Value>, StorageError> {
        let key_bytes = keyspace::full_key::<R>(key).map_err(StorageError::key_pack)?;
        let Some(value_bytes) = self
            .store()
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
        let key_bytes = keyspace::full_key::<R>(key).map_err(StorageError::key_pack)?;
        let value_bytes = value.serialize().map_err(StorageError::value_serialize)?;

        self.store_mut()
            .set(key_bytes.as_ref(), value_bytes.as_ref())
            .await
            .map_err(StorageError::kvstore)
    }

    /// Stream a sub-range of a row, given start/end bounds on the row keys.
    #[expect(clippy::type_complexity)]
    fn stream_row<R: KVRowSpec>(
        &self,
        start: Bound<R::Key>,
        end: Bound<R::Key>,
        reverse: bool,
    ) -> Result<
        impl Stream<Item = Result<(R::Key, R::Value), StorageError>> + Send + '_,
        StorageError,
    > {
        let kv_stream = self.store().range(
            start_bound::<R>(start)
                .map_err(StorageError::key_pack)?
                .as_ref()
                .map(Vec::as_slice),
            end_bound::<R>(end)
                .map_err(StorageError::key_pack)?
                .as_ref()
                .map(Vec::as_slice),
            reverse,
        );

        let row_stream = stream::try_unfold(kv_stream, move |current| async move {
            match current.next().await.map_err(StorageError::kvstore)? {
                Some((pair, next)) => {
                    let key = keyspace::split_row_key::<R>(&pair.key)
                        .map_err(StorageError::key_unpack)?;
                    let value = <R::Value as SerializableValue>::deserialize(&pair.value)
                        .map_err(StorageError::value_deserialize)?;
                    Ok(Some(((key, value), next)))
                }
                None => Ok(None),
            }
        });

        Ok(row_stream)
    }

    async fn row_has_any<R: KVRowSpec>(&self) -> Result<bool, StorageError> {
        let row_stream = self.stream_row::<R>(Bound::Unbounded, Bound::Unbounded, false)?;
        futures::pin_mut!(row_stream);
        match row_stream.next().await {
            Some(item) => {
                let _ = item?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Collect all values from a bounded row range into a `Vec`.
    async fn collect_row_values<R: KVRowSpec>(
        &self,
        start: Bound<R::Key>,
        end: Bound<R::Key>,
    ) -> Result<Vec<R::Value>, StorageError> {
        let row_stream = self.stream_row::<R>(start, end, false)?;
        futures::pin_mut!(row_stream);

        let mut values = Vec::new();
        while let Some(item) = row_stream.next().await {
            let (_key, value) = item?;
            values.push(value);
        }
        Ok(values)
    }

    /// Collect a contiguous sub-range of a row into a [`HeapArray`].
    ///
    /// Uses a single range scan from `key_for(0)` to `key_for(N-1)`.
    /// Returns `Ok(None)` when no items are present, or
    /// `Err` when only some of the expected `N` items exist.
    async fn collect_fixed_array_row<R, T, F, const N: usize>(
        &self,
        mut key_for: F,
        missing_message: &'static str,
    ) -> Result<Option<HeapArray<T, N>>, StorageError>
    where
        R: KVRowSpec<Value = T>,
        F: FnMut(usize) -> R::Key,
    {
        let values = self
            .collect_row_values::<R>(Bound::Included(key_for(0)), Bound::Included(key_for(N - 1)))
            .await?;

        if values.is_empty() {
            return Ok(None);
        }
        if values.len() != N {
            return Err(StorageError::state_inconsistency(missing_message));
        }

        Ok(Some(HeapArray::from_vec(values)))
    }
}

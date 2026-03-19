//! Async trait for garbling table persistent storage.
//!
//! A garbling table consists of three components:
//!
//! | Component        | Size (production) | Access pattern       |
//! |-----------------|-------------------|---------------------|
//! | Ciphertexts     | ~43 GB            | Streamed read/write |
//! | Translation     | ~4 MB             | Bulk read/write     |
//! | Metadata        | 64 B              | Bulk read/write     |
//!
//! Ciphertexts are too large for memory and must be streamed. Translation
//! material and metadata fit comfortably and are read/written in a single call.
//!
//! # Commitment verification
//!
//! Implementations must ensure partially-written tables are not externally
//! visible. A typical approach is to write under staging or versioned object
//! paths and publish a final commit marker only after all table components are
//! durable.
//!
//! # Runtime bridging
//!
//! The production implementation (`object_store`-backed) spawns a background
//! single-threaded tokio runtime. Monoio workers stream data to it via bounded
//! channels. The tokio thread handles the actual S3/filesystem I/O and hashing.
//!
//! # Implementations
//!
//! - S3 / GCS / Azure via `object_store` crate (tokio bridge).
//! - Local filesystem via `object_store::local::LocalFileSystem`.
//! - In-memory via `object_store::memory::InMemory` (for testing).

use std::fmt::Debug;

use mosaic_common::Byte32;
use mosaic_net_svc_api::PeerId;
use mosaic_vs3::Index;

// ════════════════════════════════════════════════════════════════════════════
// Table identifier
// ════════════════════════════════════════════════════════════════════════════

/// Identifies a specific garbling table in storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableId {
    /// The peer this table belongs to.
    pub peer_id: PeerId,
    /// The circuit index (1..=N_CIRCUITS for garbled tables, corresponds to
    /// the evaluator's 7 unopened circuits).
    pub index: Index,
}

// ════════════════════════════════════════════════════════════════════════════
// Metadata
// ════════════════════════════════════════════════════════════════════════════

/// Small metadata stored alongside a garbling table.
///
/// The evaluator needs these values to configure its evaluation instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableMetadata {
    /// Output label ciphertext. Encrypts the output share value under the
    /// garbler's output label, allowing the evaluator to recover the share
    /// from the evaluation result.
    pub output_label_ct: Byte32,
    /// AES-128 key used by the garbling instance.
    pub aes_key: [u8; 16],
    /// Public S value used in the CCRND hash function.
    pub public_s: [u8; 16],
}

// ════════════════════════════════════════════════════════════════════════════
// Storage trait
// ════════════════════════════════════════════════════════════════════════════

/// Persistent storage for garbling tables.
///
/// Provides async access to garbling table components (ciphertexts,
/// translation material, metadata) keyed by [`TableId`].
///
/// The ciphertext component is streamed via [`TableWriter`] / [`TableReader`]
/// because it is too large (~43 GB) to fit in memory. Translation material
/// and metadata are small enough to read/write in a single call.
pub trait TableStore: Send + Sync + 'static {
    /// Error type for storage operations.
    type Error: std::error::Error + Debug + Send + 'static;

    /// Writer for streaming ciphertext data into storage.
    type Writer: TableWriter<Error = Self::Error> + Send;

    /// Reader for streaming ciphertext data out of storage.
    type Reader: TableReader<Error = Self::Error> + Send;

    /// Begin writing a new garbling table.
    ///
    /// Returns a [`TableWriter`] for streaming ciphertext data. Translation
    /// material and metadata are written via the writer's
    /// [`finish`](TableWriter::finish) method after all ciphertext chunks
    /// have been written.
    ///
    /// If a table with this ID already exists, it is overwritten.
    fn create(
        &self,
        id: &TableId,
    ) -> impl Future<Output = Result<Self::Writer, Self::Error>> + Send;

    /// Open a stored garbling table for reading.
    ///
    /// Returns a [`TableReader`] for streaming ciphertext data. Translation
    /// material and metadata are available via dedicated methods on the reader.
    ///
    /// Returns an error if the table does not exist.
    fn open(&self, id: &TableId) -> impl Future<Output = Result<Self::Reader, Self::Error>> + Send;

    /// Check whether a table exists in storage.
    fn exists(&self, id: &TableId) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Delete a table from storage.
    ///
    /// No-op if the table does not exist.
    fn delete(&self, id: &TableId) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

// ════════════════════════════════════════════════════════════════════════════
// Writer
// ════════════════════════════════════════════════════════════════════════════

/// Streams ciphertext data into a garbling table.
///
/// # Usage
///
/// ```text
/// let mut writer = store.create(&table_id).await?;
/// for chunk in ciphertext_chunks {
///     writer.write_ciphertext(chunk).await?;
/// }
/// writer.finish(translation_bytes, metadata).await?;
/// ```
///
/// The writer is consumed by [`finish`](Self::finish), which also persists
/// the translation material and metadata and publishes the table for readers.
/// Dropping the writer without calling `finish` must leave the table
/// invisible to [`TableStore::open`] and [`TableStore::exists`].
pub trait TableWriter {
    /// Error type (must match the parent [`TableStore::Error`]).
    type Error: std::error::Error + Debug + Send + 'static;

    /// Write a chunk of ciphertext data.
    ///
    /// Chunks are appended in order. The total size across all calls equals
    /// the number of AND gates × 16 bytes.
    fn write_ciphertext(
        &mut self,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Finalise the table: persist translation material and metadata, then
    /// commit the ciphertext stream.
    ///
    /// After this call returns successfully the table is durable and visible
    /// to readers.
    fn finish(
        &mut self,
        translation: &[u8],
        metadata: TableMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

// ════════════════════════════════════════════════════════════════════════════
// Reader
// ════════════════════════════════════════════════════════════════════════════

/// Reads a stored garbling table.
///
/// # Usage
///
/// ```text
/// let mut reader = store.open(&table_id).await?;
/// let metadata = reader.metadata().await?;
/// let translation = reader.read_translation().await?;
/// let mut buf = vec![0u8; 4 * 1024 * 1024];
/// loop {
///     let n = reader.read_ciphertext(&mut buf).await?;
///     if n == 0 { break; }
///     process(&buf[..n]);
/// }
/// ```
pub trait TableReader {
    /// Error type (must match the parent [`TableStore::Error`]).
    type Error: std::error::Error + Debug + Send + 'static;

    /// Read the table metadata.
    fn metadata(&mut self) -> impl Future<Output = Result<TableMetadata, Self::Error>> + Send;

    /// Read the full translation material into memory.
    ///
    /// Translation material is ~4 MB for the production circuit
    /// (N_WITHDRAWAL_INPUT_WIRES × 256 × 8 × 16 bytes).
    fn read_translation(&mut self) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;

    /// Read the next chunk of ciphertext data into `buf`.
    ///
    /// Returns the number of bytes read. Returns `0` when all ciphertext
    /// data has been consumed (EOF).
    ///
    /// Ciphertexts are returned in the same order they were written —
    /// sequential AND-gate ciphertexts in circuit execution order.
    fn read_ciphertext(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;
}

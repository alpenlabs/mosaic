//! Storage interface for Mosaic.
//!
//! # State Machine Storage
//!
//! - [`StorageProvider`] — returns read-only handles ([`StateRead`]) for the Job Scheduler.
//!   Handlers can inspect state machine data but **cannot** mutate it. This is enforced at the type
//!   level.
//!
//! - [`StorageProviderMut`] — returns mutable handles ([`StateMut`]) for the SM Executor, which
//!   needs write access to run the STF.
//!
//! # Garbling Table Storage
//!
//! - [`TableStore`] — persistent storage for garbling tables (ciphertexts, translation material,
//!   metadata). Implementations include S3 (via `object_store`), local filesystem, and in-memory
//!   for testing.
//!
//! [`StateRead`]: mosaic_cac_types::state_machine::garbler::StateRead
//! [`StateMut`]: mosaic_cac_types::state_machine::garbler::StateMut

pub mod table_store;

use core::future::Future;

use mosaic_cac_types::state_machine::{evaluator, garbler};
use mosaic_net_svc_api::PeerId;
pub use table_store::{TableId, TableMetadata, TableReader, TableStore, TableWriter};
use thiserror::Error;

/// Storage Provider Error.
#[derive(Debug, Error)]
pub enum StorageProviderError {
    /// Failed to serialize/deserialize.
    #[error("Serialization: {0}")]
    Serialization(String),
    /// Other type of error not covered above.
    #[error("storage: {0}")]
    Other(String),
}

/// Storage Provider Result
pub type StorageProviderResult<T> = Result<T, StorageProviderError>;

/// Commit hook for mutable storage sessions/handles.
///
/// This is intended for transactional backends where all writes performed via
/// a mutable state handle should be atomically finalized at the end of one STF
/// call. In-memory backends may implement this as a no-op.
pub trait Commit {
    /// Error type produced by commit.
    type Error: std::fmt::Debug;

    /// Finalize writes performed through this mutable handle.
    fn commit(self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Read-only provider of per-peer storage handles.
///
/// Used by the **Job Scheduler** so that action handlers can inspect state
/// machine data without being able to mutate it. This separation is enforced
/// at the type level: [`StorageProvider`] only exposes [`garbler::StateRead`]
/// and [`evaluator::StateRead`].
///
/// # Implementations
///
/// A concrete backend (e.g. `InMemoryStorageProvider`) should implement both
/// [`StorageProvider`] and [`StorageProviderMut`]. The job scheduler only
/// receives the [`StorageProvider`] bound, so it physically cannot call
/// write methods.
pub trait StorageProvider: Send + Sync + 'static {
    /// Read-only garbler state handle.
    type GarblerState: garbler::StateRead + Send + Sync;

    /// Read-only evaluator state handle.
    type EvaluatorState: evaluator::StateRead + Send + Sync;

    /// Get a read-only storage handle for a peer's garbler state machine.
    ///
    /// If the peer has no existing state, the returned handle should represent
    /// empty / default state and reads should return `Ok(None)`.
    fn garbler_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = StorageProviderResult<Self::GarblerState>> + Send;

    /// Get a read-only storage handle for a peer's evaluator state machine.
    ///
    /// If the peer has no existing state, the returned handle should represent
    /// empty / default state and reads should return `Ok(None)`.
    fn evaluator_state(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = StorageProviderResult<Self::EvaluatorState>> + Send;
}

/// Read-write provider of per-peer storage handles.
///
/// Used by the **SM Executor** which needs mutable access to run the STF
/// (`handle_event` and `handle_action_result` take `&mut S: StateMut`).
///
/// A concrete backend should implement both [`StorageProvider`] (for
/// read-only job handler access) and [`StorageProviderMut`] (for SM
/// execution). The two traits intentionally have separate associated types
/// so that an implementation can return different handle types for read vs.
/// write if needed (e.g. a read-snapshot vs. a transactional write handle).
pub trait StorageProviderMut: 'static {
    /// Mutable garbler state handle.
    type GarblerState: garbler::StateMut + Commit + Send + Sync;

    /// Mutable evaluator state handle.
    type EvaluatorState: evaluator::StateMut + Commit + Send + Sync;

    /// Get a mutable storage handle for a peer's garbler state machine.
    ///
    /// If the peer has no existing state, the returned handle should represent
    /// empty / default state. Writes via [`garbler::StateMut`] will create
    /// data on first access.
    fn garbler_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = StorageProviderResult<Self::GarblerState>>;

    /// Get a mutable storage handle for a peer's evaluator state machine.
    ///
    /// If the peer has no existing state, the returned handle should represent
    /// empty / default state. Writes via [`evaluator::StateMut`] will create
    /// data on first access.
    fn evaluator_state_mut(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = StorageProviderResult<Self::EvaluatorState>>;
}

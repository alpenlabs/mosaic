//! Provider trait for state persistence and input queue management.

use std::future::Future;

use crate::{
    error::Result,
    types::{InputSeqNo, PersistedInput},
};

/// Provider trait for state persistence and input queue management.
///
/// Implementations abstract over the concrete storage backend (RocksDB,
/// in-memory, etc.) and provide:
///
/// - State snapshots for crash recovery
/// - Input queue reading with exactly-once processing semantics
///
/// Note: Input *persistence* is the responsibility of external code that
/// submits inputs. The provider only *reads* inputs and tracks processing.
///
/// # Type Parameters
///
/// - `State`: The state machine's state type
/// - `NormalInput`: The "normal" input type (not `TrackedActionCompleted`)
pub trait PhasmProvider: Send + Sync + 'static {
    /// The state machine's state type.
    type State: Clone + Send + Sync;

    /// The type for normal inputs (the payload in `Input::Normal(T)`).
    type NormalInput: Clone + Send + Sync;

    // === State Persistence ===

    /// Loads the persisted state, if any exists.
    ///
    /// Returns `None` if this is a fresh start with no prior state.
    fn load_state(&self) -> impl Future<Output = Result<Option<Self::State>>> + Send;

    /// Saves the current state to persistence.
    ///
    /// This should be atomic - either the full state is saved or none of it.
    fn save_state(&self, state: &Self::State) -> impl Future<Output = Result<()>> + Send;

    // === Input Queue Reading ===

    /// Gets the sequence number of the last input that was fully processed.
    ///
    /// Returns `None` if no inputs have been processed yet.
    fn last_processed_seq_no(&self) -> impl Future<Output = Result<Option<InputSeqNo>>> + Send;

    /// Loads all unprocessed inputs from the durable queue.
    ///
    /// Returns inputs with `seq_no > last_processed`, ordered by `seq_no`.
    fn load_pending_inputs(
        &self,
    ) -> impl Future<Output = Result<Vec<PersistedInput<Self::NormalInput>>>> + Send;

    /// Marks an input as fully processed.
    ///
    /// Called after the STF completes and state is persisted. This creates
    /// a checkpoint that prevents re-processing on restart.
    fn mark_input_processed(&self, seq_no: InputSeqNo) -> impl Future<Output = Result<()>> + Send;
}

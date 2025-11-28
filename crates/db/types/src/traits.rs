//! Database trait definitions.

use serde::{de::DeserializeOwned, Serialize};

use crate::error::DbResult;
use crate::types::{JobFilter, JobId, JobRecord};
use mosaic_job_types::JobExecState;

/// Core database operations trait.
///
/// This trait provides transaction management for atomic operations.
pub trait Database: Send + Sync {
    /// The transaction type for this database.
    type Transaction<'a>: DbTransaction
    where
        Self: 'a;

    /// Begin a new transaction.
    fn begin_transaction(&self) -> DbResult<Self::Transaction<'_>>;
}

/// A database transaction with atomic commit/rollback semantics.
pub trait DbTransaction {
    /// Commit the transaction, persisting all changes.
    fn commit(self) -> DbResult<()>;

    /// Rollback the transaction, discarding all changes.
    fn rollback(self) -> DbResult<()>;
}

/// Job persistence operations.
///
/// This trait provides CRUD operations for job records.
pub trait JobStore: Send + Sync {
    /// Create a new job and return its ID.
    ///
    /// The job is created in the `Created` state.
    fn create_job(&self, job_type: &str, config: &[u8]) -> DbResult<JobId>;

    /// Get a job by its ID.
    fn get_job(&self, id: JobId) -> DbResult<Option<JobRecord>>;

    /// Update a job's execution state.
    fn update_job_state(&self, id: JobId, state: JobExecState) -> DbResult<()>;

    /// Update a job's progress.
    fn update_job_progress(&self, id: JobId, completed: u64, total: u64) -> DbResult<()>;

    /// Set a job's error message (typically when transitioning to Failed state).
    fn set_job_error(&self, id: JobId, error: &str) -> DbResult<()>;

    /// List jobs matching the given filter.
    fn list_jobs(&self, filter: &JobFilter) -> DbResult<Vec<JobRecord>>;

    /// List all jobs that are in Created or Running state.
    ///
    /// This is used during recovery to find jobs that need to be resumed.
    fn list_pending_jobs(&self) -> DbResult<Vec<JobRecord>>;

    /// Delete a job by its ID.
    fn delete_job(&self, id: JobId) -> DbResult<()>;
}

/// State machine persistence operations.
///
/// This trait provides storage for PHASM-style state machines,
/// supporting both state data and pending actions for crash recovery.
pub trait StateMachineStore: Send + Sync {
    /// Save the state of a state machine.
    ///
    /// This overwrites any existing state for the given machine ID.
    fn save_state<S: Serialize>(&self, machine_id: &str, state: &S) -> DbResult<()>;

    /// Load the state of a state machine.
    ///
    /// Returns `None` if no state exists for the given machine ID.
    fn load_state<S: DeserializeOwned>(&self, machine_id: &str) -> DbResult<Option<S>>;

    /// Save pending actions for a state machine.
    ///
    /// These are actions that were emitted but not yet completed,
    /// used for crash recovery via PHASM's `restore()` function.
    fn save_pending_actions(&self, machine_id: &str, actions: &[u8]) -> DbResult<()>;

    /// Load pending actions for a state machine.
    fn load_pending_actions(&self, machine_id: &str) -> DbResult<Option<Vec<u8>>>;

    /// Clear pending actions for a state machine.
    ///
    /// Called after actions have been successfully completed.
    fn clear_pending_actions(&self, machine_id: &str) -> DbResult<()>;

    /// Delete all data for a state machine.
    fn delete_machine(&self, machine_id: &str) -> DbResult<()>;

    /// Check if a state machine exists.
    fn machine_exists(&self, machine_id: &str) -> DbResult<bool>;
}

/// Generic key-value store for snapshots and intermediate state.
///
/// This trait supports per-step snapshots for crash recovery of long-running jobs.
pub trait SnapshotStore: Send + Sync {
    /// Save a snapshot at a given step.
    ///
    /// If a snapshot already exists for this key and step, it is overwritten.
    fn save_snapshot(&self, key: &str, step: u64, data: &[u8]) -> DbResult<()>;

    /// Load the latest snapshot for a key.
    ///
    /// Returns the step number and data of the most recent snapshot,
    /// or `None` if no snapshots exist.
    fn load_latest_snapshot(&self, key: &str) -> DbResult<Option<(u64, Vec<u8>)>>;

    /// Load a specific snapshot by key and step.
    fn load_snapshot(&self, key: &str, step: u64) -> DbResult<Option<Vec<u8>>>;

    /// Delete all snapshots for a key.
    fn delete_snapshots(&self, key: &str) -> DbResult<()>;

    /// Delete snapshots older than a given step.
    ///
    /// This is useful for cleaning up old snapshots after a job has progressed.
    fn delete_snapshots_before(&self, key: &str, step: u64) -> DbResult<()>;
}

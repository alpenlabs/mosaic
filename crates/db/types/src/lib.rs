//! Database traits and types for Mosaic.
//!
//! This crate defines the abstract database interface used by the Mosaic
//! garbler service. It provides traits for:
//!
//! - [`JobStore`]: Persistent storage for job records
//! - [`StateMachineStore`]: Storage for PHASM-style state machines
//! - [`SnapshotStore`]: Key-value storage for job snapshots
//!
//! The traits are designed to be backend-agnostic, with SQLite being the
//! primary implementation in the `mosaic-db-sqlite` crate.

mod error;
mod traits;
mod types;

pub use error::{DbError, DbResult};
pub use traits::{Database, DbTransaction, JobStore, SnapshotStore, StateMachineStore};
pub use types::{JobFilter, JobId, JobRecord};

// Re-export JobExecState from mosaic-job-types for convenience
pub use mosaic_job_types::JobExecState;

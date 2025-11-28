//! Job management and execution for Mosaic.
//!
//! This crate provides a job manager that handles the lifecycle of long-running
//! jobs in the Mosaic garbler service. It supports:
//!
//! - Creating and starting jobs
//! - Concurrent execution via thread pool
//! - Per-step snapshots for crash recovery
//! - Job cancellation
//! - Progress tracking
//!
//! # Architecture
//!
//! Jobs implement the [`Job`] trait, which defines how to:
//! - Execute discrete steps
//! - Serialize/deserialize state for snapshots
//! - Report progress
//!
//! The [`JobManager`] coordinates job execution:
//! - Jobs are persisted to the database before execution
//! - Snapshots are saved periodically during execution
//! - On crash, jobs can be resumed from their last snapshot
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use mosaic_db_sqlite::SqliteDatabase;
//! use mosaic_job_manager::{JobManager, JobManagerConfig, Job};
//!
//! // Open database
//! let db = Arc::new(SqliteDatabase::open("mosaic.db").unwrap());
//!
//! // Create manager
//! let config = JobManagerConfig::default();
//! let manager = JobManager::new(db, config);
//!
//! // Create and start a job
//! let job_id = manager.create_job::<MyJob>(my_config).unwrap();
//! manager.start_job::<MyJob>(job_id).unwrap();
//!
//! // Wait for completion
//! manager.wait_for_job(job_id, Duration::from_secs(60)).unwrap();
//! ```

mod error;
mod job;
mod manager;

pub use error::{JobError, JobResult};
pub use job::{Job, JobContext, StepResult};
pub use manager::{JobManager, JobManagerConfig};

// Re-export commonly used types
pub use mosaic_db_types::{JobExecState, JobId, JobRecord};

//! Job scheduler implementation for Mosaic.
//!
//! This crate contains the execution infrastructure for actions emitted by
//! Garbler and Evaluator state machines. It provides three specialized pools:
//!
//! - **Light pool**: FIFO queue for I/O-bound tasks (sends, acks)
//! - **Heavy pool**: Priority queue for CPU-bound tasks (verification, crypto)
//! - **Garbling coordinator**: Barrier-synchronized topology reads for garbling
//!
//! # Crate Layout
//!
//! ```text
//! job-scheduler/
//! ├── pool/       — Generic async thread pool (light & heavy)
//! ├── garbling/   — Garbling coordinator (reader, barrier, registration)
//! ├── handlers/   — Action execution logic (internal)
//! └── scheduler   — Top-level JobScheduler wiring
//! ```
//!
//! The SM Scheduler does not depend on this crate. It interacts with the job
//! system exclusively through [`mosaic_job_api`] types.

#[allow(dead_code, unreachable_pub)]
pub mod garbling;
pub(crate) mod pool;
pub mod scheduler;

pub(crate) mod handlers;
pub(crate) mod priority;

pub use scheduler::{JobScheduler, JobSchedulerConfig};

// Re-export the API crate for convenience.
pub use mosaic_job_api;

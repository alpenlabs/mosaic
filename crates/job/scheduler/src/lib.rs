//! Job scheduler implementation for Mosaic.
//!
//! This crate contains the execution infrastructure for actions emitted by
//! Garbler and Evaluator state machines. It provides three specialized pools:
//!
//! - **Light pool**: FIFO queue for I/O-bound tasks (sends, acks)
//! - **Heavy pool**: Priority queue for CPU-bound tasks (verification, crypto)
//! - **Garbling coordinator**: Barrier-synchronized circuit reads for garbling
//!
//! The scheduler is generic over `ExecuteGarblerJob` + `ExecuteEvaluatorJob`, which decouples
//! it from handler implementations. The concrete dispatch logic lives in a separate
//! crate (`mosaic-job-handlers`).
//!
//! The SM Scheduler does not depend on this crate. It interacts with the job
//! system exclusively through [`mosaic_job_api`] types.
//!

pub mod garbling;
pub(crate) mod pool;
pub mod scheduler;

pub(crate) mod priority;

// Re-export the API crate for convenience.
pub use mosaic_job_api;
pub use scheduler::{JobScheduler, JobSchedulerConfig};

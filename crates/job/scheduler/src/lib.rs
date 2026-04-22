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

pub mod garbling;
pub(crate) mod pool;
pub mod scheduler;

pub(crate) mod priority;

use mosaic_net_svc_api::PeerId;

#[derive(Debug)]
pub(crate) enum SchedulerFault {
    CompletionChannelClosed {
        source: &'static str,
        peer_id: PeerId,
    },
    ThreadExited {
        source: &'static str,
        thread: String,
        reason: String,
    },
}

// Re-export the API crate for convenience.
pub use garbling::GarblingConfig;
pub use mosaic_job_api;
pub use pool::PoolConfig;
pub use scheduler::{JobScheduler, JobSchedulerConfig, JobSchedulerController};

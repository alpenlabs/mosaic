//! Core types and traits for the job system.

mod id;
mod job;
mod result;
mod traits;

pub use id::JobId;
pub use job::{JobExecState, JobExecStatus, JobInfo, JobRecord};
pub use result::JobResult;
pub use traits::ResumableJob;

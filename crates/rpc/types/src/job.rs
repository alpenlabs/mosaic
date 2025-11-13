use serde::{Deserialize, Serialize};

/// General information about a job's processing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcJobStatus {
    /// What kind of job it is.
    job_ty: String,

    /// The state of a job's execution.
    state: RpcJobState,

    /// Total incremental work units processed.
    total_work_units: u32,

    /// The number of work units we've executed and persisted.
    completed_work_units: u32,
}

/// Describes a job's execution state.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcJobState {
    /// Job has been created but not running yet.
    Created,

    /// Job is currently running.
    Running,

    /// Job has finished successfully.
    Finished,

    /// Job has failed irrecoverably.
    Failed,
}

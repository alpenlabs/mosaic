use crate::JobId;

/// Data required to start a job.
#[derive(Debug)]
pub struct JobInfo {
    /// Identifier.
    pub id: JobId,
    /// Discriminant.
    pub job_type: String,
    // pub state_machine_id:
    /// Serialized `Input`.
    pub input: Vec<u8>,
}

/// JobInfo with execution status.
#[derive(Debug, Clone)]
pub struct JobRecord {
    /// Identifier.
    pub id: JobId,
    /// Discriminant.
    pub job_type: String,
    /// Serialized `Input`.
    pub input: Vec<u8>,
    /// Job execution status.
    pub state: JobExecState,
}

/// Describes a job's execution state.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(missing_docs, reason = "wip")]
pub enum JobExecState {
    /// Job has been created but not running yet.
    Created,

    /// Job is currently running.
    Running { snapshot: Option<Vec<u8>> },

    /// Job has finished successfully.
    Finished { output: Vec<u8> },

    /// Job has failed irrecoverably.
    Failed { reason: String },

    /// Job was cancelled.
    Cancelled,
}

/// Job execution status only, without associated data.
#[derive(Debug)]
pub enum JobExecStatus {
    /// Job has been created but not running yet.
    Created,

    /// Job is currently running.
    Running,

    /// Job has finished successfully.
    Finished,

    /// Job has failed irrecoverably.
    Failed,

    /// Job was cancelled.
    Cancelled,
}

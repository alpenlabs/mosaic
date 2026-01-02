use mosaic_job_types::{JobId, JobInfo, JobRecord};

use crate::StorageResult;

/// Storage backend for job persistence.
pub trait JobStateDb: Send + Sync + 'static {
    /// Load a job record by ID.
    fn load(&self, id: JobId) -> StorageResult<Option<JobRecord>>;

    /// Save or update a job record.
    fn save_new_job(&self, record: &JobInfo) -> StorageResult<()>;

    /// Update just the snapshot for a job.
    /// Should fail if job is not in `Running` state.
    fn update_snapshot(&self, id: JobId, snapshot: Vec<u8>) -> StorageResult<()>;

    /// Mark a job as completed with output.
    fn complete(&self, id: JobId, output: Vec<u8>) -> StorageResult<()>;

    /// Mark a job as failed with an error message.
    /// Should fail if job is already
    fn fail(&self, id: JobId, error: String) -> StorageResult<()>;
}

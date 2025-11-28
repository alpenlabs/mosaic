//! Database record types.

use mosaic_job_types::JobExecState;
use serde::{Deserialize, Serialize};

/// Unique identifier for a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub u64);

impl From<u64> for JobId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<JobId> for u64 {
    fn from(id: JobId) -> Self {
        id.0
    }
}

/// Persistent job record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    /// Unique job identifier.
    pub id: JobId,

    /// Type of job (e.g., "table_generation", "table_verification").
    pub job_type: String,

    /// Current execution state.
    pub state: JobExecState,

    /// Serialized job configuration.
    pub config: Vec<u8>,

    /// Unix timestamp when the job was created.
    pub created_at: i64,

    /// Unix timestamp when the job was last updated.
    pub updated_at: i64,

    /// Number of work units completed so far.
    pub completed_units: u64,

    /// Total number of work units (0 if unknown).
    pub total_units: u64,

    /// Error message if the job failed.
    pub error_message: Option<String>,
}

/// Filter criteria for querying jobs.
#[derive(Debug, Default, Clone)]
pub struct JobFilter {
    /// Filter by execution state.
    pub state: Option<JobExecState>,

    /// Filter by job type.
    pub job_type: Option<String>,

    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

impl JobFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by state.
    pub fn with_state(mut self, state: JobExecState) -> Self {
        self.state = Some(state);
        self
    }

    /// Filter by job type.
    pub fn with_job_type(mut self, job_type: impl Into<String>) -> Self {
        self.job_type = Some(job_type.into());
        self
    }

    /// Limit number of results.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Result of a job execution.
#[derive(Debug)]
pub enum JobResult {
    /// Job completed successfully with serialized output.
    Completed(Vec<u8>),
    /// Job failed with an error message.
    Failed(String),
    /// Job was cancelled.
    Cancelled,
}

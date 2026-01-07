/// Unique identifier for a job.
///
/// The executor is responsible for deriving deterministic IDs
/// based on job type and input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub [u8; 32]);

use std::error::Error;

/// State machine executor error.
#[derive(Debug)]
pub enum ExecutorError {
    /// State machine execution error.
    StateMachine(Box<dyn Error>),
}

impl ExecutorError {
    /// state machine error.
    pub fn state_machine(err: impl Error + 'static) -> Self {
        Self::StateMachine(Box::new(err))
    }
}

/// State machine executor result.
pub type ExecutorResult<T> = Result<T, ExecutorError>;

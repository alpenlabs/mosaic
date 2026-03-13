use kanal::AsyncSender;

use crate::SmCommand;

/// Error returned when SM executor is shut down.
#[derive(Debug)]
pub struct ExecutorStopped;

impl std::fmt::Display for ExecutorStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sm executor is shut down")
    }
}

impl std::error::Error for ExecutorStopped {}

/// Cloneable handle for interacting with SM executor.
#[derive(Debug, Clone)]
pub struct SmExecutorHandle {
    command_tx: AsyncSender<SmCommand>,
}

impl SmExecutorHandle {
    /// Create handle from command sender.
    #[doc(hidden)]
    pub fn new(command_tx: AsyncSender<SmCommand>) -> Self {
        Self { command_tx }
    }

    /// Send command to SM executor.
    pub async fn send(&self, cmd: SmCommand) -> Result<(), ExecutorStopped> {
        self.command_tx.send(cmd).await.map_err(|_| ExecutorStopped)
    }
}

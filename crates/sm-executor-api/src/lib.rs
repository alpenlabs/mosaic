//! Public API surface for the SM executor.

mod command;
mod config;
mod handle;

pub use command::{
    DepositInitData, DisputedWithdrawalData, InitData, SmCommand, SmCommandKind, SmRole, SmTarget,
};
pub use config::SmExecutorConfig;
pub use handle::{ExecutorStopped, SmExecutorHandle};

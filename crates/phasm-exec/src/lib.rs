//! Async executor framework for phasm state machines.
//!
//! This crate provides an async runtime for phasm `StateMachine` instances
//! with:
//!
//! - **Durable input queue**: Inputs are persisted before processing, enabling
//!   replay on restart for exactly-once processing semantics
//! - **Integrated action execution**: The executor runs the STF and dispatches
//!   actions, handling tracked action results automatically
//! - **Watch/notify waking**: Opaque handles for signaling new input arrival
//! - **Recovery flow**: On restart, loads state, restores pending actions, and
//!   replays unprocessed inputs
//!
//! # Architecture
//!
//! The executor is built around three core traits:
//!
//! - [`PhasmProvider`]: Abstracts state persistence and input queue reading
//! - [`ActionExecutor`]: Handles execution of tracked and untracked actions
//! - [`phasm::StateMachine`]: The state machine being executed
//!
//! # Example
//!
//! ```ignore
//! use mosaic_phasm_exec::{
//!     run_worker, create_input_channel, create_shutdown_channel,
//!     WorkerConfig,
//! };
//!
//! let (notifier, sender) = create_input_channel();
//! let (shutdown_handle, shutdown_rx) = create_shutdown_channel();
//!
//! // Spawn worker
//! let handle = tokio::spawn(async move {
//!     run_worker::<MyStateMachine, _, _>(
//!         WorkerConfig::default(),
//!         MyState::default(),
//!         provider,
//!         executor,
//!         notifier,
//!         shutdown_rx,
//!     ).await
//! });
//!
//! // External code persists inputs and notifies
//! sender.notify();
//!
//! // Later, shut down
//! shutdown_handle.shutdown();
//! handle.await?;
//! ```

mod error;
mod executor;
mod notify;
pub mod phasm;
mod provider;
#[cfg(test)]
mod tests;
mod types;
mod worker;

// Re-export error types
pub use error::{Error, Result};

// Re-export notification handles
pub use notify::{
    create_input_channel, create_shutdown_channel, InputNotifier, InputSender, ShutdownHandle,
    ShutdownReceiver,
};

// Re-export traits
pub use executor::ActionExecutor;
pub use provider::PhasmProvider;

// Re-export types
pub use types::{InputSeqNo, PersistedInput, WorkerConfig};

// Re-export worker function
pub use worker::run_worker;

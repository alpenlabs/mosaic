//! protocol state machines

pub mod deposit;
mod error;
pub mod garbler;
pub mod setup;

pub use error::{SMError, SMResult};

//! protocol state machines

mod common;
mod error;
pub mod evaluator;
pub mod garbler;

pub use error::{ResultOptionExt, SMError, SMResult};

#[cfg(test)]
mod tests;

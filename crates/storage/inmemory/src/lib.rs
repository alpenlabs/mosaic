//! In-memory implementation for state machine states

pub mod error;
pub mod evaluator;
pub mod garbler;
/// In-memory storage provider and mutable session handles.
pub mod provider;

pub use provider::InMemoryStorageProvider;

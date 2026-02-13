//! Action execution handlers.
//!
//! This module contains the logic for executing each action type emitted by
//! the state machines. Handlers are internal to the scheduler — workers invoke
//! them as opaque one-shot async tasks.
//!
//! Each handler takes an action and produces a [`JobResult`] containing an
//! [`ActionCompletion`] with the tracked action ID and result, ready to be
//! routed back to the originating SM as `TrackedActionCompleted { id, result }`.
//!
//! # Responsibilities
//!
//! - **Light handlers**: Network sends and acks via `net-client`
//! - **Heavy handlers**: Cryptographic operations (verification, adaptor
//!   signatures, polynomial generation)
//! - **Garbling handlers**: Processing gate chunks with a given seed

pub(crate) mod evaluator;
pub(crate) mod garbler;

/// Shared resources available to all handlers during execution.
///
/// Constructed once by the scheduler and passed to each job by reference.
/// All fields are cheaply cloneable or behind `Arc`.
pub struct HandlerContext {
    /// Typed network client for protocol message sends and acks.
    #[allow(dead_code)]
    pub net_client: mosaic_net_client::NetClient,
    // TODO: storage / artifact store handle
    // TODO: crypto primitives / precomputed tables
}

impl std::fmt::Debug for HandlerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerContext").finish_non_exhaustive()
    }
}

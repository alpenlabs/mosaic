//! Action execution handlers.
//!
//! This module contains the logic for executing each action type emitted by
//! the state machines. Handlers are internal to the scheduler — workers invoke
//! them as opaque one-shot async tasks.
//!
//! Each handler takes an action and produces an [`ActionCompletion`] with the
//! tracked action ID and result, ready to be routed back to the originating SM
//! as `TrackedActionCompleted { id, result }`.
//!
//! # Responsibilities
//!
//! - **Light handlers**: Network sends and acks via `net-client`
//! - **Heavy handlers**: Cryptographic operations (verification, adaptor
//!   signatures, polynomial generation)
//! - **Garbling handlers**: Processing gate chunks with a given seed

use crate::polynomial_cache::PolynomialCache;

pub(crate) mod evaluator;
pub(crate) mod garbler;

/// Shared resources available to all handlers during execution.
///
/// Constructed once by the scheduler and passed to each job by reference.
/// All fields are cheaply cloneable or behind `Arc`.
pub struct HandlerContext {
    /// Typed network client for protocol message sends and acks.
    pub net_client: mosaic_net_client::NetClient,
    /// Polynomial cache for garbler setup (generate-once, read-181-times).
    pub polynomial_cache: PolynomialCache,
}

impl HandlerContext {
    /// Create a new handler context with default polynomial cache size.
    pub fn new(net_client: mosaic_net_client::NetClient) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(4),
        }
    }

    /// Create a new handler context with a custom polynomial cache size.
    pub fn with_cache_size(
        net_client: mosaic_net_client::NetClient,
        max_cache_entries: usize,
    ) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(max_cache_entries),
        }
    }
}

impl std::fmt::Debug for HandlerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerContext").finish_non_exhaustive()
    }
}

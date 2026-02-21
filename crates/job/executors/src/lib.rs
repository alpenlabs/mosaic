//! Action executor implementations for the Mosaic job scheduler.
//!
//! Provides [`MosaicExecutor`], the concrete implementation of the
//! [`JobExecutor`] trait defined in `mosaic-job-api`.
//!
//! This crate provides [`MosaicExecutor`], the concrete implementation of the
//! [`JobExecutor`] trait. The scheduler is generic over `JobExecutor` and has
//! no compile-time dependency on the execution logic in this crate.
//!
//! # Modules
//!
//! - [`garbler`] / [`evaluator`] — per-role action execution.
//! - [`garbling`] — reusable [`GarblingSession`](garbling::GarblingSession) for
//!   circuit garbling (shared by commitment and transfer actions).
//! - [`polynomial_cache`] — bounded cache for polynomial data during setup.

use std::path::PathBuf;

pub mod evaluator;
pub mod garbler;
pub mod garbling;
pub mod polynomial_cache;

use mosaic_job_api::{HandlerOutcome, JobExecutor};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;

use crate::polynomial_cache::PolynomialCache;

/// Concrete executor for Mosaic job actions.
///
/// Holds all resources needed by action executors: network client, polynomial
/// cache, and a [`StorageProvider`] for reading state machine data.
///
/// Generic over [`StorageProvider`] so the storage backend (in-memory, FDB,
/// etc.) is pluggable without changing execution logic.
pub struct MosaicExecutor<SP: StorageProvider> {
    /// Typed network client for protocol message sends and acks.
    pub net_client: mosaic_net_client::NetClient,
    /// Polynomial cache for garbler setup (generate-once, read-many-times).
    pub polynomial_cache: PolynomialCache,
    /// Per-peer storage provider for reading state machine data.
    pub storage: SP,
    /// Path to the v5c circuit file used for garbling and evaluation.
    pub circuit_path: PathBuf,
}

impl<SP: StorageProvider> MosaicExecutor<SP> {
    /// Create a new executor with default polynomial cache size.
    pub fn new(
        net_client: mosaic_net_client::NetClient,
        storage: SP,
        circuit_path: PathBuf,
    ) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(4),
            storage,
            circuit_path,
        }
    }

    /// Create a new executor with a custom polynomial cache size.
    pub fn with_cache_size(
        net_client: mosaic_net_client::NetClient,
        storage: SP,
        circuit_path: PathBuf,
        max_cache_entries: usize,
    ) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(max_cache_entries),
            storage,
            circuit_path,
        }
    }
}

impl<SP: StorageProvider> std::fmt::Debug for MosaicExecutor<SP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MosaicExecutor").finish_non_exhaustive()
    }
}

impl<SP: StorageProvider> JobExecutor for MosaicExecutor<SP> {
    fn execute_garbler(
        &self,
        peer_id: &PeerId,
        action: &mosaic_cac_types::state_machine::garbler::Action,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::execute(self, peer_id, action)
    }

    fn execute_evaluator(
        &self,
        peer_id: &PeerId,
        action: &mosaic_cac_types::state_machine::evaluator::Action,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::execute(self, peer_id, action)
    }
}

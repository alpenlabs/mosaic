//! Garbling coordinator for synchronized topology reads.
//!
//! **Note:** This module is scaffolding — most types are not yet wired up.
//!
//! Garbling operations must read a 130GB topology file containing circuit gate
//! definitions. With `O_DIRECT`, concurrent readers at different file offsets
//! cause disk thrashing. Sequential reads are dramatically faster.
//!
//! The coordinator solves this with a single reader thread that reads the
//! topology sequentially, broadcasting gate chunks to all active garbling jobs.
//! Jobs process chunks in lockstep, synchronized by a barrier.
//!
//! # Key Insight
//!
//! All circuits share the same topology — only the garbling seeds differ. One
//! sequential read serves N concurrent jobs, each producing 43GB of different
//! output (streamed to a peer or hashed for commitment).
//!
//! # Chunk Cycle
//!
//! 1. Reader reads next chunk sequentially from topology file
//! 2. Coordinator pushes chunk to workers (round-robin, spread-first)
//! 3. Workers garble with job-specific seeds, stream or hash output
//! 4. Barrier waits for all jobs to complete the chunk
//! 5. Repeat until topology exhausted

mod reader;
mod registration;

use std::sync::Arc;

use kanal::AsyncSender;
use mosaic_job_api::JobCompletion;

pub use registration::GarblingJobHandle;

/// Configuration for the garbling coordinator.
#[derive(Debug, Clone)]
pub struct GarblingConfig {
    /// Number of worker threads dedicated to garbling.
    pub threads: usize,
    /// Maximum concurrent garbling tasks per worker.
    pub concurrency_per_worker: usize,
    /// Size of each topology chunk read from disk.
    pub chunk_size: usize,
    /// Path to the topology file.
    pub topology_path: std::path::PathBuf,
}

impl Default for GarblingConfig {
    fn default() -> Self {
        Self {
            threads: 4,
            concurrency_per_worker: 8,
            chunk_size: 64 * 1024 * 1024, // 64 MB
            topology_path: std::path::PathBuf::new(),
        }
    }
}

/// Output mode for a garbling job.
#[derive(Debug)]
pub enum GarblingOutput {
    /// Stream garbled output to a peer.
    Stream,
    /// Hash garbled output for commitment.
    Hash,
}

/// Coordinates garbling jobs to share sequential topology reads.
///
/// The coordinator owns a single reader thread and a pool of dedicated workers.
/// Garbling jobs register with the coordinator and receive gate chunks via their
/// handles. The first registered job starts the reader; the last unregistered
/// job stops it.
///
/// Jobs arriving mid-read-through wait for the next full pass — partial
/// garbling tables are useless.
pub struct GarblingCoordinator {
    config: GarblingConfig,
    state: Arc<CoordinatorState>,
    completion_tx: AsyncSender<JobCompletion>,
}

/// Shared state between coordinator, reader, and workers.
struct CoordinatorState {
    // TODO: active jobs registry, barrier, reader control
}

impl std::fmt::Debug for GarblingCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarblingCoordinator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GarblingCoordinator {
    /// Create a new garbling coordinator.
    pub fn new(config: GarblingConfig, completion_tx: AsyncSender<JobCompletion>) -> Self {
        Self {
            config,
            state: Arc::new(CoordinatorState {}),
            completion_tx,
        }
    }

    /// Register a garbling job with the coordinator.
    ///
    /// The job will participate in the next full topology read-through.
    /// If this is the first active job, the reader thread is started.
    ///
    /// Returns a handle that the job uses to receive gate chunks and signal
    /// chunk completion.
    pub fn register_job(&self, _seed: [u8; 32], _mode: GarblingOutput) -> GarblingJobHandle {
        // TODO: add to active jobs, start reader if first job
        unimplemented!()
    }

    /// Unregister a garbling job.
    ///
    /// If this is the last active job, the reader thread is stopped.
    pub fn unregister_job(&self, _handle: GarblingJobHandle) {
        // TODO: remove from active jobs, stop reader if last job
        unimplemented!()
    }

    /// Shut down the coordinator gracefully.
    ///
    /// Waits for the current chunk cycle to complete, then stops the reader
    /// and all workers.
    pub fn shutdown(self) {
        // TODO: signal reader to stop, join worker threads
    }
}

//! Garbling coordinator for synchronized circuit reading.
//!
//! Garbling operations read a ~130 GB v5c circuit file. Concurrent readers at
//! different offsets cause disk thrashing. Sequential reads are dramatically
//! faster.
//!
//! The coordinator solves this with ckt's [`ReaderV5c`] (triple-buffered monoio
//! broadcasting blocks to all active garbling sessions. Each session
//! maintains its own ~1 GB working space and produces different output from the
//! same gate stream (only the garbling seed differs).
//!
//! [`ReaderV5c`]: https://docs.rs/ckt-fmtv5-types

use kanal::AsyncSender;
use mosaic_job_api::JobCompletion;

/// Configuration for the garbling coordinator.
#[derive(Debug, Clone)]
pub struct GarblingConfig {
    /// Maximum concurrent garbling sessions. Each session uses ~1 GB of RAM
    /// for the circuit working space, so this effectively caps garbling memory
    /// at `max_concurrent * 1 GB`.
    pub max_concurrent: usize,
    /// Path to the v5c circuit file.
    pub topology_path: std::path::PathBuf,
}

impl Default for GarblingConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            topology_path: std::path::PathBuf::new(),
        }
    }
}

/// Coordinates garbling jobs to share sequential circuit reads.
///
/// The coordinator uses ckt's `ReaderV5c` to read the circuit file once,
/// broadcasting blocks to all registered `GarblingSession`s. Sessions
/// process blocks in lockstep via a barrier, preventing any single session
/// from racing ahead and causing the reader to buffer unboundedly.
///
/// Jobs arriving mid-read-through wait for the next full pass — partial
/// garbling tables are useless.
pub struct GarblingCoordinator {
    config: GarblingConfig,
    completion_tx: AsyncSender<JobCompletion>,
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
            completion_tx,
        }
    }

    /// Shut down the coordinator gracefully.
    pub fn shutdown(self) {
        // TODO: wait for in-progress garbling pass to complete
    }
}

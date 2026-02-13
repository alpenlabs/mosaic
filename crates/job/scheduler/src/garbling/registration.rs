//! Garbling job registration and handle types.
//!
//! When a garbling action is submitted, the scheduler registers it with the
//! [`GarblingCoordinator`](super::GarblingCoordinator). The coordinator returns
//! a [`GarblingJobHandle`] that the job uses to receive gate chunks and signal
//! chunk completion.
//!
//! The handle is the job's only interface to the coordinator — it does not
//! expose any coordinator internals.

use std::sync::atomic::{AtomicU64, Ordering};

use super::GarblingOutput;
use super::reader::GateChunk;

/// Unique identifier for a registered garbling job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GarblingJobId(u64);

impl GarblingJobId {
    /// Generate a new unique job ID.
    pub(crate) fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for GarblingJobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "garbling-job-{}", self.0)
    }
}

/// Handle for a garbling job registered with the coordinator.
///
/// Created by [`GarblingCoordinator::register_job`](super::GarblingCoordinator::register_job)
/// and used by the job to participate in the coordinated chunk cycle:
///
/// 1. Await the next gate chunk via [`recv_chunk`](Self::recv_chunk)
/// 2. Process the chunk (garble with seed, stream or hash output)
/// 3. Signal completion via [`chunk_done`](Self::chunk_done)
/// 4. Repeat until `recv_chunk` returns `None` (topology exhausted)
pub struct GarblingJobHandle {
    id: GarblingJobId,
    /// Receives gate chunks broadcast by the coordinator.
    chunk_rx: kanal::AsyncReceiver<GateChunk>,
    /// Signals the coordinator that this job has finished processing a chunk.
    done_tx: kanal::AsyncSender<ChunkCompletion>,
}

impl std::fmt::Debug for GarblingJobHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarblingJobHandle")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl GarblingJobHandle {
    /// Create a new handle.
    ///
    /// Called internally by the coordinator during job registration.
    pub(crate) fn new(
        id: GarblingJobId,
        chunk_rx: kanal::AsyncReceiver<GateChunk>,
        done_tx: kanal::AsyncSender<ChunkCompletion>,
    ) -> Self {
        Self {
            id,
            chunk_rx,
            done_tx,
        }
    }

    /// The unique identifier for this garbling job.
    pub fn id(&self) -> GarblingJobId {
        self.id
    }

    /// Receive the next gate chunk from the topology reader.
    ///
    /// Returns `None` when the topology has been fully read (current pass
    /// complete) or the coordinator has shut down.
    pub async fn recv_chunk(&self) -> Option<GateChunk> {
        self.chunk_rx.recv().await.ok()
    }

    /// Signal that this job has finished processing the current chunk.
    ///
    /// The coordinator waits for all registered jobs to signal completion
    /// before the reader proceeds to the next chunk. This barrier prevents
    /// the reader from getting ahead of slow consumers.
    pub async fn chunk_done(&self) {
        let _ = self.done_tx.send(ChunkCompletion { job_id: self.id }).await;
    }
}

/// Completion signal sent from a job back to the coordinator.
#[derive(Debug)]
pub(crate) struct ChunkCompletion {
    /// Which job completed the chunk.
    pub job_id: GarblingJobId,
}

/// Registration request for a new garbling job.
///
/// Passed to the coordinator which creates the channels and returns a
/// [`GarblingJobHandle`].
#[derive(Debug)]
pub(crate) struct JobRegistration {
    /// Unique identifier assigned to this job.
    pub id: GarblingJobId,
    /// Garbling seed for this circuit.
    pub seed: [u8; 32],
    /// Whether to stream output to a peer or hash for commitment.
    pub mode: GarblingOutput,
    /// Coordinator sends chunks to the job through this channel.
    pub chunk_tx: kanal::Sender<GateChunk>,
    /// Job signals chunk completion through this channel.
    pub done_rx: kanal::Receiver<ChunkCompletion>,
}

impl JobRegistration {
    /// Create a new registration, returning it alongside the job handle.
    ///
    /// The registration is kept by the coordinator; the handle is given to the
    /// job.
    pub fn new(seed: [u8; 32], mode: GarblingOutput) -> (Self, GarblingJobHandle) {
        let id = GarblingJobId::next();

        // Per-job channels: coordinator → job (chunks) and job → coordinator (done).
        // Bounded to 1 enforces lockstep: coordinator can only push the next
        // chunk after the job has consumed the previous one.
        let (chunk_tx, chunk_rx) = kanal::bounded(1);
        let (done_tx, done_rx) = kanal::bounded(1);

        let registration = Self {
            id,
            seed,
            mode,
            chunk_tx,
            done_rx,
        };

        let handle =
            GarblingJobHandle::new(id, chunk_rx.as_async().clone(), done_tx.as_async().clone());

        (registration, handle)
    }
}

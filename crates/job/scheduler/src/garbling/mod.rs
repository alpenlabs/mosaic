//! Garbling coordinator for synchronized circuit reading.
//!
//! Garbling operations read a ~130 GB v5c circuit file. Concurrent readers at
//! different offsets cause disk thrashing. Sequential reads are dramatically
//! faster.
//!
//! The coordinator batches pending circuit sessions into **passes**. Each pass
//! reads the circuit file once via [`ReaderV5c`], converting blocks into
//! [`Arc<OwnedChunk>`] and broadcasting them to all active sessions. Sessions
//! process chunks in lockstep; a per-session timeout evicts slow consumers
//! (e.g. G8 with a congested peer) without blocking the rest.
//!
//! # Flow
//!
//! 1. Scheduler receives a circuit action (G3/E3/G8/E4/E8).
//! 2. Scheduler calls the executor's `begin_*` method → gets a [`CircuitSession`].
//! 3. Scheduler submits the session to the coordinator via [`GarblingCoordinator::submit`].
//! 4. Coordinator collects sessions, starts a pass, drives them block-by-block.
//! 5. Completions flow back through the completion channel.
//!
//! [`ReaderV5c`]: ckt_fmtv5_types::v5::c::ReaderV5c
//! [`CircuitSession`]: mosaic_job_api::CircuitSession
//! [`Arc<OwnedChunk>`]: mosaic_job_api::OwnedChunk

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ckt_fmtv5_types::v5::c::{Block, ReaderV5c, get_block_num_gates};
use mosaic_job_api::{CircuitSession, HandlerOutcome, JobCompletion, OwnedBlock, OwnedChunk};
use mosaic_net_svc_api::PeerId;

/// Size of each v5c block in bytes (gates region only, for copying).
const GATE_SIZE: usize = 12; // 3 × u32

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════

/// Configuration for the garbling coordinator.
#[derive(Debug, Clone)]
pub struct GarblingConfig {
    /// Maximum concurrent sessions per pass. Each session uses ~1 GB of RAM,
    /// so this effectively caps garbling memory at `max_concurrent * ~1 GB`.
    pub max_concurrent: usize,
    /// Path to the v5c circuit file.
    pub circuit_path: PathBuf,
    /// Maximum time to wait for more sessions before starting a pass with
    /// fewer than `max_concurrent` sessions.
    pub batch_timeout: Duration,
    /// Per-session, per-chunk timeout. If a session doesn't finish processing
    /// a chunk within this duration, it is evicted from the pass and its job
    /// is considered failed (the scheduler will requeue it).
    pub chunk_timeout: Duration,
}

impl Default for GarblingConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            circuit_path: PathBuf::new(),
            batch_timeout: Duration::from_millis(500),
            chunk_timeout: Duration::from_secs(30),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Submitted session
// ════════════════════════════════════════════════════════════════════════════

/// A circuit session submitted to the coordinator, along with the metadata
/// needed to produce a [`JobCompletion`] when it finishes.
pub struct SubmittedSession {
    /// The peer this session belongs to.
    pub peer_id: PeerId,
    /// The live session that will be driven block-by-block.
    pub session: Box<dyn CircuitSession>,
}

impl std::fmt::Debug for SubmittedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmittedSession")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Coordinator
// ════════════════════════════════════════════════════════════════════════════

/// Coordinates garbling jobs to share sequential circuit reads.
///
/// Submit pre-created [`CircuitSession`]s via [`submit`](Self::submit). The
/// coordinator batches them into passes and drives them through the circuit
/// file block-by-block.
pub struct GarblingCoordinator {
    config: GarblingConfig,
    /// Channel for submitting sessions from the scheduler thread.
    submit_tx: kanal::Sender<SubmittedSession>,
    /// Handle to the coordinator thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for GarblingCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarblingCoordinator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GarblingCoordinator {
    /// Create and start the garbling coordinator.
    ///
    /// Spawns a dedicated monoio thread that runs the pass loop. Sessions
    /// submitted via [`submit`](Self::submit) are collected and driven
    /// through the circuit file.
    pub fn new(config: GarblingConfig, completion_tx: kanal::AsyncSender<JobCompletion>) -> Self {
        let (submit_tx, submit_rx) = kanal::bounded(config.max_concurrent * 2);

        let cfg = config.clone();
        let thread = std::thread::Builder::new()
            .name("garbling-coordinator".into())
            .spawn(move || {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("failed to build monoio runtime for garbling coordinator")
                    .block_on(coordinator_loop(cfg, submit_rx.to_async(), completion_tx));
            })
            .expect("failed to spawn garbling coordinator thread");

        Self {
            config,
            submit_tx,
            thread: Some(thread),
        }
    }

    /// Submit a circuit session to be driven through the next pass.
    ///
    /// If the coordinator is mid-pass, the session waits for the next one.
    /// This method is synchronous (called from the scheduler's dispatch loop).
    pub fn submit(&self, session: SubmittedSession) {
        if self.submit_tx.send(session).is_err() {
            tracing::error!("garbling coordinator channel closed — session dropped");
        }
    }

    /// Shut down the coordinator gracefully.
    ///
    /// Closes the submission channel, waits for the current pass to finish,
    /// then joins the coordinator thread.
    pub fn shutdown(&mut self) {
        // Close the submit channel — the coordinator loop will exit after
        // finishing any in-progress pass.
        let _ = self.submit_tx.close();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}


// ════════════════════════════════════════════════════════════════════════════
// Coordinator loop
// ════════════════════════════════════════════════════════════════════════════

/// Main loop running on the coordinator's monoio thread.
///
/// Collects submitted sessions into batches, then runs a pass for each batch.
async fn coordinator_loop(
    config: GarblingConfig,
    submit_rx: kanal::AsyncReceiver<SubmittedSession>,
    completion_tx: kanal::AsyncSender<JobCompletion>,
) {
    tracing::info!(
        max_concurrent = config.max_concurrent,
        "garbling coordinator started"
    );

    loop {
        // ── Collect a batch ──────────────────────────────────────────
        let mut batch: Vec<SubmittedSession> = Vec::with_capacity(config.max_concurrent);

        // Wait for at least one session.
        match submit_rx.recv().await {
            Ok(session) => batch.push(session),
            Err(_) => break, // Channel closed — shut down.
        }

        // Try to collect more sessions up to max_concurrent, with a timeout.
        let deadline = monoio::time::Instant::now() + config.batch_timeout;
        while batch.len() < config.max_concurrent {
            let remaining = deadline.saturating_duration_since(monoio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match monoio::time::timeout(remaining, submit_rx.recv()).await {
                Ok(Ok(session)) => batch.push(session),
                Ok(Err(_)) => break, // Channel closed.
                Err(_) => break,     // Timeout — start pass with what we have.
            }
        }

        if batch.is_empty() {
            continue;
        }

        tracing::info!(sessions = batch.len(), "starting garbling pass");

        // ── Run the pass ─────────────────────────────────────────────
        run_pass(&config, &mut batch, &completion_tx).await;

        tracing::info!("garbling pass complete");
    }

    tracing::info!("garbling coordinator shutting down");
}

/// Run a single pass: read the circuit file once, driving all sessions
/// block-by-block.
async fn run_pass(
    config: &GarblingConfig,
    batch: &mut Vec<SubmittedSession>,
    completion_tx: &kanal::AsyncSender<JobCompletion>,
) {
    // Open the shared circuit reader.
    let mut reader = match ReaderV5c::open(&config.circuit_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%e, "failed to open circuit file — failing all sessions");
            for submitted in batch.drain(..) {
                let outcome = HandlerOutcome::Retry;
                let _ = completion_tx
                    .send(JobCompletion {
                        peer_id: submitted.peer_id,
                        completion: match outcome {
                            HandlerOutcome::Done(c) => c,
                            HandlerOutcome::Retry => {
                                // Can't produce a valid completion for Retry at this level.
                                // The session will be resubmitted by the scheduler.
                                continue;
                            }
                        },
                    })
                    .await;
            }
            return;
        }
    };

    let total_gates = reader.header().total_gates();
    let outputs = reader.outputs().to_vec();
    let mut block_idx: usize = 0;

    // ── Read blocks and broadcast to all sessions ────────────────────
    while let Some(chunk_result) = reader.next_blocks_chunk().await.transpose() {
        let reader_chunk = match chunk_result {
            Ok(chunk) => chunk,
            Err(e) => {
                tracing::error!(%e, "circuit read error — aborting pass");
                break;
            }
        };

        // Convert borrowed blocks to owned, wrap in Arc for sharing.
        let owned = convert_chunk(&reader_chunk, total_gates, &mut block_idx);
        let shared = Arc::new(owned);

        // Drive each session with a per-session timeout.
        let mut evicted_indices: Vec<usize> = Vec::new();

        for (i, submitted) in batch.iter_mut().enumerate() {
            let result = monoio::time::timeout(
                config.chunk_timeout,
                submitted.session.process_chunk(&shared),
            )
            .await;

            match result {
                Ok(Ok(())) => { /* session keeping up */ }
                Ok(Err(e)) => {
                    tracing::warn!(?e, peer = ?submitted.peer_id, "session error — evicting");
                    evicted_indices.push(i);
                }
                Err(_timeout) => {
                    tracing::warn!(peer = ?submitted.peer_id, "session timed out — evicting");
                    evicted_indices.push(i);
                }
            }
        }

        // Remove evicted sessions (iterate in reverse to keep indices valid).
        for &idx in evicted_indices.iter().rev() {
            let _evicted = batch.remove(idx);
            // Evicted session is dropped — the scheduler will retry the action
            // because no completion is sent for it.
        }

        if batch.is_empty() {
            tracing::warn!("all sessions evicted — aborting pass");
            return;
        }
    }

    // ── Finalize all surviving sessions ──────────────────────────────
    for submitted in batch.drain(..) {
        let peer_id = submitted.peer_id;
        let outcome = submitted.session.finish().await;

        match outcome {
            HandlerOutcome::Done(completion) => {
                let _ = completion_tx
                    .send(JobCompletion {
                        peer_id,
                        completion,
                    })
                    .await;
            }
            HandlerOutcome::Retry => {
                // Session wants to retry — don't send a completion.
                // The scheduler will resubmit the action.
                tracing::debug!(?peer_id, "session finished with Retry");
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Block conversion
// ════════════════════════════════════════════════════════════════════════════

/// Convert a borrowed chunk of blocks from the circuit reader into an owned
/// [`OwnedChunk`] suitable for sharing across sessions via [`Arc`].
fn convert_chunk(
    reader_chunk: &ckt_fmtv5_types::v5::c::Chunk<'_>,
    total_gates: u64,
    block_idx: &mut usize,
) -> OwnedChunk {
    let mut blocks = Vec::new();

    for block in reader_chunk.blocks_iter() {
        let num_gates = get_block_num_gates(total_gates, *block_idx);
        *block_idx += 1;

        blocks.push(convert_block(block, num_gates));
    }

    OwnedChunk { blocks }
}

/// Convert a single borrowed [`Block`] into an [`OwnedBlock`].
///
/// Copies the gate data (in1, in2, out as raw bytes) and gate type bits.
/// Each block is ~256 KiB — this copy is negligible compared to the
/// garbling/evaluation work.
fn convert_block(block: &Block, num_gates: usize) -> OwnedBlock {
    // Copy gate data: num_gates × 12 bytes (3 × u32 LE).
    let gate_bytes = num_gates * GATE_SIZE;
    let gate_ptr = block.gates.as_ptr() as *const u8;
    let gate_data = unsafe { std::slice::from_raw_parts(gate_ptr, gate_bytes) }.to_vec();

    // Copy gate type bits: ceil(num_gates / 8) bytes.
    let type_bytes = num_gates.div_ceil(8);
    let gate_types = block.types[..type_bytes].to_vec();

    OwnedBlock {
        gate_data,
        gate_types,
        num_gates,
    }
}

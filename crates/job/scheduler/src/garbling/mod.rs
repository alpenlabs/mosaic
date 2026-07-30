//! Garbling coordinator for synchronized circuit reading.
//!
//! Garbling operations read a ~130 GB v5c circuit file. Concurrent readers at
//! different offsets cause disk thrashing. Sequential reads are dramatically
//! faster.
//!
//! # Architecture
//!
//! The coordinator has a **main thread** that reads the circuit file and
//! **N worker threads** that process sessions in parallel:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │           Main thread (coordinator_loop)             │
//! │  collect jobs → create sessions → read circuit       │
//! │                                                     │
//! │  For each chunk:                                    │
//! │    read → Arc<OwnedChunk> ──broadcast──┬──┬──┬──┐  │
//! │                                        │  │  │  │  │
//! │    wait for all reports ◄──barrier──────┘──┘──┘──┘  │
//! └─────────────────────────────────────────────────────┘
//!         │           │           │           │
//!    ┌────▼───┐  ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
//!    │Worker 0│  │Worker 1│  │Worker 2│  │Worker 3│
//!    │sessions│  │sessions│  │sessions│  │sessions│
//!    │ A, E   │  │ B, F   │  │ C, G   │  │ D, H   │
//!    └────────┘  └────────┘  └────────┘  └────────┘
//! ```
//!
//! # Pass Lifecycle
//!
//! 1. Collect [`PendingCircuitJob`]s from the submission channel and retry list.
//! 2. Create live [`CircuitSession`]s via the [`SessionFactory`]. Jobs that fail with
//!    [`CircuitError::StorageUnavailable`] stay on the retry list — **no action is ever silently
//!    dropped**.
//! 3. Distribute sessions across worker threads (round-robin, spread-first).
//! 4. Read the circuit file once via [`ReaderV5c`], converting blocks into [`Arc<OwnedChunk>`] and
//!    broadcasting to all workers.
//! 5. Workers process their sessions concurrently. Per-session timeout evicts slow consumers (e.g.
//!    G8 with a congested peer) without blocking others. Evicted actions go to the retry list.
//! 6. After all blocks: workers finalize sessions, report completions, and the coordinator forwards
//!    them to the SM.
//!
//! [`ReaderV5c`]: ckt_fmtv5_types::v5::c::ReaderV5c
//! [`CircuitSession`]: mosaic_job_api::CircuitSession
//! [`SessionFactory`]: mosaic_job_api::SessionFactory
//! [`PendingCircuitJob`]: mosaic_job_api::PendingCircuitJob
//! [`CircuitAction`]: mosaic_job_api::CircuitAction
//! [`Arc<OwnedChunk>`]: mosaic_job_api::OwnedChunk

use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use ckt_fmtv5_types::v5::c::{Block, ReaderV5c, get_block_num_gates};
use mosaic_job_api::{
    CircuitError, CircuitSession, HandlerOutcome, JobCompletion, OwnedBlock, OwnedChunk,
    PendingCircuitJob, SessionFactory,
};
use mosaic_net_svc_api::PeerId;
use tracing::Instrument;

use crate::SchedulerFault;

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "thread panicked".to_string(),
        },
    }
}

/// Size of each v5c gate record in bytes (3 × u32).
const GATE_SIZE: usize = 12;

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════

/// Configuration for the garbling coordinator.
#[derive(Debug, Clone)]
pub struct GarblingConfig {
    /// Number of worker threads for concurrent session processing.
    /// Each worker runs its own monoio runtime. Default: 4.
    pub worker_threads: usize,
    /// Maximum concurrent sessions per pass. Each session uses ~1 GB of RAM,
    /// so this effectively caps garbling memory at `max_concurrent * ~1 GB`.
    /// Sessions are distributed round-robin across worker threads.
    pub max_concurrent: usize,
    /// Path to the v5c circuit file.
    pub circuit_path: PathBuf,
    /// Maximum time to wait for more jobs before starting a pass with fewer
    /// than `max_concurrent` sessions.
    pub batch_timeout: Duration,
    /// Per-session, per-chunk timeout. Each expiry without progress on the
    /// current chunk counts one strike against the session (see
    /// [`chunk_stall_strikes`](Self::chunk_stall_strikes)).
    pub chunk_timeout: Duration,
    /// Number of consecutive `chunk_timeout` expiries a session may accrue
    /// on a single chunk before it is evicted from the pass and its action
    /// placed on the retry list. Strikes extend the budget without
    /// cancelling the in-flight chunk; a value of 1 reproduces the old
    /// evict-on-first-timeout behaviour. Default: 3.
    pub chunk_stall_strikes: u32,
}

impl Default for GarblingConfig {
    fn default() -> Self {
        Self {
            worker_threads: 4,
            max_concurrent: 8,
            circuit_path: PathBuf::new(),
            batch_timeout: Duration::from_millis(500),
            chunk_timeout: Duration::from_secs(30),
            chunk_stall_strikes: 3,
        }
    }
}

impl GarblingConfig {
    /// Upper bound on how many sessions a single worker can be assigned.
    fn max_sessions_per_worker(&self) -> usize {
        self.max_concurrent.div_ceil(self.worker_threads.max(1))
    }

    /// The per-session chunk timeout workers actually enforce.
    ///
    /// A worker drives its sessions concurrently, so co-resident sessions
    /// contend for the same uplink: a chunk that had the link to itself
    /// takes proportionally longer in wall-clock once its siblings are
    /// pushing too. Scaling the configured budget by the number of
    /// co-resident sessions keeps each session's effective allowance
    /// independent of how sessions happen to be packed onto workers.
    ///
    /// Erring long is the right side to err on: a spurious eviction throws
    /// away a partially-sent ~43 GB table and re-garbles it from scratch,
    /// whereas a late eviction only delays the retry of a transfer that was
    /// already doomed.
    fn session_chunk_timeout(&self) -> Duration {
        let sessions = u32::try_from(self.max_sessions_per_worker()).unwrap_or(u32::MAX);
        self.chunk_timeout.saturating_mul(sessions)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Active session (lives during a pass)
// ════════════════════════════════════════════════════════════════════════════

/// A live session being driven through a pass, paired with the original action
/// descriptor so we can retry if the session is evicted.
struct ActiveSession {
    /// The peer this session belongs to.
    peer_id: PeerId,
    /// Original action descriptor — preserved for retry on eviction.
    job: PendingCircuitJob,
    /// The live session driven block-by-block.
    session: Box<dyn CircuitSession>,
}

// ════════════════════════════════════════════════════════════════════════════
// Worker protocol
// ════════════════════════════════════════════════════════════════════════════

/// Commands sent from the main coordinator thread to worker threads.
enum WorkerCommand {
    /// Assign sessions for the upcoming pass. Replaces any previous sessions.
    AssignSessions(Vec<ActiveSession>),
    /// Process this chunk for all assigned sessions.
    ProcessChunk(Arc<OwnedChunk>),
    /// All blocks processed — finalize sessions and report completions.
    FinishPass,
    /// Shut down the worker thread permanently.
    Shutdown,
}

/// Reports sent from worker threads back to the main coordinator thread.
enum WorkerReport {
    /// Chunk processing complete.
    ChunkDone(ChunkReport),
    /// Pass finalization complete.
    FinishDone(FinishReport),
}

/// Sent after processing one chunk.
struct ChunkReport {
    /// Jobs whose sessions were evicted (timeout or error).
    evicted_jobs: Vec<PendingCircuitJob>,
    /// Jobs whose sessions remain active on this worker after the chunk.
    remaining_jobs: Vec<PendingCircuitJob>,
}

/// Sent after finalizing all sessions at end of pass.
struct FinishReport {
    /// Completed results produced during finish.
    completions: Vec<JobCompletion>,
    /// Jobs whose sessions finished with [`HandlerOutcome::Retry`].
    retry_jobs: Vec<PendingCircuitJob>,
}

// ════════════════════════════════════════════════════════════════════════════
// Worker handle (main thread's view of a worker)
// ════════════════════════════════════════════════════════════════════════════

/// Handle to a worker thread, held by the coordinator's main thread.
struct WorkerHandle {
    id: usize,
    command_tx: kanal::AsyncSender<WorkerCommand>,
    report_rx: kanal::AsyncReceiver<WorkerReport>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WorkerHandle {
    /// Spawn a new worker thread with its own monoio runtime.
    fn spawn(
        id: usize,
        chunk_timeout: Duration,
        stall_strikes: u32,
        fault_tx: kanal::AsyncSender<SchedulerFault>,
    ) -> Self {
        // Bounded channels: main sends at most 1 command before waiting for
        // a report, so capacity 2 provides adequate headroom.
        let (command_tx, command_rx) = kanal::bounded_async(2);
        let (report_tx, report_rx) = kanal::bounded_async(2);

        let thread_name = format!("garbling-worker-{id}");
        let thread = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                let run_result = catch_unwind(AssertUnwindSafe(|| {
                    monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("failed to build monoio runtime for garbling worker")
                        .block_on(worker_loop(id, chunk_timeout, stall_strikes, command_rx, report_tx));
                }));

                if let Err(payload) = run_result {
                    let reason = panic_payload_to_string(payload);
                    tracing::error!(worker = id, %reason, "garbling worker thread exited due to panic");
                    let _ = fault_tx.to_sync().send(SchedulerFault::ThreadExited {
                        source: "garbling_worker",
                        thread: thread_name,
                        reason,
                    });
                }
            })
            .expect("failed to spawn garbling worker thread");

        Self {
            id,
            command_tx,
            report_rx,
            thread: Some(thread),
        }
    }

    /// Send a command to the worker.
    async fn send(&self, cmd: WorkerCommand) -> bool {
        self.command_tx.send(cmd).await.is_ok()
    }

    /// Receive the next report from the worker, with a timeout.
    ///
    /// Returns `None` if the worker is dead (channel closed) or the timeout
    /// expires. The timeout prevents the coordinator from hanging if a worker
    /// thread panics.
    async fn recv_report(&self, timeout: Duration) -> Option<WorkerReport> {
        match monoio::time::timeout(timeout, self.report_rx.recv()).await {
            Ok(Ok(report)) => Some(report),
            Ok(Err(_)) => {
                tracing::error!(worker = self.id, "worker report channel closed");
                None
            }
            Err(_) => {
                tracing::error!(worker = self.id, "timed out waiting for worker report");
                None
            }
        }
    }

    /// Shut down the worker gracefully.
    fn shutdown(&mut self) {
        // Send shutdown command (best effort — worker may already be dead).
        let _ = self.command_tx.try_send(WorkerCommand::Shutdown);
        let _ = self.command_tx.close();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Coordinator (public API)
// ════════════════════════════════════════════════════════════════════════════

/// Coordinates garbling jobs to share sequential circuit reads.
///
/// The scheduler submits [`PendingCircuitJob`]s via [`submit`](Self::submit).
/// The coordinator creates sessions internally (with retry for transient
/// failures), distributes them across worker threads, and drives them through
/// the circuit file block-by-block.
pub struct GarblingCoordinator {
    /// Channel for submitting jobs from the scheduler (async — never blocks
    /// the scheduler thread).
    submit_tx: kanal::AsyncSender<PendingCircuitJob>,
    /// Handle to the coordinator's main thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for GarblingCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarblingCoordinator")
            .finish_non_exhaustive()
    }
}

impl GarblingCoordinator {
    /// Create and start the garbling coordinator.
    ///
    /// Spawns a dedicated main thread (which in turn spawns worker threads).
    /// Jobs submitted via [`submit`](Self::submit) are collected into batches,
    /// sessions are created via the `factory`, and workers process them
    /// concurrently.
    pub(crate) fn new(
        config: GarblingConfig,
        factory: Arc<dyn SessionFactory>,
        completion_tx: kanal::AsyncSender<JobCompletion>,
        fault_tx: kanal::AsyncSender<SchedulerFault>,
    ) -> Self {
        // Unbounded: the scheduler dispatch loop forwards each circuit
        // action through this channel inline. Bounding it head-of-line
        // blocks unrelated dispatch when a garbling pass is in progress
        // (see #182). Volume is bounded upstream by per-peer protocol-message
        // rate limiting (#220).
        let (submit_tx, submit_rx) = kanal::unbounded_async();

        let coordinator_thread_name = "garbling-coordinator".to_string();
        let thread = std::thread::Builder::new()
            .name(coordinator_thread_name.clone())
            .spawn(move || {
                let run_result = catch_unwind(AssertUnwindSafe(|| {
                    monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("failed to build monoio runtime for garbling coordinator")
                        .block_on(coordinator_loop(
                            config,
                            factory,
                            submit_rx,
                            completion_tx,
                            fault_tx.clone(),
                        ));
                }));

                if let Err(payload) = run_result {
                    let reason = panic_payload_to_string(payload);
                    tracing::error!(%reason, "garbling coordinator thread exited due to panic");
                    let _ = fault_tx.to_sync().send(SchedulerFault::ThreadExited {
                        source: "garbling_coordinator",
                        thread: coordinator_thread_name,
                        reason,
                    });
                }
            })
            .expect("failed to spawn garbling coordinator thread");

        Self {
            submit_tx,
            thread: Some(thread),
        }
    }

    /// Submit a circuit job to be executed in the next pass.
    ///
    /// This is an **async** operation — it never blocks the scheduler thread.
    /// If the coordinator is mid-pass, the job queues up for the next one.
    pub async fn submit(&self, job: PendingCircuitJob) {
        if self.submit_tx.send(job).await.is_err() {
            tracing::error!("garbling coordinator channel closed — job dropped");
        }
    }

    /// Shut down the coordinator gracefully.
    ///
    /// Closes the submission channel, waits for the current pass to finish
    /// (workers are shut down internally), then joins the coordinator thread.
    pub fn shutdown(&mut self) {
        let _ = self.submit_tx.close();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Coordinator main loop
// ════════════════════════════════════════════════════════════════════════════

/// Main loop running on the coordinator's dedicated thread.
///
/// Spawns worker threads, collects jobs into batches, creates sessions
/// (retrying transient failures), distributes them across workers, and
/// orchestrates passes through the circuit file.
async fn coordinator_loop(
    config: GarblingConfig,
    factory: Arc<dyn SessionFactory>,
    submit_rx: kanal::AsyncReceiver<PendingCircuitJob>,
    completion_tx: kanal::AsyncSender<JobCompletion>,
    fault_tx: kanal::AsyncSender<SchedulerFault>,
) {
    let span = tracing::info_span!(
        "job_scheduler.garbling_coordinator",
        worker_threads = config.worker_threads.max(1),
        max_concurrent = config.max_concurrent,
        circuit_path = %config.circuit_path.display()
    );
    async move {
        // Spawn persistent worker threads.
        let n_workers = config.worker_threads.max(1);
        let mut workers: Vec<WorkerHandle> = (0..n_workers)
            .map(|id| {
                WorkerHandle::spawn(
                    id,
                    config.session_chunk_timeout(),
                    config.chunk_stall_strikes.max(1),
                    fault_tx.clone(),
                )
            })
            .collect();

        tracing::info!(
            worker_threads = n_workers,
            max_concurrent = config.max_concurrent,
            circuit_path = %config.circuit_path.display(),
            "garbling coordinator started"
        );

        // Jobs whose session creation failed with StorageUnavailable or that were
        // evicted mid-pass. They are retried on the next pass.
        let mut pending_retry: Vec<PendingCircuitJob> = Vec::new();

        loop {
            // ── 1. Collect a batch of jobs ───────────────────────────────
            let mut jobs: Vec<PendingCircuitJob> = Vec::with_capacity(config.max_concurrent);

            // Drain retry list first (bounded by max_concurrent).
            let retry_take = pending_retry.len().min(config.max_concurrent);
            jobs.extend(pending_retry.drain(..retry_take));

            // If no retries, block until at least one new job arrives.
            if jobs.is_empty() {
                match submit_rx.recv().await {
                    Ok(job) => jobs.push(job),
                    Err(_) => break, // Channel closed — shut down.
                }
            }

            // Try to collect more jobs up to max_concurrent, with a timeout.
            let deadline = monoio::time::Instant::now() + config.batch_timeout;
            while jobs.len() < config.max_concurrent {
                let remaining = deadline.saturating_duration_since(monoio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match monoio::time::timeout(remaining, submit_rx.recv()).await {
                    Ok(Ok(job)) => jobs.push(job),
                    Ok(Err(_)) => break, // Channel closed.
                    Err(_) => break,     // Timeout — start pass with what we have.
                }
            }

            if jobs.is_empty() {
                continue;
            }

            tracing::debug!(
                jobs = jobs.len(),
                retry_backlog = pending_retry.len(),
                "garbling coordinator collected pass batch"
            );

            // ── 2. Create sessions from collected jobs ───────────────────
            let mut sessions: Vec<ActiveSession> = Vec::with_capacity(jobs.len());

            for job in jobs {
                match factory.create_session(&job).await {
                    Ok(session) => {
                        sessions.push(ActiveSession {
                            peer_id: job.peer_id,
                            job: PendingCircuitJob {
                                peer_id: job.peer_id,
                                action: job.action.clone(),
                            },
                            session,
                        });
                    }
                    Err(CircuitError::AlreadyComplete) => {
                        // The state machine no longer needs this work —
                        // either it already recorded it as done (e.g. a
                        // duplicate transfer job for a table the evaluator
                        // receipted) or it has moved past the step (incl.
                        // aborted setups). Idempotent success — drop the
                        // job. No completion is sent: the SM treats these
                        // completions as informational and has moved on.
                        tracing::info!(
                            peer = ?job.peer_id,
                            action = ?job.action,
                            "action no longer required per state machine — dropping job"
                        );
                    }
                    Err(CircuitError::StorageUnavailable) => {
                        // Transient — data not yet written by STF. Keep for retry.
                        tracing::debug!(
                            peer = ?job.peer_id,
                            action = ?job.action,
                            "session storage unavailable — will retry next pass"
                        );
                        pending_retry.push(job);
                    }
                    Err(CircuitError::TransientFailure(reason)) => {
                        // Transient — e.g. peer not ready for bulk stream. Keep for retry.
                        tracing::debug!(
                            peer = ?job.peer_id,
                            action = ?job.action,
                            reason,
                            "transient setup failure — will retry next pass"
                        );
                        pending_retry.push(job);
                    }
                    Err(e) => {
                        // Permanent failure (SetupFailed, ChunkFailed during setup).
                        // This is a programming error — the action cannot be retried.
                        tracing::error!(
                            ?e,
                            peer = ?job.peer_id,
                            action = ?job.action,
                            "permanent session creation failure — action dropped"
                        );
                    }
                }
            }

            if sessions.is_empty() {
                if !pending_retry.is_empty() {
                    // All jobs failed this round — sleep before retrying.
                    tracing::debug!(
                        pending = pending_retry.len(),
                        "no sessions created — sleeping before retry"
                    );
                    monoio::time::sleep(Duration::from_millis(500)).await;
                }
                continue;
            }

            // ── 3. Run the pass ──────────────────────────────────────────
            let session_count = sessions.len();
            run_pass(
                &config,
                sessions,
                &mut workers,
                &completion_tx,
                &fault_tx,
                &mut pending_retry,
            )
            .instrument(tracing::info_span!(
                "job_scheduler.garbling_pass",
                sessions = session_count
            ))
            .await;
        }

        // ── Shutdown workers ─────────────────────────────────────────────
        for worker in &mut workers {
            worker.shutdown();
        }

        if !pending_retry.is_empty() {
            tracing::warn!(
                count = pending_retry.len(),
                "garbling coordinator shutting down with pending retry jobs"
            );
        }

        tracing::info!("garbling coordinator shut down");
    }
    .instrument(span)
    .await;
}

// ════════════════════════════════════════════════════════════════════════════
// Pass execution (multi-threaded)
// ════════════════════════════════════════════════════════════════════════════

/// Run a single pass: distribute sessions across workers, read the circuit
/// file once, broadcast chunks, and collect results.
///
/// Evicted sessions have their original action moved to `pending_retry`.
/// Surviving sessions are finalized by workers; completions go to the SM.
async fn run_pass(
    config: &GarblingConfig,
    sessions: Vec<ActiveSession>,
    workers: &mut [WorkerHandle],
    completion_tx: &kanal::AsyncSender<JobCompletion>,
    fault_tx: &kanal::AsyncSender<SchedulerFault>,
    pending_retry: &mut Vec<PendingCircuitJob>,
) {
    let n_workers = workers.len();

    // ── Distribute sessions round-robin (spread-first) ──────────────
    // With 7 sessions across 4 workers: [2, 2, 2, 1] sessions each.
    let mut assignments: Vec<Vec<ActiveSession>> = (0..n_workers).map(|_| Vec::new()).collect();
    for (i, session) in sessions.into_iter().enumerate() {
        assignments[i % n_workers].push(session);
    }

    // Send assignments to workers and track which ones have sessions.
    let mut active_worker_ids: Vec<usize> = Vec::with_capacity(n_workers);
    let mut active_jobs_by_worker: HashMap<usize, Vec<PendingCircuitJob>> = HashMap::new();
    for (wid, assignment) in assignments.into_iter().enumerate() {
        if !assignment.is_empty() {
            let count = assignment.len();
            let tracked_jobs: Vec<PendingCircuitJob> =
                assignment.iter().map(|active| active.job.clone()).collect();
            if workers[wid]
                .send(WorkerCommand::AssignSessions(assignment))
                .await
            {
                active_worker_ids.push(wid);
                active_jobs_by_worker.insert(wid, tracked_jobs);
                tracing::debug!(worker = wid, sessions = count, "assigned sessions");
            } else {
                tracing::error!(worker = wid, "failed to assign sessions — worker dead");
                pending_retry.extend(tracked_jobs);
            }
        }
    }

    if active_worker_ids.is_empty() {
        tracing::error!("no active workers — aborting pass");
        return;
    }

    // ── Open the shared circuit reader ───────────────────────────────
    let mut reader = match ReaderV5c::open(&config.circuit_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                %e,
                "failed to open circuit file — requeueing all sessions"
            );
            // Tell workers to finish immediately (they have sessions assigned
            // but no chunks to process). The sessions will call finish() which
            // may return Retry — those get collected.
            collect_finish_reports(
                &active_worker_ids,
                &mut active_jobs_by_worker,
                workers,
                completion_tx,
                fault_tx,
                pending_retry,
            )
            .await;
            return;
        }
    };

    let total_gates = reader.header().total_gates();
    let mut block_idx: usize = 0;

    // Timeout for waiting on worker reports. A worker's sessions are driven
    // concurrently, so one session-timeout covers the chunk for all of them,
    // plus a margin: sessions that never await (commitment and evaluation do
    // no network I/O) still complete one after another inside the join.
    let report_timeout = config
        .session_chunk_timeout()
        .saturating_mul(config.chunk_stall_strikes.max(1))
        .saturating_add(Duration::from_secs(5));

    // ── Read blocks and broadcast to workers ─────────────────────────
    while let Some(chunk_result) = reader.next_blocks_chunk().await.transpose() {
        let reader_chunk = match chunk_result {
            Ok(chunk) => chunk,
            Err(e) => {
                tracing::error!(
                    %e,
                    remaining_workers = active_worker_ids.len(),
                    "circuit read error mid-pass — finishing early"
                );
                break;
            }
        };

        // Convert borrowed blocks to owned, wrap in Arc for sharing.
        let owned = convert_chunk(&reader_chunk, total_gates, &mut block_idx);
        let shared = Arc::new(owned);

        // Broadcast chunk to all active workers.
        for &wid in &active_worker_ids {
            if !workers[wid]
                .send(WorkerCommand::ProcessChunk(Arc::clone(&shared)))
                .await
            {
                tracing::error!(worker = wid, "failed to send chunk — worker dead");
            }
        }

        // ── Barrier: wait for all workers to report ──────────────────
        active_worker_ids = collect_chunk_reports(
            &active_worker_ids,
            &mut active_jobs_by_worker,
            workers,
            report_timeout,
            pending_retry,
        )
        .await;

        if active_worker_ids.is_empty() {
            tracing::warn!("all workers idle — ending pass early");
            return;
        }
    }

    // ── Finalize surviving sessions ──────────────────────────────────
    collect_finish_reports_with_timeout(
        &active_worker_ids,
        &mut active_jobs_by_worker,
        workers,
        completion_tx,
        fault_tx,
        Duration::from_secs(60),
        pending_retry,
    )
    .await;
}

/// Collect chunk-phase reports from all active workers.
///
/// Returns the set of workers that still have active sessions after processing
/// the chunk. Any worker that fails to report has its tracked jobs requeued.
async fn collect_chunk_reports(
    active_worker_ids: &[usize],
    active_jobs_by_worker: &mut HashMap<usize, Vec<PendingCircuitJob>>,
    workers: &mut [WorkerHandle],
    report_timeout: Duration,
    pending_retry: &mut Vec<PendingCircuitJob>,
) -> Vec<usize> {
    let mut still_active: Vec<usize> = Vec::with_capacity(active_worker_ids.len());

    for &wid in active_worker_ids {
        match workers[wid].recv_report(report_timeout).await {
            Some(WorkerReport::ChunkDone(report)) => {
                pending_retry.extend(report.evicted_jobs);
                if report.remaining_jobs.is_empty() {
                    active_jobs_by_worker.remove(&wid);
                    tracing::debug!(
                        worker = wid,
                        "all sessions evicted — worker idle for rest of pass"
                    );
                } else {
                    active_jobs_by_worker.insert(wid, report.remaining_jobs);
                    still_active.push(wid);
                }
            }
            Some(WorkerReport::FinishDone(_)) => {
                tracing::error!(
                    worker = wid,
                    "unexpected FinishDone during chunk processing"
                );
                if let Some(jobs) = active_jobs_by_worker.remove(&wid) {
                    pending_retry.extend(jobs);
                }
            }
            None => {
                tracing::error!(
                    worker = wid,
                    "worker failed to report — requeueing sessions assigned to this worker"
                );
                if let Some(jobs) = active_jobs_by_worker.remove(&wid) {
                    pending_retry.extend(jobs);
                }
            }
        }
    }

    still_active
}

/// Send [`WorkerCommand::FinishPass`] to all active workers and collect
/// their [`FinishReport`]s.
async fn collect_finish_reports(
    active_worker_ids: &[usize],
    active_jobs_by_worker: &mut HashMap<usize, Vec<PendingCircuitJob>>,
    workers: &mut [WorkerHandle],
    completion_tx: &kanal::AsyncSender<JobCompletion>,
    fault_tx: &kanal::AsyncSender<SchedulerFault>,
    pending_retry: &mut Vec<PendingCircuitJob>,
) {
    collect_finish_reports_with_timeout(
        active_worker_ids,
        active_jobs_by_worker,
        workers,
        completion_tx,
        fault_tx,
        Duration::from_secs(60),
        pending_retry,
    )
    .await;
}

/// Send [`WorkerCommand::FinishPass`] to all active workers and collect
/// their [`FinishReport`]s, using the provided timeout.
async fn collect_finish_reports_with_timeout(
    active_worker_ids: &[usize],
    active_jobs_by_worker: &mut HashMap<usize, Vec<PendingCircuitJob>>,
    workers: &mut [WorkerHandle],
    completion_tx: &kanal::AsyncSender<JobCompletion>,
    fault_tx: &kanal::AsyncSender<SchedulerFault>,
    finish_timeout: Duration,
    pending_retry: &mut Vec<PendingCircuitJob>,
) {
    // Send finish command to all active workers.
    for &wid in active_worker_ids {
        if !workers[wid].send(WorkerCommand::FinishPass).await {
            tracing::error!(worker = wid, "failed to send FinishPass — worker dead");
            if let Some(jobs) = active_jobs_by_worker.remove(&wid) {
                pending_retry.extend(jobs);
            }
        }
    }

    // Collect finish reports.
    for &wid in active_worker_ids {
        match workers[wid].recv_report(finish_timeout).await {
            Some(WorkerReport::FinishDone(report)) => {
                active_jobs_by_worker.remove(&wid);
                for completion in report.completions {
                    let peer_id = completion.peer_id;
                    if completion_tx.send(completion).await.is_err() {
                        tracing::error!(
                            worker = wid,
                            "completion channel closed while forwarding finish report"
                        );
                        let _ = fault_tx
                            .send(SchedulerFault::CompletionChannelClosed {
                                source: "garbling_coordinator",
                                peer_id,
                            })
                            .await;
                        return;
                    }
                }
                pending_retry.extend(report.retry_jobs);
            }
            Some(WorkerReport::ChunkDone(_)) => {
                tracing::error!(worker = wid, "unexpected ChunkDone during finish phase");
                if let Some(jobs) = active_jobs_by_worker.remove(&wid) {
                    pending_retry.extend(jobs);
                }
            }
            None => {
                tracing::error!(
                    worker = wid,
                    "worker failed to report finish — requeueing sessions assigned to this worker"
                );
                if let Some(jobs) = active_jobs_by_worker.remove(&wid) {
                    pending_retry.extend(jobs);
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Worker thread
// ════════════════════════════════════════════════════════════════════════════

/// Drive `process_chunk` on every session concurrently, returning the
/// ascending indices of sessions that errored or timed out.
///
/// The sessions are polled as one interleaved set rather than one after
/// another. This is load-bearing for transfer sessions: their
/// `process_chunk` awaits a network write that blocks on the peer's
/// receive window, and garbling outruns the wire by roughly an order of
/// magnitude, so in steady state essentially every write blocks. Driven
/// sequentially, N sessions on one worker serve their peers in strict
/// alternation and each peer gets ~1/N of the worker's throughput even
/// though the peers are entirely independent. Driven concurrently, all N
/// peers drain at once for the duration of the chunk.
///
/// This removes the serialization *within* a chunk only. The coordinator
/// still barriers across workers between chunks (see [`run_pass`]), so a
/// slow peer continues to gate the pass at chunk granularity.
///
/// # Eviction: strike budget, never mid-chunk cancellation between strikes
///
/// A pass covers tens of thousands of chunks, so eviction policy is
/// survival math: killing a session on its *first* slow chunk makes table
/// completion probability `(1 - p)^n_chunks` — brutal even for tiny per-
/// chunk stall probabilities, and an evicted transfer restarts from block
/// zero (no resumption yet). Instead a session gets `stall_strikes`
/// consecutive `chunk_timeout` intervals: each expiry logs a strike and
/// **keeps polling the same future**; only the final strike drops it.
///
/// Cancelling and re-running `process_chunk` between strikes would be
/// unsound for transfer sessions — the future is dropped at an await point
/// mid-write, and re-garbling the chunk onto the same stream would emit
/// duplicate bytes. Eviction (dropping the whole session and its stream)
/// is the only safe response to a cancelled chunk, which is why strikes
/// extend the budget *without* cancelling.
async fn process_chunk_on_sessions(
    worker_id: usize,
    sessions: &mut [ActiveSession],
    chunk: &Arc<OwnedChunk>,
    chunk_timeout: Duration,
    stall_strikes: u32,
) -> Vec<usize> {
    let stall_strikes = stall_strikes.max(1);
    let results =
        futures::future::join_all(sessions.iter_mut().enumerate().map(|(index, active)| {
            let peer_id = active.peer_id;
            let session = &mut active.session;
            async move {
                let mut fut = session.process_chunk(chunk);
                let mut strikes = 0u32;
                let result = loop {
                    match monoio::time::timeout(chunk_timeout, &mut fut).await {
                        Ok(res) => break Some(res),
                        Err(_) => {
                            strikes += 1;
                            if strikes >= stall_strikes {
                                // Final strike: drop the future (cancelling
                                // the chunk) and evict the session.
                                break None;
                            }
                            tracing::warn!(
                                worker = worker_id,
                                peer = ?peer_id,
                                strikes,
                                budget = stall_strikes,
                                timeout_ms = chunk_timeout.as_millis(),
                                "session slow on chunk — striking, still polling"
                            );
                        }
                    }
                };
                (index, peer_id, result)
            }
        }))
        .await;

    let mut evicted_indices = Vec::new();
    for (index, peer_id, result) in results {
        match result {
            Some(Ok(())) => { /* session keeping up */ }
            Some(Err(e)) => {
                tracing::warn!(
                    worker = worker_id,
                    ?e,
                    peer = ?peer_id,
                    "session error — evicting for retry"
                );
                evicted_indices.push(index);
            }
            None => {
                tracing::warn!(
                    worker = worker_id,
                    peer = ?peer_id,
                    strikes = stall_strikes,
                    "session exhausted its stall budget on one chunk — evicting for retry"
                );
                evicted_indices.push(index);
            }
        }
    }
    // The caller removes by index in reverse, which is only index-stable if
    // these ascend. `join_all` yields results in input order so they already
    // do; sorting keeps that invariant local rather than resting on the
    // ordering guarantees of a dependency.
    evicted_indices.sort_unstable();
    evicted_indices
}

/// Main loop for a garbling worker thread.
///
/// Receives sessions and chunk commands from the coordinator's main thread.
/// Processes its own sessions concurrently per chunk, in parallel with the
/// other workers. Reports completed results back to the coordinator.
async fn worker_loop(
    id: usize,
    chunk_timeout: Duration,
    stall_strikes: u32,
    command_rx: kanal::AsyncReceiver<WorkerCommand>,
    report_tx: kanal::AsyncSender<WorkerReport>,
) {
    async move {
        tracing::debug!(
            chunk_timeout_ms = chunk_timeout.as_millis(),
            "garbling worker started"
        );

        let mut sessions: Vec<ActiveSession> = Vec::new();

        loop {
            let command = match command_rx.recv().await {
                Ok(cmd) => cmd,
                Err(_) => break, // Channel closed — coordinator shutting down.
            };

            match command {
                WorkerCommand::AssignSessions(new_sessions) => {
                    tracing::debug!(
                        worker = id,
                        count = new_sessions.len(),
                        "received session assignment"
                    );
                    sessions = new_sessions;
                }

                WorkerCommand::ProcessChunk(chunk) => {
                    let evicted_indices = process_chunk_on_sessions(
                        id,
                        &mut sessions,
                        &chunk,
                        chunk_timeout,
                        stall_strikes,
                    )
                    .await;

                    // Remove evicted sessions (reverse order for stable indices)
                    // and collect their jobs for retry.
                    let mut evicted_jobs: Vec<PendingCircuitJob> =
                        Vec::with_capacity(evicted_indices.len());
                    for &idx in evicted_indices.iter().rev() {
                        let evicted = sessions.remove(idx);
                        evicted_jobs.push(evicted.job);
                    }

                    let report = WorkerReport::ChunkDone(ChunkReport {
                        evicted_jobs,
                        remaining_jobs: sessions.iter().map(|active| active.job.clone()).collect(),
                    });
                    if report_tx.send(report).await.is_err() {
                        tracing::error!(worker = id, "report channel closed — exiting");
                        break;
                    }
                }

                WorkerCommand::FinishPass => {
                    let mut completions: Vec<JobCompletion> = Vec::new();
                    let mut retry_jobs: Vec<PendingCircuitJob> = Vec::new();

                    for active in sessions.drain(..) {
                        let ActiveSession {
                            peer_id,
                            job,
                            session,
                        } = active;

                        let outcome = session.finish().await;

                        match outcome {
                            HandlerOutcome::Done(completion) => {
                                completions.push(JobCompletion {
                                    peer_id,
                                    completion,
                                });
                            }
                            HandlerOutcome::Retry => {
                                tracing::debug!(
                                    worker = id,
                                    ?peer_id,
                                    "session finished with Retry — requeueing"
                                );
                                retry_jobs.push(job);
                            }
                        }
                    }

                    let report = WorkerReport::FinishDone(FinishReport {
                        completions,
                        retry_jobs,
                    });
                    if report_tx.send(report).await.is_err() {
                        tracing::error!(worker = id, "report channel closed — exiting");
                        break;
                    }
                }

                WorkerCommand::Shutdown => {
                    tracing::debug!(worker = id, "received shutdown command");
                    break;
                }
            }
        }

        // If we exit with sessions still assigned (e.g. channel closed mid-pass),
        // the coordinator still holds recoverable job ownership and can requeue them.
        if !sessions.is_empty() {
            tracing::warn!(
                worker = id,
                count = sessions.len(),
                "worker exiting with active sessions"
            );
        }

        tracing::debug!("garbling worker shut down");
    }
    .instrument(tracing::debug_span!(
        "job_scheduler.garbling_worker",
        worker = id
    ))
    .await;
}

// ════════════════════════════════════════════════════════════════════════════
// Block conversion
// ════════════════════════════════════════════════════════════════════════════

/// Convert a borrowed chunk of blocks from the circuit reader into an owned
/// [`OwnedChunk`] suitable for sharing across workers via [`Arc`].
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
/// garbling/evaluation work done by sessions.
fn convert_block(block: &Block, num_gates: usize) -> OwnedBlock {
    // Copy gate data: num_gates × 12 bytes (3 × u32 LE).
    let gate_bytes = num_gates * GATE_SIZE;
    let gate_ptr = block.gates.as_ptr() as *const u8;
    // SAFETY: `Block::gates` is a contiguous array of `Gate` structs, each
    // containing three `u32` fields (in1, in2, out) with no padding (same-
    // sized fields guarantee no inter-field padding on all targets). The
    // resulting byte slice is immediately copied into a Vec, so no aliasing
    // concerns. `gate_bytes = num_gates * 12` never exceeds the allocation
    // because `num_gates <= block.gates.len()` (enforced by the caller via
    // `get_block_num_gates`).
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    use mosaic_cac_types::{
        GarblingSeed, Seed,
        state_machine::garbler::{ActionId, ActionResult},
    };
    use mosaic_job_api::{ActionCompletion, CircuitAction, HandlerOutcome, PendingCircuitJob};

    use super::*;

    struct NoopSession;

    impl CircuitSession for NoopSession {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }

        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async {
                HandlerOutcome::Done(ActionCompletion::Garbler {
                    id: ActionId::SendCommitMsgHeader,
                    result: ActionResult::CommitMsgHeaderAcked,
                })
            })
        }
    }

    fn run_monoio<F>(future: F)
    where
        F: Future<Output = ()> + 'static,
    {
        monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .enable_timer()
            .build()
            .expect("build monoio runtime")
            .block_on(future);
    }

    fn sample_job(peer_byte: u8) -> PendingCircuitJob {
        PendingCircuitJob {
            peer_id: PeerId::from([peer_byte; 32]),
            action: CircuitAction::GarblerTransfer {
                seed: GarblingSeed::from([peer_byte; 32]),
            },
        }
    }

    fn sample_completion(peer_id: PeerId) -> JobCompletion {
        JobCompletion {
            peer_id,
            completion: ActionCompletion::Garbler {
                id: ActionId::GeneratePolynomialCommitments(
                    Seed::from([9; 32]),
                    mosaic_cac_types::state_machine::garbler::Wire::Output,
                ),
                result: ActionResult::CommitMsgHeaderAcked,
            },
        }
    }

    #[test]
    fn run_pass_requeues_jobs_when_assignment_fails() {
        run_monoio(async {
            let (command_tx, _command_rx) = kanal::bounded_async(1);
            let (report_tx, report_rx) = kanal::bounded_async(1);
            let _ = command_tx.close();
            drop(report_tx);

            let mut workers = vec![WorkerHandle {
                id: 0,
                command_tx,
                report_rx,
                thread: None,
            }];

            let job = sample_job(1);
            let sessions = vec![ActiveSession {
                peer_id: job.peer_id,
                job: job.clone(),
                session: Box::new(NoopSession),
            }];

            let (completion_tx, _completion_rx) = kanal::bounded_async(1);
            let (fault_tx, _fault_rx) = kanal::bounded_async(1);
            let mut pending_retry = Vec::new();
            run_pass(
                &GarblingConfig {
                    worker_threads: 1,
                    max_concurrent: 1,
                    circuit_path: PathBuf::new(),
                    batch_timeout: Duration::from_millis(1),
                    chunk_timeout: Duration::from_millis(1),
                    chunk_stall_strikes: 1,
                },
                sessions,
                &mut workers,
                &completion_tx,
                &fault_tx,
                &mut pending_retry,
            )
            .await;

            assert_eq!(pending_retry.len(), 1);
            assert_eq!(pending_retry[0].peer_id, job.peer_id);
        });
    }

    #[test]
    fn collect_chunk_reports_requeues_jobs_when_worker_misses_report() {
        run_monoio(async {
            let (command_tx, _command_rx) = kanal::bounded_async(1);
            let (_report_tx, report_rx) = kanal::bounded_async(1);

            let mut workers = vec![WorkerHandle {
                id: 0,
                command_tx,
                report_rx,
                thread: None,
            }];

            let job = sample_job(2);
            let mut active_jobs_by_worker = HashMap::from([(0usize, vec![job.clone()])]);
            let mut pending_retry = Vec::new();
            let still_active = collect_chunk_reports(
                &[0],
                &mut active_jobs_by_worker,
                &mut workers,
                Duration::from_millis(1),
                &mut pending_retry,
            )
            .await;

            assert!(still_active.is_empty());
            assert!(active_jobs_by_worker.is_empty());
            assert_eq!(pending_retry.len(), 1);
            assert_eq!(pending_retry[0].peer_id, job.peer_id);
        });
    }

    #[test]
    fn collect_finish_reports_forwards_completions_and_requeues_retries() {
        run_monoio(async {
            let (command_tx, _command_rx) = kanal::bounded_async(1);
            let (report_tx, report_rx) = kanal::bounded_async(1);

            let peer_id = PeerId::from([3; 32]);
            let retry_job = sample_job(4);
            report_tx
                .send(WorkerReport::FinishDone(FinishReport {
                    completions: vec![sample_completion(peer_id)],
                    retry_jobs: vec![retry_job.clone()],
                }))
                .await
                .expect("send finish report");

            let mut workers = vec![WorkerHandle {
                id: 0,
                command_tx,
                report_rx,
                thread: None,
            }];

            let mut active_jobs_by_worker = HashMap::from([(0usize, vec![sample_job(5)])]);
            let (completion_tx, completion_rx) = kanal::bounded_async(2);
            let (fault_tx, _fault_rx) = kanal::bounded_async(1);
            let mut pending_retry = Vec::new();

            collect_finish_reports(
                &[0],
                &mut active_jobs_by_worker,
                &mut workers,
                &completion_tx,
                &fault_tx,
                &mut pending_retry,
            )
            .await;

            assert!(active_jobs_by_worker.is_empty());
            assert_eq!(pending_retry.len(), 1);
            assert_eq!(pending_retry[0].peer_id, retry_job.peer_id);

            let forwarded = completion_rx
                .recv()
                .await
                .expect("receive forwarded completion");
            assert_eq!(forwarded.peer_id, peer_id);
        });
    }

    #[test]
    fn collect_finish_reports_requeues_jobs_when_worker_misses_finish_report() {
        run_monoio(async {
            let (command_tx, _command_rx) = kanal::bounded_async(1);
            let (_report_tx, report_rx) = kanal::bounded_async(1);

            let mut workers = vec![WorkerHandle {
                id: 0,
                command_tx,
                report_rx,
                thread: None,
            }];

            let job = sample_job(6);
            let mut active_jobs_by_worker = HashMap::from([(0usize, vec![job.clone()])]);
            let (completion_tx, _completion_rx) = kanal::bounded_async(1);
            let (fault_tx, _fault_rx) = kanal::bounded_async(1);
            let mut pending_retry = Vec::new();

            collect_finish_reports_with_timeout(
                &[0],
                &mut active_jobs_by_worker,
                &mut workers,
                &completion_tx,
                &fault_tx,
                Duration::from_millis(1),
                &mut pending_retry,
            )
            .await;

            assert!(active_jobs_by_worker.is_empty());
            assert_eq!(pending_retry.len(), 1);
            assert_eq!(pending_retry[0].peer_id, job.peer_id);
        });
    }

    #[test]
    fn closed_completion_channel_reports_scheduler_fault() {
        run_monoio(async {
            let peer_id = PeerId::from([11; 32]);
            let (command_tx, _command_rx) = kanal::bounded_async(2);
            let (report_tx, report_rx) = kanal::bounded_async(2);
            let (completion_tx, completion_rx) = kanal::bounded_async(1);
            let (fault_tx, fault_rx) = kanal::bounded_async(1);
            drop(completion_rx);

            report_tx
                .send(WorkerReport::FinishDone(FinishReport {
                    completions: vec![JobCompletion {
                        peer_id,
                        completion: ActionCompletion::Garbler {
                            id: ActionId::SendCommitMsgChunk(0),
                            result: ActionResult::CommitMsgChunkAcked,
                        },
                    }],
                    retry_jobs: vec![],
                }))
                .await
                .expect("send finish report");

            let mut workers = vec![WorkerHandle {
                id: 0,
                command_tx,
                report_rx,
                thread: None,
            }];
            let mut active_jobs_by_worker = HashMap::from([(
                0usize,
                vec![PendingCircuitJob {
                    peer_id,
                    action: CircuitAction::GarblerTransfer {
                        seed: GarblingSeed::from([5; 32]),
                    },
                }],
            )]);
            let mut pending_retry = Vec::new();

            collect_finish_reports_with_timeout(
                &[0],
                &mut active_jobs_by_worker,
                &mut workers,
                &completion_tx,
                &fault_tx,
                Duration::from_millis(1),
                &mut pending_retry,
            )
            .await;

            let fault = monoio::time::timeout(Duration::from_secs(2), fault_rx.recv())
                .await
                .expect("timed out waiting for scheduler fault")
                .expect("fault channel should stay open");
            assert!(matches!(
                fault,
                SchedulerFault::CompletionChannelClosed {
                    source: "garbling_coordinator",
                    peer_id: fault_peer,
                } if fault_peer == peer_id
            ));
        });
    }

    // ── Concurrent session processing within one worker ──────────────

    /// Yields exactly once: `Pending` on the first poll (waking itself),
    /// `Ready` on the second. `Send`, and deterministic — no timers.
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// Session that records the peak number of sessions simultaneously
    /// inside `process_chunk`.
    struct ConcurrencyProbe {
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl CircuitSession for ConcurrencyProbe {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            let active = Arc::clone(&self.active);
            let peak = Arc::clone(&self.peak);
            Box::pin(async move {
                let in_flight = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(in_flight, Ordering::SeqCst);
                // `join_all` polls every one of its futures before it
                // yields, so all N siblings reach this await — and so all N
                // have incremented `active` — before any of them resumes.
                // Driven concurrently `peak` reaches N; driven one at a
                // time it never exceeds 1. No timing dependence.
                //
                // That polling behaviour is an implementation detail of
                // `join_all` rather than a documented guarantee, but the
                // dependency is safe: were it to change, this test would
                // fail loudly rather than silently stop checking anything.
                YieldOnce(false).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async {
                HandlerOutcome::Done(ActionCompletion::Garbler {
                    id: ActionId::SendCommitMsgHeader,
                    result: ActionResult::CommitMsgHeaderAcked,
                })
            })
        }
    }

    /// Session that never completes — models a peer whose receive window
    /// has stalled indefinitely. Only `chunk_timeout` frees it.
    struct StalledSession;

    impl CircuitSession for StalledSession {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(())
            })
        }

        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async { HandlerOutcome::Retry })
        }
    }

    /// Session whose chunk processing always errors.
    struct FailingSession;

    impl CircuitSession for FailingSession {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            Box::pin(async { Err(CircuitError::ChunkFailed("test failure".into())) })
        }

        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async { HandlerOutcome::Retry })
        }
    }

    fn active_session(byte: u8, session: Box<dyn CircuitSession>) -> ActiveSession {
        ActiveSession {
            peer_id: PeerId::from([byte; 32]),
            job: sample_job(byte),
            session,
        }
    }

    fn empty_chunk() -> Arc<OwnedChunk> {
        Arc::new(OwnedChunk { blocks: Vec::new() })
    }

    fn probe(active: &Arc<AtomicUsize>, peak: &Arc<AtomicUsize>) -> Box<dyn CircuitSession> {
        Box::new(ConcurrencyProbe {
            active: Arc::clone(active),
            peak: Arc::clone(peak),
        })
    }

    #[test]
    fn worker_drives_its_sessions_concurrently() {
        run_monoio(async {
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut sessions: Vec<ActiveSession> = (0u8..4)
                .map(|i| active_session(i, probe(&active, &peak)))
                .collect();

            let evicted = process_chunk_on_sessions(
                0,
                &mut sessions,
                &empty_chunk(),
                Duration::from_secs(5),
                1,
            )
            .await;

            assert!(evicted.is_empty(), "no session should be evicted");
            assert_eq!(
                peak.load(Ordering::SeqCst),
                4,
                "sessions did not overlap — they are still being driven one at a time"
            );
            assert_eq!(active.load(Ordering::SeqCst), 0, "all sessions finished");
        });
    }

    #[test]
    fn stalled_sessions_are_evicted_without_blocking_siblings() {
        const CHUNK_TIMEOUT: Duration = Duration::from_millis(300);

        run_monoio(async {
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut sessions = vec![
                active_session(0, probe(&active, &peak)),
                active_session(1, Box::new(StalledSession)),
                active_session(2, probe(&active, &peak)),
                active_session(3, Box::new(StalledSession)),
            ];

            let started = std::time::Instant::now();
            let evicted =
                process_chunk_on_sessions(0, &mut sessions, &empty_chunk(), CHUNK_TIMEOUT, 1).await;
            let elapsed = started.elapsed();

            assert_eq!(evicted, vec![1, 3], "only the stalled sessions are evicted");
            assert_eq!(
                peak.load(Ordering::SeqCst),
                2,
                "healthy sessions should have run alongside the stalled ones"
            );
            // Per-session timeouts run concurrently: two stalled sessions
            // cost one timeout (~1x), not two (~2x). Threshold sits midway
            // between so neither scheduling slop nor a loaded machine can
            // flip it. `peak` above is the deterministic check; this one
            // guards the timeouts specifically.
            assert!(
                elapsed < CHUNK_TIMEOUT * 3 / 2,
                "chunk took {elapsed:?} for two stalled sessions at a \
                 {CHUNK_TIMEOUT:?} timeout — timeouts are running one after another"
            );
        });
    }

    /// Session whose chunk future completes when signalled externally,
    /// recording how many times `process_chunk` was entered.
    struct SlowThenOkSession {
        entered: Arc<AtomicUsize>,
        ready_rx: kanal::AsyncReceiver<()>,
    }

    impl CircuitSession for SlowThenOkSession {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let rx = self.ready_rx.clone();
            Box::pin(async move {
                let _ = rx.recv().await;
                Ok(())
            })
        }

        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async { HandlerOutcome::Retry })
        }
    }

    #[test]
    fn slow_session_survives_stall_strikes_without_restart() {
        run_monoio(async {
            let entered = Arc::new(AtomicUsize::new(0));
            let (ready_tx, ready_rx) = kanal::bounded_async(1);
            let mut sessions = vec![ActiveSession {
                peer_id: PeerId::from([1u8; 32]),
                job: sample_job(1),
                session: Box::new(SlowThenOkSession {
                    entered: Arc::clone(&entered),
                    ready_rx,
                }),
            }];

            // Complete the chunk from a thread after ~2.5 strike intervals.
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(250));
                let _ = ready_tx.to_sync().send(());
            });

            let evicted = process_chunk_on_sessions(
                0,
                &mut sessions,
                &empty_chunk(),
                Duration::from_millis(100),
                5,
            )
            .await;

            assert!(
                evicted.is_empty(),
                "session accrued strikes below the budget and must survive"
            );
            // The load-bearing assertion: strikes must keep polling the SAME
            // future. Re-entering process_chunk between strikes would mean
            // the chunk was cancelled and restarted — unsound for transfer
            // sessions mid-stream.
            assert_eq!(
                entered.load(Ordering::SeqCst),
                1,
                "process_chunk was re-entered — chunk cancelled between strikes"
            );
        });
    }

    #[test]
    fn session_evicted_only_after_strike_budget() {
        run_monoio(async {
            let mut sessions = vec![active_session(0, Box::new(StalledSession))];
            let started = std::time::Instant::now();
            let evicted = process_chunk_on_sessions(
                0,
                &mut sessions,
                &empty_chunk(),
                Duration::from_millis(100),
                3,
            )
            .await;
            let elapsed = started.elapsed();

            assert_eq!(evicted, vec![0]);
            // 3 strikes at 100ms each: eviction cannot land before 300ms.
            assert!(
                elapsed >= Duration::from_millis(300),
                "evicted after {elapsed:?} — struck out before the budget elapsed"
            );
        });
    }

    #[test]
    fn evicted_indices_are_ascending() {
        run_monoio(async {
            let mut sessions = vec![
                active_session(0, Box::new(NoopSession)),
                active_session(1, Box::new(FailingSession)),
                active_session(2, Box::new(NoopSession)),
                active_session(3, Box::new(FailingSession)),
            ];

            let evicted = process_chunk_on_sessions(
                0,
                &mut sessions,
                &empty_chunk(),
                Duration::from_secs(5),
                1,
            )
            .await;

            // The caller removes evicted sessions by index in reverse, which
            // is only index-stable if these are sorted ascending.
            assert_eq!(evicted, vec![1, 3]);
        });
    }
}

//! Pool worker — a dedicated thread running a monoio async executor with
//! bounded concurrency.
//!
//! Each worker runs its own monoio event loop. It pulls [`PoolJob`]s from a
//! shared [`JobQueue`], spawns them as local `!Send` tasks, and limits
//! concurrency with the queue's built-in backpressure.
//!
//! When a handler signals a transient failure via [`ExecuteResult::Retry`], the
//! worker sleeps briefly and requeues the job to the back of the queue. This
//! ensures one unresponsive peer cannot monopolise worker slots — other peers'
//! jobs get a chance to run between retries.

use std::{sync::Arc, time::Duration};

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_job_api::{ExecuteEvaluatorJob, ExecuteGarblerJob, HandlerOutcome, JobCompletion};
use mosaic_net_svc_api::PeerId;
use tracing::Instrument;

use super::{PoolJob, queue::JobQueue};

/// Initial backoff delay before requeuing a job that returned
/// [`ExecuteResult::Retry`].
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Maximum backoff delay. Caps the exponential growth so a persistently
/// failing job doesn't wait unreasonably long between attempts.
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Compute exponential backoff with cap: `min(base * 2^attempts, max)`.
///
/// Prevents busy-spinning when a transient condition (unresponsive peer,
/// full cache, unavailable storage) persists across consecutive attempts,
/// while bounding the worst-case delay.
///
/// All operations are saturating — no panic or overflow is possible
/// regardless of `attempts` value.
fn retry_backoff(attempts: u32) -> Duration {
    // checked_shl returns None when attempts >= 32; fall back to u32::MAX
    // so that the subsequent saturating_mul + min clamps to RETRY_BACKOFF_MAX.
    let multiplier = 1u32.checked_shl(attempts).unwrap_or(u32::MAX);
    let backoff = RETRY_BACKOFF_BASE.saturating_mul(multiplier);
    backoff.min(RETRY_BACKOFF_MAX)
}

/// A job descriptor that lives in the shared queue.
///
/// Contains the action to execute and the peer it belongs to. The worker
/// matches on the variant to call the appropriate handler.
///
/// This type is [`Send`] — it is shared across threads via the queue. The
/// resulting handler future is `!Send` and runs locally on monoio.
#[derive(Debug)]
#[expect(clippy::large_enum_variant)]
pub(crate) enum WorkerJob {
    /// Execute a garbler action.
    Garbler {
        /// The peer this SM is paired with.
        peer_id: PeerId,
        /// The garbler action to execute.
        action: GarblerAction,
    },
    /// Execute an evaluator action.
    Evaluator {
        /// The peer this SM is paired with.
        peer_id: PeerId,
        /// The evaluator action to execute.
        action: EvaluatorAction,
    },
}

/// A worker thread handle.
///
/// The worker runs on a dedicated thread with its own monoio runtime. It
/// pulls jobs from the shared [`JobQueue`], spawns them as local tasks (up
/// to `concurrency` at a time), and sends completions through `completion_tx`.
pub(crate) struct Worker<D: ExecuteGarblerJob + ExecuteEvaluatorJob> {
    id: usize,
    /// Thread join handle (used by `shutdown` for graceful join).
    #[allow(dead_code)]
    handle: Option<std::thread::JoinHandle<()>>,
    _d: std::marker::PhantomData<D>,
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> std::fmt::Debug for Worker<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").field("id", &self.id).finish()
    }
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> Worker<D> {
    /// Spawn a new worker thread with a monoio runtime.
    ///
    /// The worker immediately begins pulling jobs from `queue`.
    /// Each pulled job is spawned as a local monoio task, bounded by
    /// `concurrency`.
    pub(crate) fn spawn(
        id: usize,
        dispatcher: Arc<D>,
        queue: Arc<JobQueue>,
        completion_tx: kanal::AsyncSender<JobCompletion>,
        concurrency: usize,
    ) -> Self {
        let handle = std::thread::Builder::new()
            .name(format!("worker-{id}"))
            .spawn(move || {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .enable_timer()
                    .build()
                    .expect("failed to build monoio runtime")
                    .block_on(worker_loop(
                        id,
                        dispatcher,
                        queue,
                        completion_tx,
                        concurrency,
                    ));
            })
            .expect("failed to spawn worker thread");

        Self {
            id,
            handle: Some(handle),
            _d: std::marker::PhantomData,
        }
    }

    /// Shut down the worker gracefully.
    ///
    /// The worker will finish after the shared queue is closed and drained.
    /// This method blocks until the thread exits.
    #[allow(dead_code)]
    pub(crate) fn shutdown(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Main loop for a worker thread.
///
/// Pulls jobs from the shared queue, spawns each as a local monoio task
/// (bounded by `concurrency`), and sends completions back.
///
/// Concurrency is bounded using a channel-based permit pool: a bounded
/// channel is pre-filled with `concurrency` tokens. Before pulling a job,
/// the loop acquires a permit (blocking if at capacity). When a spawned
/// task completes, it returns its permit to the pool.
///
/// This ensures the worker only pulls from the shared queue when it has
/// capacity to run the job — other workers can grab jobs in the meantime.
async fn worker_loop<D: ExecuteGarblerJob + ExecuteEvaluatorJob>(
    id: usize,
    dispatcher: Arc<D>,
    queue: Arc<JobQueue>,
    completion_tx: kanal::AsyncSender<JobCompletion>,
    concurrency: usize,
) {
    // Permit pool: bounded channel pre-filled with `concurrency` tokens.
    // Acquire = recv a token, release = send a token back.
    let (permit_tx, permit_rx) = kanal::bounded(concurrency);
    for _ in 0..concurrency {
        let _ = permit_tx.send(());
    }
    let permit_rx = permit_rx.to_async();

    async move {
        tracing::info!(concurrency, "worker started");

        loop {
            // 1. Wait for capacity — blocks if all permits are held by in-flight tasks.
            if permit_rx.recv().await.is_err() {
                tracing::debug!("permit channel closed; worker exiting");
                break;
            }

            // 2. Pull next job — we only reach here when we have capacity.
            let Some(pool_job) = queue.pop().await else {
                tracing::debug!("job queue closed and drained; worker exiting");
                break;
            };

            let (peer_id, role) = job_identity(&pool_job.job);
            let attempts = pool_job.attempts;

            let dispatcher = Arc::clone(&dispatcher);
            let queue = Arc::clone(&queue);
            let completion_tx = completion_tx.clone();
            let permit_tx = permit_tx.clone();

            // 3. Spawn local task. The permit is returned when the task completes, regardless of
            //    whether it succeeded or was requeued for retry.
            monoio::spawn(
                async move {
                    tracing::trace!("executing worker job");
                    let result = execute_job(dispatcher.as_ref(), &pool_job).await;
                    match result {
                        ExecuteResult::Complete(completion) => {
                            tracing::debug!("worker job completed");
                            let _ = completion_tx.send(*completion).await;
                        }
                        ExecuteResult::Retry => {
                            let mut job = pool_job;
                            job.attempts += 1;
                            let backoff = retry_backoff(job.attempts);
                            tracing::debug!(
                                attempts = job.attempts,
                                backoff_ms = backoff.as_millis(),
                                "worker job requested retry"
                            );
                            monoio::time::sleep(backoff).await;
                            queue.requeue(job);
                        }
                    }
                    // Release permit back to the pool.
                    let _ = permit_tx.send(());
                }
                .instrument(tracing::debug_span!(
                    "job_scheduler.worker_job",
                    worker = id,
                    peer = ?peer_id,
                    role,
                    attempts
                )),
            );
        }

        tracing::info!("worker shutting down");
    }
    .instrument(tracing::info_span!("job_scheduler.worker", worker = id))
    .await;
}

/// Result of executing a job.
///
/// [`Complete`](Self::Complete) carries the finished [`JobCompletion`] to be
/// sent to the SM. [`Retry`](Self::Retry) tells the caller to requeue the
/// original [`PoolJob`] (which the caller still owns — `execute_job` only
/// borrows it).
enum ExecuteResult {
    /// Job completed successfully — deliver to SM.
    Complete(Box<JobCompletion>),
    /// Transient failure — caller should requeue the original job.
    Retry,
}

/// Execute a single job by dispatching to the appropriate handler.
///
/// Borrows the [`PoolJob`] so that on [`HandlerOutcome::Retry`] the caller
/// retains ownership and can requeue it. Handlers receive `&Action` and
/// clone any data they need to send over the network.
async fn execute_job<D: ExecuteGarblerJob + ExecuteEvaluatorJob>(
    dispatcher: &D,
    pool_job: &PoolJob,
) -> ExecuteResult {
    let (peer_id, outcome) = match &pool_job.job {
        WorkerJob::Garbler { peer_id, action } => {
            let o = dispatch_garbler(dispatcher, peer_id, action).await;
            (*peer_id, o)
        }
        WorkerJob::Evaluator { peer_id, action } => {
            let o = dispatch_evaluator(dispatcher, peer_id, action).await;
            (*peer_id, o)
        }
    };

    match outcome {
        HandlerOutcome::Done(completion) => ExecuteResult::Complete(Box::new(JobCompletion {
            peer_id,
            completion,
        })),
        HandlerOutcome::Retry => ExecuteResult::Retry,
    }
}

fn job_identity(job: &WorkerJob) -> (PeerId, &'static str) {
    match job {
        WorkerJob::Garbler { peer_id, .. } => (*peer_id, "garbler"),
        WorkerJob::Evaluator { peer_id, .. } => (*peer_id, "evaluator"),
    }
}

/// Dispatch a garbler action to the correct per-action method on the executor.
///
/// Pool actions are dispatched directly. Circuit actions (GenerateTableCommitment,
/// TransferGarblingTable) should never reach here — they are routed to the
/// garbling coordinator by the scheduler before reaching the worker pool.
async fn dispatch_garbler<D: ExecuteGarblerJob>(
    exec: &D,
    peer_id: &PeerId,
    action: &GarblerAction,
) -> HandlerOutcome {
    match action {
        GarblerAction::GeneratePolynomialCommitments(seed, wire) => {
            exec.generate_polynomial_commitments(peer_id, *seed, *wire)
                .await
        }
        GarblerAction::GenerateShares(seed, index) => {
            exec.generate_shares(peer_id, *seed, *index).await
        }
        GarblerAction::SendCommitMsgHeader(header) => {
            exec.send_commit_msg_header(peer_id, header).await
        }
        GarblerAction::SendCommitMsgChunk(chunk) => {
            exec.send_commit_msg_chunk(peer_id, chunk).await
        }
        GarblerAction::SendChallengeResponseMsgHeader(header) => {
            exec.send_challenge_response_header(peer_id, header).await
        }
        GarblerAction::SendChallengeResponseMsgChunk(chunk) => {
            exec.send_challenge_response_chunk(peer_id, chunk).await
        }
        GarblerAction::DepositVerifyAdaptors(deposit_id) => {
            exec.deposit_verify_adaptors(peer_id, *deposit_id).await
        }
        GarblerAction::CompleteAdaptorSignatures(deposit_id) => {
            exec.complete_adaptor_signatures(peer_id, *deposit_id).await
        }
        // Circuit actions should be routed to the garbling coordinator,
        // not to worker pool threads. If they arrive here, something is
        // wrong with the scheduler's routing logic.
        GarblerAction::GenerateTableCommitment(..) | GarblerAction::TransferGarblingTable(..) => {
            tracing::error!(
                "circuit action reached worker pool — should go to garbling coordinator"
            );
            HandlerOutcome::Retry
        }
        _ => {
            tracing::error!("unhandled garbler action variant");
            HandlerOutcome::Retry
        }
    }
}

/// Dispatch an evaluator action to the correct per-action method on the executor.
///
/// Pool actions are dispatched directly. Circuit actions (GenerateTableCommitment,
/// ReceiveGarblingTable, EvaluateGarblingTable) should never reach here.
async fn dispatch_evaluator<D: ExecuteEvaluatorJob>(
    exec: &D,
    peer_id: &PeerId,
    action: &EvaluatorAction,
) -> HandlerOutcome {
    match action {
        EvaluatorAction::SendChallengeMsg(msg) => exec.send_challenge_msg(peer_id, msg).await,
        EvaluatorAction::VerifyOpenedInputShares => exec.verify_opened_input_shares(peer_id).await,
        EvaluatorAction::GenerateDepositAdaptors(deposit_id) => {
            exec.generate_deposit_adaptors(peer_id, *deposit_id).await
        }
        EvaluatorAction::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx) => {
            exec.generate_withdrawal_adaptors_chunk(peer_id, *deposit_id, chunk_idx)
                .await
        }
        EvaluatorAction::DepositSendAdaptorMsgChunk(deposit_id, chunk) => {
            exec.deposit_send_adaptor_msg_chunk(peer_id, *deposit_id, chunk)
                .await
        }
        EvaluatorAction::SendChallengeResponseReceipt(msg) => {
            exec.send_challenge_response_receipt(peer_id, msg).await
        }
        // E4: Pool action — receives from network, no circuit reader needed.
        EvaluatorAction::ReceiveGarblingTable(commitment) => {
            exec.receive_garbling_table(peer_id, *commitment).await
        }
        EvaluatorAction::SendTableTransferReceipt(msg) => {
            exec.send_table_transfer_receipt(peer_id, msg).await
        }
        // Circuit actions should be routed to the garbling coordinator.
        EvaluatorAction::GenerateTableCommitment(..)
        | EvaluatorAction::EvaluateGarblingTable(..) => {
            tracing::error!(
                "circuit action reached worker pool — should go to garbling coordinator"
            );
            HandlerOutcome::Retry
        }
        _ => {
            tracing::error!("unhandled evaluator action variant");
            HandlerOutcome::Retry
        }
    }
}

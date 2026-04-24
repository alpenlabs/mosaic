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

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    time::Duration,
};

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_job_api::{ExecuteEvaluatorJob, ExecuteGarblerJob, HandlerOutcome, JobCompletion};
use mosaic_net_svc_api::PeerId;
use tracing::Instrument;

use super::{PoolJob, queue::JobQueue};
use crate::SchedulerFault;

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
        fault_tx: kanal::AsyncSender<SchedulerFault>,
        concurrency: usize,
    ) -> Self {
        let thread_name = format!("worker-{id}");
        let handle = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                let run_result = catch_unwind(AssertUnwindSafe(|| {
                    monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("failed to build monoio runtime")
                        .block_on(worker_loop(
                            id,
                            dispatcher,
                            Arc::clone(&queue),
                            completion_tx,
                            fault_tx.clone(),
                            concurrency,
                        ));
                }));

                if let Err(payload) = run_result {
                    let reason = panic_payload_to_string(payload);
                    tracing::error!(worker = id, %reason, "worker thread exited due to panic");
                    queue.close();
                    let _ = fault_tx.to_sync().send(SchedulerFault::ThreadExited {
                        source: "pool_worker",
                        thread: thread_name,
                        reason,
                    });
                }
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

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "worker thread panicked".to_string(),
        },
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
    fault_tx: kanal::AsyncSender<SchedulerFault>,
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
            let fault_tx = fault_tx.clone();
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
                            if completion_tx.send(*completion).await.is_err() {
                                tracing::error!(
                                    worker = id,
                                    ?peer_id,
                                    "completion channel closed; signaling fatal scheduler fault"
                                );
                                queue.close();
                                let _ = fault_tx
                                    .send(SchedulerFault::CompletionChannelClosed {
                                        source: "pool_worker",
                                        peer_id,
                                    })
                                    .await;
                            }
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
        GarblerAction::SendCommitMsgChunk(wire_idx) => {
            exec.send_commit_msg_chunk(peer_id, *wire_idx).await
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
    }
}

#[cfg(test)]
#[allow(clippy::manual_async_fn)]
mod tests {
    use std::{future::Future, sync::Arc, time::Duration};

    use mosaic_cac_types::{
        AdaptorMsgChunk, ChallengeMsg, ChallengeResponseMsgHeader, CommitMsgHeader, DepositId,
        GarblingSeed, Index, Seed, TableTransferReceiptMsg,
        state_machine::{
            evaluator::ChunkIndex,
            garbler::{self, Action as GarblerAction, Wire},
        },
    };
    use mosaic_job_api::{
        ActionCompletion, CircuitError, CircuitSession, ExecuteEvaluatorJob, ExecuteGarblerJob,
        HandlerOutcome, OwnedChunk,
    };

    use super::*;
    use crate::priority::Priority;

    struct DummySession;

    impl CircuitSession for DummySession {
        fn process_chunk(
            &mut self,
            _chunk: &Arc<OwnedChunk>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }

        fn finish(
            self: Box<Self>,
        ) -> std::pin::Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
            Box::pin(async { HandlerOutcome::Retry })
        }
    }

    #[derive(Clone, Copy)]
    struct TestDispatcher;

    impl ExecuteGarblerJob for TestDispatcher {
        type Session = DummySession;

        fn generate_polynomial_commitments(
            &self,
            _peer_id: &PeerId,
            seed: Seed,
            wire: Wire,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async move {
                HandlerOutcome::Done(ActionCompletion::Garbler {
                    id: garbler::ActionId::GeneratePolynomialCommitments(seed, wire),
                    result: garbler::ActionResult::CommitMsgChunkAcked,
                })
            }
        }

        fn generate_shares(
            &self,
            _peer_id: &PeerId,
            _seed: Seed,
            _index: Index,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn send_commit_msg_header(
            &self,
            _peer_id: &PeerId,
            _header: &CommitMsgHeader,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn send_commit_msg_chunk(
            &self,
            _peer_id: &PeerId,
            wire_idx: u16,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async move {
                HandlerOutcome::Done(ActionCompletion::Garbler {
                    id: garbler::ActionId::SendCommitMsgChunk(wire_idx),
                    result: garbler::ActionResult::CommitMsgChunkAcked,
                })
            }
        }

        fn send_challenge_response_header(
            &self,
            _peer_id: &PeerId,
            _header: &ChallengeResponseMsgHeader,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn send_challenge_response_chunk(
            &self,
            _peer_id: &PeerId,
            _index: &Index,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn deposit_verify_adaptors(
            &self,
            _peer_id: &PeerId,
            _deposit_id: DepositId,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn complete_adaptor_signatures(
            &self,
            _peer_id: &PeerId,
            _deposit_id: DepositId,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn begin_table_commitment(
            &self,
            _peer_id: &PeerId,
            _index: Index,
            _seed: GarblingSeed,
        ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
            async { Ok(DummySession) }
        }

        fn begin_table_transfer(
            &self,
            _peer_id: &PeerId,
            _seed: GarblingSeed,
        ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
            async { Ok(DummySession) }
        }
    }

    impl ExecuteEvaluatorJob for TestDispatcher {
        type Session = DummySession;

        fn send_challenge_msg(
            &self,
            _peer_id: &PeerId,
            _msg: &ChallengeMsg,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn verify_opened_input_shares(
            &self,
            _peer_id: &PeerId,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn send_table_transfer_receipt(
            &self,
            _peer_id: &PeerId,
            _msg: &TableTransferReceiptMsg,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn generate_deposit_adaptors(
            &self,
            _peer_id: &PeerId,
            _deposit_id: DepositId,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn generate_withdrawal_adaptors_chunk(
            &self,
            _peer_id: &PeerId,
            _deposit_id: DepositId,
            _chunk_idx: &ChunkIndex,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn deposit_send_adaptor_msg_chunk(
            &self,
            _peer_id: &PeerId,
            _deposit_id: DepositId,
            _chunk: &AdaptorMsgChunk,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn receive_garbling_table(
            &self,
            _peer_id: &PeerId,
            _commitment: mosaic_cac_types::GarblingTableCommitment,
        ) -> impl Future<Output = HandlerOutcome> + Send {
            async { HandlerOutcome::Retry }
        }

        fn begin_table_commitment(
            &self,
            _peer_id: &PeerId,
            _index: Index,
            _seed: GarblingSeed,
        ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
            async { Ok(DummySession) }
        }

        fn begin_evaluation(
            &self,
            _peer_id: &PeerId,
            _index: Index,
            _commitment: mosaic_cac_types::GarblingTableCommitment,
        ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
            async { Ok(DummySession) }
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

    #[test]
    fn closed_completion_channel_reports_scheduler_fault() {
        run_monoio(async {
            let peer_id = PeerId::from_bytes([9; 32]);
            let queue = Arc::new(JobQueue::new(false));
            let dispatcher = Arc::new(TestDispatcher);
            let (completion_tx, completion_rx) = kanal::bounded_async(1);
            let (fault_tx, fault_rx) = kanal::bounded_async(1);
            drop(completion_rx);

            let worker = monoio::spawn(worker_loop(
                0,
                dispatcher,
                Arc::clone(&queue),
                completion_tx,
                fault_tx,
                1,
            ));

            queue.push(PoolJob {
                priority: Priority::Normal,
                job: WorkerJob::Garbler {
                    peer_id,
                    action: GarblerAction::SendCommitMsgChunk(0),
                },
                attempts: 0,
            });

            let fault = monoio::time::timeout(Duration::from_secs(2), fault_rx.recv())
                .await
                .expect("timed out waiting for scheduler fault")
                .expect("fault channel should stay open");
            assert!(matches!(
                fault,
                SchedulerFault::CompletionChannelClosed {
                    source: "pool_worker",
                    peer_id: fault_peer,
                } if fault_peer == peer_id
            ));

            queue.close();
            monoio::time::timeout(Duration::from_secs(2), worker)
                .await
                .expect("timed out waiting for worker shutdown");
        });
    }
}

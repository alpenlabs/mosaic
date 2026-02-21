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
//!
//! The handler context (net-client, storage, crypto) lives on the worker thread
//! and is shared across all local tasks via [`Arc`].

use std::sync::Arc;
use std::time::Duration;

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_job_api::JobCompletion;
use mosaic_net_svc_api::PeerId;

use super::PoolJob;
use super::queue::JobQueue;
use crate::handlers::{HandlerContext, HandlerOutcome};

/// Delay before requeuing a job that returned [`ExecuteResult::Retry`].
///
/// Prevents busy-spinning when a transient condition (unresponsive peer,
/// full cache, unavailable storage) persists across consecutive attempts.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);

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
pub(crate) struct Worker {
    id: usize,
    /// Thread join handle.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").field("id", &self.id).finish()
    }
}

impl Worker {
    /// Spawn a new worker thread with a monoio runtime.
    ///
    /// The worker immediately begins pulling jobs from `queue`.
    /// Each pulled job is spawned as a local monoio task, bounded by
    /// `concurrency`.
    pub(crate) fn spawn(
        id: usize,
        ctx: Arc<HandlerContext>,
        queue: Arc<JobQueue>,
        completion_tx: kanal::AsyncSender<JobCompletion>,
        concurrency: usize,
    ) -> Self {
        let handle = std::thread::Builder::new()
            .name(format!("worker-{id}"))
            .spawn(move || {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("failed to build monoio runtime")
                    .block_on(worker_loop(id, ctx, queue, completion_tx, concurrency));
            })
            .expect("failed to spawn worker thread");

        Self {
            id,
            handle: Some(handle),
        }
    }

    /// Shut down the worker gracefully.
    ///
    /// The worker will finish after the shared queue is closed and drained.
    /// This method blocks until the thread exits.
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
async fn worker_loop(
    id: usize,
    ctx: Arc<HandlerContext>,
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

    tracing::info!(worker = id, concurrency, "worker started");

    loop {
        // 1. Wait for capacity — blocks if all permits are held by in-flight tasks.
        if permit_rx.recv().await.is_err() {
            break;
        }

        // 2. Pull next job — we only reach here when we have capacity.
        let Some(pool_job) = queue.pop().await else {
            break;
        };

        let ctx = Arc::clone(&ctx);
        let queue = Arc::clone(&queue);
        let completion_tx = completion_tx.clone();
        let permit_tx = permit_tx.clone();

        // 3. Spawn local task. The permit is returned when the task completes,
        //    regardless of whether it succeeded or was requeued for retry.
        monoio::spawn(async move {
            let result = execute_job(&ctx, &pool_job).await;
            match result {
                ExecuteResult::Complete(completion) => {
                    let _ = completion_tx.send(completion).await;
                }
                ExecuteResult::Retry => {
                    let mut job = pool_job;
                    job.attempts += 1;
                    monoio::time::sleep(RETRY_BACKOFF).await;
                    queue.requeue(job);
                }
            }
            // Release permit back to the pool.
            let _ = permit_tx.send(());
        });
    }

    tracing::info!(worker = id, "worker shutting down");
}

/// Result of executing a job.
///
/// [`Complete`](Self::Complete) carries the finished [`JobCompletion`] to be
/// sent to the SM. [`Retry`](Self::Retry) tells the caller to requeue the
/// original [`PoolJob`] (which the caller still owns — `execute_job` only
/// borrows it).
enum ExecuteResult {
    /// Job completed successfully — deliver to SM.
    Complete(JobCompletion),
    /// Transient failure — caller should requeue the original job.
    Retry,
}

/// Execute a single job by dispatching to the appropriate handler.
///
/// Borrows the [`PoolJob`] so that on [`HandlerOutcome::Retry`] the caller
/// retains ownership and can requeue it. Handlers receive `&Action` and
/// clone any data they need to send over the network.
async fn execute_job(ctx: &HandlerContext, pool_job: &PoolJob) -> ExecuteResult {
    let (peer_id, outcome) = match &pool_job.job {
        WorkerJob::Garbler { peer_id, action } => {
            let o = crate::handlers::garbler::execute(ctx, peer_id, action).await;
            (*peer_id, o)
        }
        WorkerJob::Evaluator { peer_id, action } => {
            let o = crate::handlers::evaluator::execute(ctx, peer_id, action).await;
            (*peer_id, o)
        }
    };

    match outcome {
        HandlerOutcome::Done(completion) => ExecuteResult::Complete(JobCompletion {
            peer_id,
            completion,
        }),
        HandlerOutcome::Retry => ExecuteResult::Retry,
    }
}

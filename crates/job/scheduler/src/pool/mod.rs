//! Async thread pool for job execution.
//!
//! Provides [`JobThreadPool`] — a configurable pool of monoio worker threads
//! that pull jobs from a shared priority queue (or FIFO). Workers compete for
//! jobs — whichever worker is idle first grabs the next highest-priority job.
//!
//! This naturally load-balances without explicit distribution logic.

pub(crate) mod queue;
pub(crate) mod worker;

use std::sync::Arc;

use mosaic_job_api::{ExecuteEvaluatorJob, ExecuteGarblerJob, JobCompletion};

use self::{
    queue::JobQueue,
    worker::{Worker, WorkerJob},
};
use crate::{SchedulerFault, priority::Priority};

/// A job waiting in the pool's shared queue.
///
/// Wraps a [`WorkerJob`] with scheduling priority. The queue uses `priority`
/// for ordering (heavy pool) or ignores it (light pool FIFO).
pub(crate) struct PoolJob {
    /// Scheduling priority (ignored by FIFO pools).
    pub priority: Priority,
    /// The job to execute on a worker.
    pub job: WorkerJob,
    /// Number of times this job has been retried due to transient failures.
    pub attempts: u32,
}

impl std::fmt::Debug for PoolJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolJob")
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

/// Configuration for the scheduler's internal job thread pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Number of worker threads.
    pub threads: usize,
    /// Maximum concurrent jobs per worker.
    pub concurrency_per_worker: usize,
    /// Whether to use priority ordering when dequeuing.
    pub priority_queue: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            threads: 1,
            concurrency_per_worker: 8,
            priority_queue: false,
        }
    }
}

/// A pool of monoio worker threads pulling jobs from a shared queue.
///
/// Jobs are submitted via [`submit`](Self::submit) and placed in the shared
/// queue. Workers compete to pull jobs — whichever worker finishes first grabs
/// the next highest-priority job (or next FIFO job for light pools).
///
/// This naturally load-balances: busy workers don't pull, idle workers do.
pub(crate) struct JobThreadPool<D: ExecuteGarblerJob + ExecuteEvaluatorJob> {
    queue: Arc<JobQueue>,
    workers: Vec<Worker<D>>,
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> std::fmt::Debug for JobThreadPool<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobThreadPool")
            .field("workers", &self.workers.len())
            .field("queued", &self.queue.len())
            .finish()
    }
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> JobThreadPool<D> {
    /// Create a new pool with the given configuration.
    ///
    /// Spawns worker threads immediately. Each worker runs its own monoio
    /// runtime and pulls jobs from the shared queue.
    pub(crate) fn new(
        config: PoolConfig,
        dispatcher: Arc<D>,
        completion_tx: kanal::AsyncSender<JobCompletion>,
        fault_tx: kanal::AsyncSender<SchedulerFault>,
    ) -> Self {
        let queue = Arc::new(JobQueue::new(config.priority_queue));

        let workers: Vec<Worker<D>> = (0..config.threads)
            .map(|id| {
                Worker::spawn(
                    id,
                    Arc::clone(&dispatcher),
                    Arc::clone(&queue),
                    completion_tx.clone(),
                    fault_tx.clone(),
                    config.concurrency_per_worker,
                )
            })
            .collect();

        Self { queue, workers }
    }

    /// Submit a job to the pool.
    ///
    /// The job is placed in the shared queue. The next idle worker will pull
    /// it automatically.
    pub(crate) fn submit(&self, priority: Priority, job: WorkerJob) {
        self.queue.push(PoolJob {
            priority,
            job,
            attempts: 0,
        });
    }

    /// Number of jobs waiting in the queue (not yet pulled by a worker).
    #[allow(dead_code)]
    pub(crate) fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Close the queue without joining worker threads.
    ///
    /// Workers will finish in-flight jobs and then exit when they see the
    /// closed queue. This is non-blocking — use it in `Drop` impls where
    /// you can't wait for threads.
    pub(crate) fn close_queue(&self) {
        self.queue.close();
    }

    /// Shut down the pool and join all worker threads.
    ///
    /// Closes the queue (workers will finish after draining remaining jobs)
    /// and shuts down all workers. Workers finish in-flight jobs but don't
    /// accept new ones. This method blocks until all workers exit.
    ///
    /// For non-blocking cleanup (e.g. in `Drop`), use [`close_queue`](Self::close_queue).
    #[allow(dead_code)]
    pub(crate) fn shutdown(self) {
        self.queue.close();
        for worker in self.workers {
            worker.shutdown();
        }
    }
}

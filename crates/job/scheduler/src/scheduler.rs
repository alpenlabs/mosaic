//! Main job scheduler that ties together all three execution pools.
//!
//! The [`JobScheduler`] is the top-level component constructed by the main
//! binary. It owns the light pool, heavy pool, and garbling coordinator, routes
//! incoming actions to the appropriate pool, and forwards completions back to
//! the SM Scheduler via the [`JobSchedulerHandle`].

use std::sync::Arc;

use fasm::actions::Action as FasmAction;
use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_job_api::{JobActions, JobBatch, JobSchedulerHandle};

use crate::{
    garbling::{GarblingConfig, GarblingCoordinator},
    handlers::HandlerContext,
    pool::{JobThreadPool, PoolConfig, worker::WorkerJob},
    priority::Priority,
};

/// Configuration for the [`JobScheduler`].
#[derive(Debug, Clone)]
pub struct JobSchedulerConfig {
    /// Light pool: I/O-bound tasks (sends, acks).
    pub light: PoolConfig,
    /// Heavy pool: CPU-bound non-garbling tasks.
    pub heavy: PoolConfig,
    /// Garbling coordinator: coordinated topology reads + garbling.
    pub garbling: GarblingConfig,
    /// Capacity of the submission channel.
    pub submission_queue_size: usize,
    /// Capacity of the completion channel.
    pub completion_queue_size: usize,
}

impl Default for JobSchedulerConfig {
    fn default() -> Self {
        Self {
            light: PoolConfig {
                threads: 1,
                concurrency_per_worker: 32,
                priority_queue: false,
            },
            heavy: PoolConfig {
                threads: 2,
                concurrency_per_worker: 8,
                priority_queue: true,
            },
            garbling: GarblingConfig::default(),
            submission_queue_size: 256,
            completion_queue_size: 256,
        }
    }
}

/// The job scheduler — executes actions emitted by state machines.
///
/// Owns three execution pools:
/// - **Light pool**: FIFO queue, single thread, high concurrency (network I/O)
/// - **Heavy pool**: Priority queue, multiple threads (crypto, verification)
/// - **Garbling coordinator**: Barrier-synchronized topology reads + garbling
///
/// Constructed by the main binary. The SM Scheduler interacts with it
/// exclusively through the [`JobSchedulerHandle`] returned by [`new`](Self::new).
pub struct JobScheduler {
    light: JobThreadPool,
    heavy: JobThreadPool,
    garbling: GarblingCoordinator,
    /// Receives batch submissions from the SM Scheduler.
    submission_rx: kanal::AsyncReceiver<JobBatch>,
}

impl std::fmt::Debug for JobScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobScheduler")
            .field("light", &self.light)
            .field("heavy", &self.heavy)
            .field("garbling", &self.garbling)
            .finish()
    }
}

impl JobScheduler {
    /// Create a new job scheduler and return a handle for the SM Scheduler.
    ///
    /// The returned [`JobSchedulerHandle`] is the SM Scheduler's only interface
    /// to the job system. It is cheaply cloneable.
    ///
    /// After construction, call [`run`](Self::run) to start the dispatch loop.
    pub fn new(config: JobSchedulerConfig, ctx: HandlerContext) -> (Self, JobSchedulerHandle) {
        // Channel for SM Scheduler → Job Scheduler (batch submissions).
        let (submit_tx, submission_rx) = kanal::bounded_async(config.submission_queue_size);

        // Channel for Job Scheduler → SM Scheduler (completed results).
        let (completion_tx, completion_rx) = kanal::bounded_async(config.completion_queue_size);

        let ctx = Arc::new(ctx);
        let light = JobThreadPool::new(config.light, Arc::clone(&ctx), completion_tx.clone());
        let heavy = JobThreadPool::new(config.heavy, Arc::clone(&ctx), completion_tx.clone());
        let garbling = GarblingCoordinator::new(config.garbling, completion_tx);

        let handle = JobSchedulerHandle::new(submit_tx, completion_rx);

        let scheduler = Self {
            light,
            heavy,
            garbling,
            submission_rx,
        };

        (scheduler, handle)
    }

    /// Run the job scheduler on a dedicated thread with its own monoio runtime.
    ///
    /// Spawns the scheduler thread which reads batches from the SM Scheduler
    /// and routes each action to the appropriate pool. Workers on each pool
    /// pull jobs from the shared queue automatically.
    ///
    /// Returns a join handle for the scheduler thread.
    pub fn run(self) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("job-scheduler".into())
            .spawn(move || {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("failed to build scheduler monoio runtime")
                    .block_on(self.scheduler_loop());
            })
            .expect("failed to spawn scheduler thread")
    }

    /// Main scheduler loop running on monoio.
    async fn scheduler_loop(self) {
        tracing::info!("job scheduler started");

        while let Ok(batch) = self.submission_rx.recv().await {
            self.dispatch_batch(batch);
        }

        tracing::info!("job scheduler submission channel closed, shutting down");
    }

    /// Route each action in a batch to the appropriate pool.
    ///
    /// Unwraps the FASM [`ActionContainer`] to extract individual tracked
    /// actions, categorizes each one, assigns priority, and dispatches to the
    /// appropriate pool.
    fn dispatch_batch(&self, batch: JobBatch) {
        let peer_id = batch.peer_id;

        match batch.actions {
            JobActions::Garbler(container) => {
                for fasm_action in container {
                    match fasm_action {
                        FasmAction::Tracked(tracked) => {
                            let (_id, action) = tracked.into_parts();
                            let category = action.category();
                            let priority = action.priority();
                            let worker_job = WorkerJob::Garbler { peer_id, action };

                            match category {
                                ActionCategory::Light => {
                                    self.light.submit(priority, worker_job);
                                }
                                ActionCategory::Heavy => {
                                    self.heavy.submit(priority, worker_job);
                                }
                                ActionCategory::Garbling => {
                                    // TODO: register with garbling coordinator
                                    tracing::warn!("garbling dispatch not yet implemented");
                                }
                            }
                        }
                        FasmAction::Untracked(_) => {
                            // Untracked actions are fire-and-forget.
                            // Currently unused by either SM.
                        }
                    }
                }
            }
            JobActions::Evaluator(container) => {
                for fasm_action in container {
                    match fasm_action {
                        FasmAction::Tracked(tracked) => {
                            let (_id, action) = tracked.into_parts();
                            let category = action.category();
                            let priority = action.priority();
                            let worker_job = WorkerJob::Evaluator { peer_id, action };

                            match category {
                                ActionCategory::Light => {
                                    self.light.submit(priority, worker_job);
                                }
                                ActionCategory::Heavy => {
                                    self.heavy.submit(priority, worker_job);
                                }
                                ActionCategory::Garbling => {
                                    // TODO: register with garbling coordinator
                                    tracing::warn!("garbling dispatch not yet implemented");
                                }
                            }
                        }
                        FasmAction::Untracked(_) => {
                            // Untracked actions are fire-and-forget.
                            // Currently unused by either SM.
                        }
                    }
                }
            }
        }
    }

    /// Shut down all pools gracefully.
    ///
    /// Workers finish in-flight jobs but do not pick up new ones.
    pub fn shutdown(self) {
        tracing::info!("job scheduler shutting down");

        self.garbling.shutdown();
        self.light.shutdown();
        self.heavy.shutdown();

        tracing::info!("job scheduler shut down complete");
    }
}

// ============================================================================
// Action classification (pool routing + priority)
// ============================================================================

/// Internal action category for routing to the correct pool.
enum ActionCategory {
    Light,
    Heavy,
    Garbling,
}

/// Classifies an action for scheduling: which pool it belongs to and what
/// priority it should receive.
///
/// Implemented for both [`GarblerAction`] and [`EvaluatorAction`]. The
/// scheduler calls these methods when dispatching individual actions from a
/// batch.
trait Classify {
    /// Which pool should execute this action.
    fn category(&self) -> ActionCategory;

    /// Scheduling priority within the heavy pool.
    ///
    /// Derived from the protocol phase:
    /// - **Critical**: Withdrawal dispute (blockchain timeout at stake)
    /// - **High**: Active deposit processing (user waiting)
    /// - **Normal**: Setup operations (done in advance)
    fn priority(&self) -> Priority;
}

impl Classify for GarblerAction {
    fn category(&self) -> ActionCategory {
        match self {
            // Light (outbound protocol sends)
            Self::SendCommitMsgChunk(_) | Self::SendChallengeResponseMsgChunk(_) => {
                ActionCategory::Light
            }

            // Garbling (coordinated disk I/O)
            Self::GenerateTableCommitment(..) | Self::TransferGarblingTable(_) => {
                ActionCategory::Garbling
            }

            // Heavy (everything else)
            Self::GeneratePolynomialCommitments(..)
            | Self::GenerateShares(..)
            | Self::DepositVerifyAdaptors(..)
            | Self::CompleteAdaptorSignatures(..) => ActionCategory::Heavy,

            // Non-exhaustive fallback
            _ => ActionCategory::Heavy,
        }
    }

    fn priority(&self) -> Priority {
        match self {
            // Withdrawal — Critical
            Self::CompleteAdaptorSignatures(..) => Priority::Critical,

            // Deposit — High
            Self::DepositVerifyAdaptors(..) => Priority::High,

            // Setup / everything else — Normal
            _ => Priority::Normal,
        }
    }
}

impl Classify for EvaluatorAction {
    fn category(&self) -> ActionCategory {
        match self {
            // Light (outbound protocol sends)
            Self::SendChallengeMsg(_) | Self::DepositSendAdaptorMsgChunk(..) => {
                ActionCategory::Light
            }

            // Garbling (coordinated disk I/O)
            Self::GenerateTableCommitment(..) | Self::ReceiveGarblingTable(_) => {
                ActionCategory::Garbling
            }

            // Heavy (everything else)
            Self::VerifyOpenedInputShares
            | Self::GenerateDepositAdaptors(_)
            | Self::GenerateWithdrawalAdaptorsChunk(..)
            | Self::EvaluateGarblingTable(..) => ActionCategory::Heavy,

            // Non-exhaustive fallback
            _ => ActionCategory::Heavy,
        }
    }

    fn priority(&self) -> Priority {
        match self {
            // Withdrawal — Critical
            Self::EvaluateGarblingTable(..) => Priority::Critical,

            // Deposit — High
            Self::GenerateDepositAdaptors(_)
            | Self::GenerateWithdrawalAdaptorsChunk(..)
            | Self::DepositSendAdaptorMsgChunk(..) => Priority::High,

            // Setup / everything else — Normal
            _ => Priority::Normal,
        }
    }
}

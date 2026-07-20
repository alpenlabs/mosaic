//! Main job scheduler that ties together all three execution pools.
//!
//! The [`JobScheduler`] is the top-level component constructed by the main
//! binary. It owns the light pool, heavy pool, and garbling coordinator, routes
//! incoming actions to the appropriate pool, and forwards completions back to
//! the SM Scheduler via the [`JobSchedulerHandle`].

use std::{sync::Arc, thread::JoinHandle};

use fasm::actions::Action as FasmAction;
use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_job_api::{
    CircuitAction, ExecuteEvaluatorJob, ExecuteGarblerJob, HintKey, HintKind, JobActions, JobBatch,
    JobSchedulerHandle, PendingCircuitJob, SessionFactory,
};
use mosaic_net_client::{InboundHintStream, SchedulerMessage};
use mosaic_net_svc_api::PeerId;
use tracing::Instrument;

use crate::{
    SchedulerFault,
    garbling::{GarblingConfig, GarblingCoordinator},
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
    ///
    /// No longer load-bearing: the submission channel is now unbounded to
    /// avoid bounded-queue cycle deadlocks with the SM executor (see #221).
    /// Retained for config compatibility; ignored at runtime.
    pub submission_queue_size: usize,
    /// Capacity of the completion channel.
    ///
    /// No longer load-bearing: the completion channel is now unbounded for
    /// the same reason as `submission_queue_size`.
    pub completion_queue_size: usize,
}

impl Default for JobSchedulerConfig {
    fn default() -> Self {
        Self {
            light: PoolConfig {
                threads: 1,
                concurrency_per_worker: 32,
                priority_queue: false,
                // Boost cap: small vs concurrency (512 in production
                // config) so a single peer / attack surface can't reorder
                // the whole queue. See `SchedulerHint` design.
                max_boost_slots: Some(64),
            },
            heavy: PoolConfig {
                threads: 2,
                concurrency_per_worker: 8,
                priority_queue: true,
                max_boost_slots: None,
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
pub struct JobScheduler<D: ExecuteGarblerJob + ExecuteEvaluatorJob> {
    light: Option<JobThreadPool<D>>,
    heavy: Option<JobThreadPool<D>>,
    garbling: Option<GarblingCoordinator>,
    /// Receives batch submissions from the SM Scheduler.
    submission_rx: kanal::AsyncReceiver<JobBatch>,
    /// Internal fatal faults reported by workers/coordinator.
    fault_rx: kanal::AsyncReceiver<SchedulerFault>,
    /// Optional inbound scheduler-hint stream. When present, the main
    /// loop consumes hints and promotes matching queued jobs in the
    /// light pool. Absent = no hint support (tests, backwards compat).
    hint_stream_rx: Option<kanal::AsyncReceiver<InboundHintStream>>,
}

/// Controller for graceful scheduler shutdown.
#[derive(Debug)]
pub struct JobSchedulerController {
    thread_handle: Option<JoinHandle<()>>,
    shutdown_tx: kanal::AsyncSender<()>,
}

impl JobSchedulerController {
    /// Signal the scheduler to stop and wait for all worker threads to exit.
    pub fn shutdown(mut self) -> Result<(), std::io::Error> {
        let _ = self.shutdown_tx.clone().to_sync().send(());

        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| std::io::Error::other("job scheduler thread panicked"))?;
        }

        Ok(())
    }

    /// Check whether the scheduler thread is still running.
    pub fn is_running(&self) -> bool {
        self.thread_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for JobSchedulerController {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.clone().to_sync().try_send(());
    }
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> std::fmt::Debug for JobScheduler<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobScheduler")
            .field("light", &self.light)
            .field("heavy", &self.heavy)
            .field("garbling", &self.garbling)
            .finish()
    }
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> JobScheduler<D> {
    /// Create a new job scheduler and return a handle for the SM Scheduler.
    ///
    /// The returned [`JobSchedulerHandle`] is the SM Scheduler's only interface
    /// to the job system. It is cheaply cloneable.
    ///
    /// After construction, call [`run`](Self::run) to start the dispatch loop.
    pub fn new(
        config: JobSchedulerConfig,
        dispatcher: D,
        hint_stream_rx: Option<kanal::AsyncReceiver<InboundHintStream>>,
    ) -> (Self, JobSchedulerHandle) {
        // Channel for SM Scheduler → Job Scheduler (batch submissions).
        //
        // Unbounded: the SM scheduler's STF can produce these inline while
        // processing a job completion. Bounding this channel created a
        // cycle-deadlock against the worker → SM-executor completion channel
        // under failure bursts (see #221). Volume here is bounded upstream
        // by per-peer protocol-message rate limiting (#220).
        let (submit_tx, submission_rx) = kanal::unbounded_async();

        // Channel for Job Scheduler → SM Scheduler (completed results).
        //
        // Unbounded for the same reason as the submission channel: workers
        // produce completions at the rate jobs finish, and a bounded receive
        // side could block them while the SM executor is mid-processing.
        let (completion_tx, completion_rx) = kanal::unbounded_async();

        // Worker fault reports. Unbounded so a faulting worker never blocks
        // on send; volume is tiny (one per faulting thread).
        let (fault_tx, fault_rx) = kanal::unbounded_async();

        let executor = Arc::new(dispatcher);

        // The executor implements SessionFactory via blanket impl (any
        // D: ExecuteGarblerJob + ExecuteEvaluatorJob gets it automatically).
        // We erase the concrete type so the coordinator is not generic over D.
        let factory: Arc<dyn SessionFactory> = Arc::clone(&executor) as Arc<dyn SessionFactory>;

        let light = JobThreadPool::new(
            config.light,
            Arc::clone(&executor),
            completion_tx.clone(),
            fault_tx.clone(),
        );
        let heavy = JobThreadPool::new(
            config.heavy,
            Arc::clone(&executor),
            completion_tx.clone(),
            fault_tx.clone(),
        );
        let garbling = GarblingCoordinator::new(config.garbling, factory, completion_tx, fault_tx);

        let handle = JobSchedulerHandle::new(submit_tx, completion_rx);

        let scheduler = Self {
            light: Some(light),
            heavy: Some(heavy),
            garbling: Some(garbling),
            submission_rx,
            fault_rx,
            hint_stream_rx,
        };

        (scheduler, handle)
    }

    /// Handle an inbound `SchedulerMessage` by promoting the matching job
    /// in the light pool. Best-effort; unknown / unmatched hints no-op.
    fn apply_scheduler_message(&self, inbound: InboundHintStream) {
        let InboundHintStream { peer, payload } = inbound;
        let peer_id: mosaic_net_svc_api::PeerId = peer;
        let msg = match SchedulerMessage::decode(&payload) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    error = %e,
                    "failed to decode inbound SchedulerMessage; ignoring"
                );
                return;
            }
        };
        let key = match msg {
            SchedulerMessage::TransferStarting { commitment } => {
                HintKey::new(peer_id, HintKind::TransferStarting, commitment)
            }
        };
        if let Some(light) = self.light.as_ref() {
            let promoted = light.apply_hint(&key);
            tracing::debug!(
                peer = %hex::encode(peer_id),
                kind = ?key.kind,
                promoted,
                "applied SchedulerMessage hint"
            );
        }
    }

    /// Run the job scheduler on a dedicated thread with its own monoio runtime.
    ///
    /// Spawns the scheduler thread which reads batches from the SM Scheduler
    /// and routes each action to the appropriate pool. Workers on each pool
    /// pull jobs from the shared queue automatically.
    ///
    /// Returns a controller for graceful shutdown.
    pub fn run(self) -> JobSchedulerController {
        let (shutdown_tx, shutdown_rx) = kanal::bounded_async(1);

        let thread_handle = std::thread::Builder::new()
            .name("job-scheduler".into())
            .spawn(move || {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("failed to build scheduler monoio runtime")
                    .block_on(
                        self.scheduler_loop(shutdown_rx)
                            .instrument(tracing::info_span!("job_scheduler.main_loop")),
                    );
            })
            .expect("failed to spawn scheduler thread");

        JobSchedulerController {
            thread_handle: Some(thread_handle),
            shutdown_tx,
        }
    }

    /// Main scheduler loop running on monoio.
    async fn scheduler_loop(self, shutdown_rx: kanal::AsyncReceiver<()>) {
        let mut this = self;
        tracing::info!("job scheduler main loop started");

        // Optional hint receiver: if not present, we skip the select arm by
        // making it a never-completing future.
        loop {
            monoio::select! {
                recv = this.submission_rx.recv() => {
                    match recv {
                        Ok(batch) => this.dispatch_batch(batch).await,
                        Err(_) => {
                            tracing::info!("job scheduler submission channel closed; main loop exiting");
                            break;
                        }
                    }
                }
                recv = async {
                    match &this.hint_stream_rx {
                        Some(rx) => rx.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(inbound) = recv {
                        this.apply_scheduler_message(inbound);
                    } else {
                        // Channel closed: drop the receiver so this arm
                        // reverts to `pending()` on the next iteration.
                        // Otherwise `recv().await` returns `None`
                        // immediately every iteration, busy-spinning the
                        // scheduler thread and starving the other arms.
                        tracing::debug!("scheduler hint channel closed; disabling hint arm");
                        this.hint_stream_rx = None;
                    }
                }
                recv = shutdown_rx.recv() => {
                    match recv {
                        Ok(()) | Err(_) => {
                            tracing::info!("job scheduler shutdown requested");
                            break;
                        }
                    }
                }
                recv = this.fault_rx.recv() => {
                    match recv {
                        Ok(SchedulerFault::CompletionChannelClosed { source, peer_id }) => {
                            tracing::error!(
                                source,
                                peer = ?peer_id,
                                "job scheduler completion delivery failed; shutting down fail-closed"
                            );
                            break;
                        }
                        Ok(SchedulerFault::ThreadExited { source, thread, reason }) => {
                            tracing::error!(
                                source,
                                %thread,
                                %reason,
                                "job scheduler thread dependency exited unexpectedly; shutting down fail-closed"
                            );
                            break;
                        }
                        Err(_) => {
                            tracing::debug!("job scheduler fault channel closed");
                        }
                    }
                }
            }
        }

        this.shutdown();
        tracing::info!("job scheduler main loop exited cleanly");
    }

    /// Route each action in a batch to the appropriate pool.
    ///
    /// Unwraps the FASM [`ActionContainer`] to extract individual tracked
    /// actions, categorizes each one, assigns priority, and dispatches to the
    /// appropriate pool.
    async fn dispatch_batch(&self, batch: JobBatch) {
        let peer_id = batch.peer_id;
        let action_count = batch.actions.len();
        let role = if batch.actions.is_garbler() {
            "garbler"
        } else {
            "evaluator"
        };
        let span = tracing::debug_span!(
            "job_scheduler.dispatch_batch",
            peer = ?peer_id,
            role,
            actions = action_count
        );

        async move {
            tracing::debug!("dispatching submitted action batch");
            match batch.actions {
                JobActions::Garbler(container) => {
                    for fasm_action in container {
                        match fasm_action {
                            FasmAction::Tracked(tracked) => {
                                let (_id, action) = tracked.into_parts();
                                let category = action.category();
                                let priority = action.priority();

                                match category {
                                    ActionCategory::Garbling => {
                                        self.dispatch_garbler_circuit(peer_id, action).await;
                                    }
                                    _ => {
                                        let worker_job = WorkerJob::Garbler { peer_id, action };
                                        match category {
                                            ActionCategory::Light => {
                                                self.light
                                                    .as_ref()
                                                    .expect("light pool must exist while scheduler is running")
                                                    .submit(priority, worker_job, None);
                                            }
                                            ActionCategory::Heavy => {
                                                self.heavy
                                                    .as_ref()
                                                    .expect("heavy pool must exist while scheduler is running")
                                                    .submit(priority, worker_job, None);
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                }
                            }
                            FasmAction::Untracked(_) => {}
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

                                match category {
                                    ActionCategory::Garbling => {
                                        self.dispatch_evaluator_circuit(peer_id, action).await;
                                    }
                                    _ => {
                                        // For ReceiveGarblingTable, register a
                                        // hint key so an inbound
                                        // `TransferStarting` from `peer_id`
                                        // can promote this job to the front.
                                        let hint_key = match &action {
                                            EvaluatorAction::ReceiveGarblingTable(commitment) => {
                                                let payload: [u8; 32] = (*commitment).into();
                                                Some(HintKey::new(
                                                    peer_id,
                                                    HintKind::TransferStarting,
                                                    payload,
                                                ))
                                            }
                                            _ => None,
                                        };
                                        let worker_job = WorkerJob::Evaluator { peer_id, action };
                                        match category {
                                            ActionCategory::Light => {
                                                self.light
                                                    .as_ref()
                                                    .expect("light pool must exist while scheduler is running")
                                                    .submit(priority, worker_job, hint_key);
                                            }
                                            ActionCategory::Heavy => {
                                                self.heavy
                                                    .as_ref()
                                                    .expect("heavy pool must exist while scheduler is running")
                                                    .submit(priority, worker_job, None);
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                }
                            }
                            FasmAction::Untracked(_) => {}
                        }
                    }
                }
            }
            tracing::debug!("action batch dispatched");
        }
        .instrument(span)
        .await
    }

    /// Build a [`PendingCircuitJob`] for a garbler circuit action and submit
    /// it to the garbling coordinator.
    ///
    /// Session creation happens inside the coordinator (with retry for
    /// transient failures), not here. This method never blocks.
    async fn dispatch_garbler_circuit(&self, peer_id: PeerId, action: GarblerAction) {
        let circuit_action = match &action {
            GarblerAction::GenerateTableCommitment(index, seed) => {
                CircuitAction::GarblerCommitment {
                    index: *index,
                    seed: *seed,
                }
            }
            GarblerAction::TransferGarblingTable(seed) => {
                CircuitAction::GarblerTransfer { seed: *seed }
            }
            _ => {
                tracing::error!(
                    ?action,
                    "non-circuit garbler action routed to circuit dispatch"
                );
                return;
            }
        };

        self.garbling
            .as_ref()
            .expect("garbling coordinator must exist while scheduler is running")
            .submit(PendingCircuitJob {
                peer_id,
                action: circuit_action,
            })
            .await;
        tracing::debug!(peer = ?peer_id, action = ?action, "submitted garbler circuit action");
    }

    /// Build a [`PendingCircuitJob`] for an evaluator circuit action and
    /// submit it to the garbling coordinator.
    async fn dispatch_evaluator_circuit(&self, peer_id: PeerId, action: EvaluatorAction) {
        let circuit_action = match &action {
            EvaluatorAction::GenerateTableCommitment(index, seed) => {
                CircuitAction::EvaluatorCommitment {
                    index: *index,
                    seed: *seed,
                }
            }
            EvaluatorAction::EvaluateGarblingTable(index, commitment) => {
                CircuitAction::EvaluatorEvaluation {
                    index: *index,
                    commitment: *commitment,
                }
            }
            // E4 is a pool action (Light), not a circuit action — should never
            // reach here. If it does, routing logic has a bug.
            EvaluatorAction::ReceiveGarblingTable(_) => {
                tracing::error!(
                    "ReceiveGarblingTable routed to circuit dispatch — should go to light pool"
                );
                return;
            }
            _ => {
                tracing::error!(
                    ?action,
                    "non-circuit evaluator action routed to circuit dispatch"
                );
                return;
            }
        };

        self.garbling
            .as_ref()
            .expect("garbling coordinator must exist while scheduler is running")
            .submit(PendingCircuitJob {
                peer_id,
                action: circuit_action,
            })
            .await;
        tracing::debug!(peer = ?peer_id, action = ?action, "submitted evaluator circuit action");
    }

    /// Shut down all pools gracefully.
    ///
    /// Closes pool queues so workers drain remaining jobs and exit, then
    /// shuts down the garbling coordinator (joining its thread). Safe to
    /// call multiple times — all operations are idempotent.
    pub fn shutdown(mut self) {
        tracing::info!("job scheduler shutting down");
        if let Some(light) = self.light.take() {
            light.shutdown();
        }
        if let Some(heavy) = self.heavy.take() {
            heavy.shutdown();
        }
        if let Some(mut garbling) = self.garbling.take() {
            garbling.shutdown();
        }
        tracing::info!("job scheduler shut down complete");
    }
}

impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> Drop for JobScheduler<D> {
    fn drop(&mut self) {
        // Ensure queues are closed and coordinator thread is joined even if
        // the caller forgot to call shutdown(). All operations are idempotent
        // so double-calling (shutdown + drop) is safe.
        if let Some(light) = self.light.as_ref() {
            light.close_queue();
        }
        if let Some(heavy) = self.heavy.as_ref() {
            heavy.close_queue();
        }
        if let Some(garbling) = self.garbling.as_mut() {
            garbling.shutdown();
        }
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
            Self::SendCommitMsgHeader(_)
            | Self::SendCommitMsgChunk(_)
            | Self::SendChallengeResponseMsgHeader(_)
            | Self::SendChallengeResponseMsgChunk(_) => ActionCategory::Light,

            // Garbling (coordinated disk I/O)
            Self::GenerateTableCommitment(..) | Self::TransferGarblingTable(_) => {
                ActionCategory::Garbling
            }

            // Heavy (everything else)
            Self::GeneratePolynomialCommitments(..)
            | Self::GenerateShares(..)
            | Self::DepositVerifyAdaptors(..)
            | Self::CompleteAdaptorSignatures(..) => ActionCategory::Heavy,
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
            // Light (outbound protocol sends + network receive)
            Self::SendChallengeMsg(_)
            | Self::SendTableTransferReceipt(_)
            | Self::DepositSendAdaptorMsgChunk(..)
            | Self::ReceiveGarblingTable(_) => ActionCategory::Light,

            // Garbling (coordinated disk I/O — shared circuit reader)
            Self::GenerateTableCommitment(..) | Self::EvaluateGarblingTable(..) => {
                ActionCategory::Garbling
            }

            // Heavy (everything else)
            Self::VerifyOpenedInputShares
            | Self::GenerateDepositAdaptors(_)
            | Self::GenerateWithdrawalAdaptorsChunk(..) => ActionCategory::Heavy,
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

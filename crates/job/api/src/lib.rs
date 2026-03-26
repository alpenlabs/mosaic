//! API types for the Mosaic job scheduler.
//!
//! This crate defines the interface between the SM Scheduler, Job Scheduler,
//! and Job Executors. It provides:
//!
//! - [`ExecuteGarblerJob`] / [`ExecuteEvaluatorJob`] — per-action executor traits with separate
//!   methods for pool actions and circuit actions.
//! - [`CircuitSession`] — block-by-block session driven by the garbling coordinator for coordinated
//!   circuit operations.
//! - [`SessionFactory`] — dyn-compatible trait for type-erased session creation, used by the
//!   coordinator so it doesn't need executor generics.
//! - [`CircuitAction`] / [`PendingCircuitJob`] — action descriptors submitted to the garbling
//!   coordinator. Retainable for retry on transient failure.
//! - [`HandlerOutcome`] — success/retry result type.
//! - Submission and completion types for the SM ↔ scheduler channel.
//!
//! # Type Safety
//!
//! Pool actions (network sends, crypto) return [`HandlerOutcome`] directly —
//! the scheduler submits them to worker pool threads.
//!
//! Circuit actions (garbling, evaluation) return a [`CircuitSession`] — the
//! scheduler's garbling coordinator drives them block-by-block with a shared
//! circuit reader. A circuit action physically cannot go through the pool
//! path because it returns a `Session`, not a `HandlerOutcome`.
//!
//! # Session Lifecycle
//!
//! The scheduler submits [`PendingCircuitJob`]s to the garbling coordinator.
//! The coordinator creates sessions via [`SessionFactory::create_session`],
//! retrying on [`CircuitError::StorageUnavailable`]. If a session is evicted
//! mid-pass (timeout or error), the original [`CircuitAction`] is preserved
//! for retry on the next pass. No action is ever silently dropped.

mod handle;
mod submission;

use std::{future::Future, pin::Pin, sync::Arc};

/// Return type for [`SessionFactory::create_session`].
///
/// A boxed future that produces a boxed [`CircuitSession`] or a [`CircuitError`].
pub type CreateSessionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn CircuitSession>, CircuitError>> + Send + 'a>>;

pub use handle::{JobSchedulerHandle, SchedulerStopped};
use mosaic_cac_types::{
    AdaptorMsgChunk, ChallengeMsg, ChallengeResponseMsgHeader, CommitMsgHeader, DepositId,
    GarblingSeed, GarblingTableCommitment, Seed, TableTransferReceiptMsg, TableTransferRequestMsg,
    state_machine::{evaluator::ChunkIndex, garbler::Wire},
};
use mosaic_net_svc_api::PeerId;
use mosaic_vs3::Index;
pub use submission::{ActionCompletion, JobActions, JobBatch, JobCompletion};

// ════════════════════════════════════════════════════════════════════════════
// Outcome
// ════════════════════════════════════════════════════════════════════════════

/// Outcome of executing a job action.
///
/// The SM never sees failures. [`Done`](Self::Done) delivers the completion;
/// [`Retry`](Self::Retry) requeues the job so other peers can make progress
/// while this job waits for a transient condition to resolve.
#[derive(Debug)]
pub enum HandlerOutcome {
    /// Action completed successfully — deliver [`ActionCompletion`] to the SM.
    Done(ActionCompletion),
    /// Transient failure — requeue job to back of queue.
    Retry,
}

// ════════════════════════════════════════════════════════════════════════════
// Circuit session (shared by both garbler and evaluator circuit ops)
// ════════════════════════════════════════════════════════════════════════════

/// Error from a circuit session operation.
#[derive(Debug)]
pub enum CircuitError {
    /// Storage read failed or data not yet available.
    StorageUnavailable,
    /// Session setup failed (e.g. invalid parameters).
    SetupFailed(String),
    /// Processing a chunk failed.
    ChunkFailed(String),
    /// Transient network or I/O failure during session setup — retryable.
    TransientFailure(String),
}

/// A block of circuit gate data shared across concurrent sessions via [`Arc`].
///
/// The garbling coordinator copies block data from the circuit reader into
/// this owned representation, then shares it across worker threads. Each
/// block is 256 KiB of gate data (in1, in2, out addresses + gate type bits).
///
/// The coordinator reads chunks of 16 blocks at a time (~4 MiB) from the
/// `ReaderV5c` and wraps each block in an `Arc<OwnedChunk>` for distribution.
#[derive(Debug, Clone)]
pub struct OwnedBlock {
    /// Raw gate data: in1 (u32 LE), in2 (u32 LE), out (u32 LE) per gate.
    pub gate_data: Vec<u8>,
    /// Bit-packed gate types (0 = XOR, 1 = AND). One bit per gate.
    pub gate_types: Vec<u8>,
    /// Number of valid gates in this block (last block may be partial).
    pub num_gates: usize,
}

/// A chunk of blocks shared across worker threads via `Arc`.
#[derive(Debug, Clone)]
pub struct OwnedChunk {
    /// The blocks in this chunk.
    pub blocks: Vec<OwnedBlock>,
}

/// A live circuit session driven block-by-block by the garbling coordinator.
///
/// Created by `begin_table_commitment`, `begin_table_transfer`,
/// `begin_table_receive`, or `begin_evaluation` on the executor traits.
/// The coordinator reads circuit blocks, wraps them in `Arc<OwnedChunk>`,
/// and calls `process_chunk` on all active sessions. After all blocks are
/// processed, the coordinator calls `finish` to produce the completion.
/// A live circuit session driven block-by-block by the garbling coordinator.
///
/// This trait is **dyn-compatible** (uses `Pin<Box<dyn Future>>`) so the
/// coordinator can hold heterogeneous sessions (garbling commitment,
/// garbling transfer, evaluation) in the same batch.
pub trait CircuitSession: Send {
    /// Process one chunk of blocks from the shared circuit reader.
    ///
    /// The chunk is shared via `Arc` across all concurrent sessions.
    /// This method should process all gates in the chunk, feeding them
    /// to the garbling/evaluation instance and handling output (hashing,
    /// streaming, etc.) as appropriate for the session type.
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>>;

    /// Finalize the session after all blocks have been processed.
    ///
    /// Extracts output labels, computes commitments, translates evaluation
    /// results, etc. Returns the action completion to deliver to the SM.
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>>;
}

// ════════════════════════════════════════════════════════════════════════════
// Circuit action descriptors (submitted to garbling coordinator)
// ════════════════════════════════════════════════════════════════════════════

/// Describes a circuit action that the garbling coordinator will execute.
///
/// Unlike a live [`CircuitSession`], this is a plain data struct that can be
/// stored, retried, and resubmitted. The coordinator calls
/// [`SessionFactory::create_session`] to turn it into a live session when
/// it's ready to start a pass.
///
/// If session creation fails with [`CircuitError::StorageUnavailable`], the
/// action stays in the coordinator's pending list for the next pass —
/// no action is ever silently dropped.
#[derive(Debug, Clone)]
pub enum CircuitAction {
    /// G3: Generate garbling table commitment.
    GarblerCommitment {
        /// Circuit index (1..=N_CIRCUITS).
        index: Index,
        /// Garbling seed for deterministic RNG derivation.
        seed: GarblingSeed,
    },
    /// G8: Transfer garbling table to evaluator via bulk stream.
    GarblerTransfer {
        /// Garbling seed (also used to resolve circuit index and commitment
        /// from the SM root state).
        seed: GarblingSeed,
    },
    /// E3: Re-garble to verify garbling table commitment.
    EvaluatorCommitment {
        /// Circuit index (must be in the challenge set).
        index: Index,
        /// Opened garbling seed for the challenged circuit.
        seed: GarblingSeed,
    },
    /// E8: Evaluate a stored garbling table.
    EvaluatorEvaluation {
        /// Circuit index of the unopened (evaluation) circuit.
        index: Index,
        /// Expected commitment to verify evaluation against.
        commitment: GarblingTableCommitment,
    },
}

/// A circuit action waiting to be executed by the garbling coordinator.
///
/// Submitted by the scheduler via the coordinator's async channel. The
/// coordinator collects these into batches, creates sessions, and drives
/// them through the circuit file.
#[derive(Debug)]
pub struct PendingCircuitJob {
    /// The peer this action belongs to.
    pub peer_id: PeerId,
    /// The circuit action to execute.
    pub action: CircuitAction,
}

// ════════════════════════════════════════════════════════════════════════════
// Session factory (dyn-compatible, used by coordinator)
// ════════════════════════════════════════════════════════════════════════════

/// Creates [`CircuitSession`]s from [`PendingCircuitJob`] descriptors.
///
/// This trait is **dyn-compatible** (`Pin<Box<dyn Future>>` return) so the
/// garbling coordinator can hold an `Arc<dyn SessionFactory>` without being
/// generic over the concrete executor type.
///
/// A blanket implementation is provided for any type that implements both
/// [`ExecuteGarblerJob`] and [`ExecuteEvaluatorJob`], so [`MosaicExecutor`]
/// gets this automatically — no manual impl needed.
///
/// [`MosaicExecutor`]: https://docs.rs/mosaic-job-executors/latest/mosaic_job_executors/struct.MosaicExecutor.html
pub trait SessionFactory: Send + Sync + 'static {
    /// Create a live [`CircuitSession`] for the given job.
    ///
    /// # Errors
    ///
    /// - [`CircuitError::StorageUnavailable`] — transient; the coordinator will keep the job and
    ///   retry on the next pass.
    /// - [`CircuitError::SetupFailed`] — permanent; the coordinator logs an error and drops the job
    ///   (programming bug).
    fn create_session<'a>(&'a self, job: &'a PendingCircuitJob) -> CreateSessionFuture<'a>;
}

/// Blanket impl: any executor that implements both garbler and evaluator
/// traits automatically implements [`SessionFactory`].
impl<D> SessionFactory for D
where
    D: ExecuteGarblerJob + ExecuteEvaluatorJob,
{
    fn create_session<'a>(&'a self, job: &'a PendingCircuitJob) -> CreateSessionFuture<'a> {
        Box::pin(async move {
            match &job.action {
                CircuitAction::GarblerCommitment { index, seed } => {
                    let session = <D as ExecuteGarblerJob>::begin_table_commitment(
                        self,
                        &job.peer_id,
                        *index,
                        *seed,
                    )
                    .await?;
                    Ok(Box::new(session) as Box<dyn CircuitSession>)
                }
                CircuitAction::GarblerTransfer { seed } => {
                    let session =
                        <D as ExecuteGarblerJob>::begin_table_transfer(self, &job.peer_id, *seed)
                            .await?;
                    Ok(Box::new(session) as Box<dyn CircuitSession>)
                }
                CircuitAction::EvaluatorCommitment { index, seed } => {
                    let session = <D as ExecuteEvaluatorJob>::begin_table_commitment(
                        self,
                        &job.peer_id,
                        *index,
                        *seed,
                    )
                    .await?;
                    Ok(Box::new(session) as Box<dyn CircuitSession>)
                }
                CircuitAction::EvaluatorEvaluation { index, commitment } => {
                    let session = <D as ExecuteEvaluatorJob>::begin_evaluation(
                        self,
                        &job.peer_id,
                        *index,
                        *commitment,
                    )
                    .await?;
                    Ok(Box::new(session) as Box<dyn CircuitSession>)
                }
            }
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Garbler executor
// ════════════════════════════════════════════════════════════════════════════

/// Executes garbler actions. Each action has its own method for type-safe
/// routing: pool actions return [`HandlerOutcome`], circuit actions return
/// a [`CircuitSession`].
///
/// The scheduler matches the garbler `Action` enum and calls the
/// corresponding method. Pool methods are submitted to worker threads.
/// Circuit methods are submitted to the garbling coordinator.
pub trait ExecuteGarblerJob: Send + Sync + 'static {
    /// Session type for coordinated circuit operations.
    type Session: CircuitSession + Send;

    // ── Pool actions (self-contained, run on worker pool threads) ────────

    /// Generate polynomial commitments for a single wire (G1).
    fn generate_polynomial_commitments(
        &self,
        peer_id: &PeerId,
        seed: Seed,
        wire: Wire,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Generate input/output shares at a circuit index (G2).
    fn generate_shares(
        &self,
        peer_id: &PeerId,
        seed: Seed,
        index: Index,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send commit message header to evaluator (G4).
    fn send_commit_msg_header(
        &self,
        peer_id: &PeerId,
        header: &CommitMsgHeader,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send commit message chunk to evaluator (G5).
    fn send_commit_msg_chunk(
        &self,
        peer_id: &PeerId,
        wire_idx: u16,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send challenge response header to evaluator (G6).
    fn send_challenge_response_header(
        &self,
        peer_id: &PeerId,
        header: &ChallengeResponseMsgHeader,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send challenge response chunk to evaluator (G7).
    fn send_challenge_response_chunk(
        &self,
        peer_id: &PeerId,
        index: &Index,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Verify adaptor signatures from evaluator (G9).
    fn deposit_verify_adaptors(
        &self,
        peer_id: &PeerId,
        deposit_id: DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Complete adaptor signatures for disputed withdrawal (G10).
    fn complete_adaptor_signatures(
        &self,
        peer_id: &PeerId,
        deposit_id: DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    // ── Circuit actions (return Session for coordinator to drive) ────────

    /// Begin a garbling session for table commitment (G3).
    ///
    /// The executor loads withdrawal shares and output share from storage,
    /// creates a `GarblingSession`, and returns a session that hashes
    /// ciphertext output for commitment computation.
    fn begin_table_commitment(
        &self,
        peer_id: &PeerId,
        index: Index,
        seed: GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;

    /// Begin a garbling session for table transfer (G8).
    ///
    /// Same as commitment but streams ciphertext to the peer via bulk
    /// transfer instead of hashing. The pre-computed commitment is looked
    /// up from storage.
    fn begin_table_transfer(
        &self,
        peer_id: &PeerId,
        seed: GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
}

// ════════════════════════════════════════════════════════════════════════════
// Evaluator executor
// ════════════════════════════════════════════════════════════════════════════

/// Executes evaluator actions. Each action has its own method for type-safe
/// routing: pool actions return [`HandlerOutcome`], circuit actions return
/// a [`CircuitSession`].
pub trait ExecuteEvaluatorJob: Send + Sync + 'static {
    /// Session type for coordinated circuit operations.
    type Session: CircuitSession + Send;

    // ── Pool actions ─────────────────────────────────────────────────────

    /// Send challenge message to garbler (E1).
    fn send_challenge_msg(
        &self,
        peer_id: &PeerId,
        msg: &ChallengeMsg,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Verify opened input shares against polynomial commitments (E2).
    fn verify_opened_input_shares(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send table transfer request to garbler (E9).
    fn send_table_transfer_request(
        &self,
        peer_id: &PeerId,
        msg: &TableTransferRequestMsg,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send table transfer receipt to garbler (E10).
    fn send_table_transfer_receipt(
        &self,
        peer_id: &PeerId,
        msg: &TableTransferReceiptMsg,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Generate adaptor signatures for deposit wires (E5).
    fn generate_deposit_adaptors(
        &self,
        peer_id: &PeerId,
        deposit_id: DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Generate adaptor signatures for a chunk of withdrawal wires (E6).
    fn generate_withdrawal_adaptors_chunk(
        &self,
        peer_id: &PeerId,
        deposit_id: DepositId,
        chunk_idx: &ChunkIndex,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Send adaptor message chunk to garbler (E7).
    fn deposit_send_adaptor_msg_chunk(
        &self,
        peer_id: &PeerId,
        deposit_id: DepositId,
        chunk: &AdaptorMsgChunk,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Receive a garbling table from the garbler (E4).
    ///
    /// Registers a bulk transfer expectation, receives the ciphertext stream,
    /// hashes and verifies against the expected commitment, and stores to
    /// the table store. This is a pool action (not a circuit session) because
    /// it does not need the shared circuit reader — data arrives from the
    /// network, not from garbling.
    fn receive_garbling_table(
        &self,
        peer_id: &PeerId,
        commitment: GarblingTableCommitment,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    // ── Circuit actions ──────────────────────────────────────────────────

    /// Begin a garbling session for table commitment verification (E3).
    ///
    /// Same algorithm as G3 — re-garbles from the revealed seed to verify
    /// the garbler's commitment for an opened circuit.
    fn begin_table_commitment(
        &self,
        peer_id: &PeerId,
        index: Index,
        seed: GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;

    /// Begin evaluating a stored garbling table (E8).
    ///
    /// The executor loads interpolated shares, translation material, and
    /// ciphertexts, then creates an evaluation session that the coordinator
    /// drives block-by-block through the circuit.
    fn begin_evaluation(
        &self,
        peer_id: &PeerId,
        index: Index,
        commitment: GarblingTableCommitment,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
}

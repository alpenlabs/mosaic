//! API types for the Mosaic job scheduler.
//!
//!
//! This crate defines the interface between the SM Scheduler, Job Scheduler,
//! and Job Executors. It provides:
//!
//! - [`ExecuteGarblerJob`] / [`ExecuteEvaluatorJob`] — per-action executor
//!   traits with separate methods for pool actions and circuit actions.
//! - [`CircuitSession`] — block-by-block session driven by the garbling
//!   coordinator for coordinated circuit operations.
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

mod handle;
mod submission;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mosaic_cac_types::{
    AdaptorMsgChunk, ChallengeMsg, ChallengeResponseMsgChunk, ChallengeResponseMsgHeader,
    CommitMsgChunk, CommitMsgHeader, DepositId, GarblingSeed, GarblingTableCommitment, Seed,
    state_machine::evaluator::ChunkIndex, state_machine::garbler::Wire,
};
use mosaic_net_svc_api::PeerId;
use mosaic_vs3::Index;

pub use handle::{JobSchedulerHandle, SchedulerStopped};
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
        chunk: &CommitMsgChunk,
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
        chunk: &ChallengeResponseMsgChunk,
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

    /// Begin receiving a garbling table from the garbler (E4).
    ///
    /// Registers a bulk transfer expectation, receives ciphertext stream,
    /// hashes and verifies against the expected commitment, and stores
    /// to the table store.
    fn begin_table_receive(
        &self,
        peer_id: &PeerId,
        commitment: GarblingTableCommitment,
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

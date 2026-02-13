//! Handlers for evaluator state machine actions.
//!
//! Each handler executes a single evaluator action and returns a [`JobResult`]
//! containing an [`ActionCompletion`] with the tracked action ID and result.

use mosaic_cac_types::state_machine::evaluator::Action;
use mosaic_common::PeerId;
use mosaic_job_api::{JobError, JobResult};

use super::HandlerContext;

/// Dispatch an evaluator action to the appropriate handler.
pub(crate) async fn execute(ctx: &HandlerContext, peer_id: &PeerId, action: Action) -> JobResult {
    match action {
        // ── Light (Network I/O) ─────────────────────────────────────
        Action::SendChallengeMsg(msg) => send_challenge_msg(ctx, peer_id, msg).await,

        // ── Heavy (Setup) ───────────────────────────────────────────
        Action::VerifyOpenedInputShares(challenge_indices, shares, commitments) => {
            verify_opened_input_shares(ctx, challenge_indices, shares, commitments).await
        }

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, index, seed).await
        }
        Action::ReceiveGarblingTables(commitments) => {
            receive_garbling_tables(ctx, peer_id, commitments).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::DepositGenerateAdaptors(deposit_id) => generate_adaptors(ctx, deposit_id).await,

        // ── Light (Deposit Network I/O) ─────────────────────────────
        Action::DepositSendAdaptorMsgChunk(deposit_id, chunk) => {
            send_adaptor_msg_chunk(ctx, peer_id, deposit_id, chunk).await
        }

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::EvaluateGarblingTable(index, commitment) => {
            evaluate_garbling_table(ctx, index, commitment).await
        }

        _ => {
            // Non-exhaustive enum — future variants handled here until
            // explicit handlers are added.
            JobResult::Failed(JobError::Crypto(
                "unhandled evaluator action variant".into(),
            ))
        }
    }
}

// ============================================================================
// Light handlers (Network I/O)
// ============================================================================

async fn send_challenge_msg(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _msg: mosaic_cac_types::ChallengeMsg,
) -> JobResult {
    // TODO: ctx.net_client.send(peer_id, msg).await
    // Returns: EvaluatorInput::ChallengeMsgAcked
    unimplemented!()
}

async fn send_adaptor_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _deposit_id: mosaic_cac_types::DepositId,
    _chunk: mosaic_cac_types::AdaptorMsgChunk,
) -> JobResult {
    // TODO: ctx.net_client.send(peer_id, chunk).await
    // Returns: EvaluatorInput::DepositAdaptorMsgAcked(deposit_id)
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Setup)
// ============================================================================

async fn verify_opened_input_shares(
    _ctx: &HandlerContext,
    _challenge_indices: Box<mosaic_cac_types::ChallengeIndices>,
    _shares: Box<mosaic_cac_types::OpenedInputShares>,
    _commitments: Box<mosaic_cac_types::InputPolynomialCommitments>,
) -> JobResult {
    // TODO: verify opened shares against polynomial commitments for each
    //       challenged circuit
    // Returns: EvaluatorInput::VerifyOpenedInputSharesResult(Option<String>)
    //          None = success, Some(reason) = failure
    unimplemented!()
}

// ============================================================================
// Garbling handlers (routed through GarblingCoordinator)
// ============================================================================

async fn generate_table_commitment(
    _ctx: &HandlerContext,
    _index: mosaic_cac_types::Index,
    _seed: mosaic_cac_types::GarblingSeed,
) -> JobResult {
    // TODO: generate garbling table from seed and shares, compute commitment
    // NOTE: this action is routed through the GarblingCoordinator, not the
    //       heavy pool directly. The coordinator handles topology reading.
    // Returns: EvaluatorInput::TableCommitmentGenerated(index, commitment)
    unimplemented!()
}

async fn receive_garbling_tables(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _commitments: mosaic_cac_types::EvalGarblingTableCommitments,
) -> JobResult {
    // TODO: register bulk transfer expectations with net-svc for each
    //       unchallenged circuit. Wait for all tables to arrive. Verify
    //       each table's hash matches the expected commitment.
    // Returns: EvaluatorInput::GarblingTableReceived(index, commitment)
    //          for each table as it arrives
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn generate_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
) -> JobResult {
    // TODO: generate adaptor signatures for deposit and withdrawal input wires
    //       using evaluator's secret key and input share commitments
    // Returns: EvaluatorInput::DepositAdaptorsGenerated(deposit_id, deposit, withdrawal)
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn evaluate_garbling_table(
    _ctx: &HandlerContext,
    _index: mosaic_cac_types::Index,
    _commitment: mosaic_cac_types::GarblingTableCommitment,
) -> JobResult {
    // TODO: evaluate a single garbling table with interpolated input labels
    //       to produce an output share. If the output polynomial evaluates to
    //       the committed secret, the fault secret has been found.
    // Returns: EvaluatorInput::TableEvaluationResult(commitment, Option<output_share>)
    unimplemented!()
}

//! Handlers for evaluator state machine actions.
//!
//! Each handler executes a single evaluator action and produces an
//! [`ActionCompletion`]. Handlers retry internally until they succeed —
//! the caller always receives a valid completion.

use mosaic_cac_types::state_machine::evaluator::Action;
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;

use super::HandlerContext;

/// Dispatch an evaluator action to the appropriate handler.
pub(crate) async fn execute(
    ctx: &HandlerContext,
    peer_id: &PeerId,
    action: Action,
) -> ActionCompletion {
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
            // Non-exhaustive enum — future variants will panic until
            // explicit handlers are added.
            unimplemented!("unhandled evaluator action variant")
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
) -> ActionCompletion {
    // TODO: ctx.net_client.send(peer_id, msg).await in retry loop
    unimplemented!()
}

async fn send_adaptor_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _deposit_id: mosaic_cac_types::DepositId,
    _chunk: mosaic_cac_types::AdaptorMsgChunk,
) -> ActionCompletion {
    // TODO: ctx.net_client.send(peer_id, chunk).await in retry loop
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
) -> ActionCompletion {
    // TODO: verify opened shares against polynomial commitments for each
    //       challenged circuit
    unimplemented!()
}

// ============================================================================
// Garbling handlers (routed through GarblingCoordinator)
// ============================================================================

async fn generate_table_commitment(
    _ctx: &HandlerContext,
    _index: mosaic_cac_types::Index,
    _seed: mosaic_cac_types::GarblingSeed,
) -> ActionCompletion {
    // TODO: generate garbling table from seed and shares, compute commitment
    // NOTE: this action is routed through the GarblingCoordinator, not the
    //       heavy pool directly. The coordinator handles topology reading.
    unimplemented!()
}

async fn receive_garbling_tables(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _commitments: mosaic_cac_types::EvalGarblingTableCommitments,
) -> ActionCompletion {
    // TODO: register bulk transfer expectations with net-svc for each
    //       unchallenged circuit. Wait for all tables to arrive. Verify
    //       each table's hash matches the expected commitment.
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn generate_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
) -> ActionCompletion {
    // TODO: generate adaptor signatures for deposit and withdrawal input wires
    //       using evaluator's secret key and input share commitments
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn evaluate_garbling_table(
    _ctx: &HandlerContext,
    _index: mosaic_cac_types::Index,
    _commitment: mosaic_cac_types::GarblingTableCommitment,
) -> ActionCompletion {
    // TODO: evaluate a single garbling table with interpolated input labels
    //       to produce an output share. If the output polynomial evaluates to
    //       the committed secret, the fault secret has been found.
    unimplemented!()
}

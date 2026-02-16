//! Handlers for garbler state machine actions.
//!
//! Each handler executes a single garbler action and produces an
//! [`ActionCompletion`]. Handlers retry internally until they succeed —
//! the caller always receives a valid completion.

use mosaic_cac_types::state_machine::garbler::Action;
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;

use super::HandlerContext;

/// Dispatch a garbler action to the appropriate handler.
pub(crate) async fn execute(
    ctx: &HandlerContext,
    peer_id: &PeerId,
    action: Action,
) -> ActionCompletion {
    match action {
        // ── Heavy (Setup) ───────────────────────────────────────────
        Action::GeneratePolynomialCommitments => generate_polynomial_commitments(ctx).await,
        Action::GenerateShares(index) => generate_shares(ctx, index).await,

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, index, seed).await
        }
        Action::TransferGarblingTable(seed) => transfer_garbling_table(ctx, peer_id, seed).await,

        // ── Light (Network I/O) ─────────────────────────────────────
        Action::SendCommitMsgChunk(chunk) => send_commit_msg_chunk(ctx, peer_id, chunk).await,
        Action::SendChallengeResponseMsgChunk(chunk) => {
            send_challenge_response_msg_chunk(ctx, peer_id, chunk).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::DepositVerifyAdaptors(deposit_id, data) => {
            verify_adaptors(ctx, deposit_id, data).await
        }

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::CompleteAdaptorSignatures(deposit_id, data) => {
            complete_adaptor_signatures(ctx, deposit_id, data).await
        }

        _ => {
            // Non-exhaustive enum — future variants will panic until
            // explicit handlers are added.
            unimplemented!("unhandled garbler action variant")
        }
    }
}

// ============================================================================
// Heavy handlers (Setup)
// ============================================================================

async fn generate_polynomial_commitments(_ctx: &HandlerContext) -> ActionCompletion {
    // TODO: generate polynomials from base seed, compute commitments
    unimplemented!()
}

async fn generate_shares(
    _ctx: &HandlerContext,
    _index: mosaic_cac_types::Index,
) -> ActionCompletion {
    // TODO: evaluate polynomials at index to produce input/output shares
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

async fn transfer_garbling_table(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _seed: mosaic_cac_types::GarblingSeed,
) -> ActionCompletion {
    // TODO: generate garbling table from seed and stream 43GB to peer
    // NOTE: routed through GarblingCoordinator for coordinated topology reads.
    //       Output is streamed via net-client bulk transfer.
    unimplemented!()
}

// ============================================================================
// Light handlers (Network I/O)
// ============================================================================

async fn send_commit_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _chunk: mosaic_cac_types::CommitMsgChunk,
) -> ActionCompletion {
    // TODO: ctx.net_client.send(peer_id, chunk).await in retry loop
    unimplemented!()
}

async fn send_challenge_response_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _chunk: mosaic_cac_types::ChallengeResponseMsgChunk,
) -> ActionCompletion {
    // TODO: ctx.net_client.send(peer_id, chunk).await in retry loop
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn verify_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
    _data: mosaic_cac_types::state_machine::garbler::AdaptorVerificationData,
) -> ActionCompletion {
    // TODO: verify adaptor signatures against commitments and sighashes
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn complete_adaptor_signatures(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
    _data: mosaic_cac_types::state_machine::garbler::CompleteAdaptorSignaturesData,
) -> ActionCompletion {
    // TODO: complete adaptor signatures for disputed withdrawal
    unimplemented!()
}

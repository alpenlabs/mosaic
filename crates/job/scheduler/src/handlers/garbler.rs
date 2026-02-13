//! Handlers for garbler state machine actions.
//!
//! Each handler executes a single garbler action and returns a [`JobResult`]
//! containing an [`ActionCompletion`] with the tracked action ID and result.

use mosaic_cac_types::state_machine::garbler::Action;
use mosaic_common::PeerId;
use mosaic_job_api::{JobError, JobResult};

use super::HandlerContext;

/// Dispatch a garbler action to the appropriate handler.
pub(crate) async fn execute(ctx: &HandlerContext, peer_id: &PeerId, action: Action) -> JobResult {
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

        // ── Light (Deposit Network I/O) ─────────────────────────────

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::DepositVerifyAdaptors(deposit_id, data) => {
            verify_adaptors(ctx, deposit_id, data).await
        }

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::CompleteAdaptorSignatures(deposit_id, data) => {
            complete_adaptor_signatures(ctx, deposit_id, data).await
        }

        _ => {
            // Non-exhaustive enum — future variants handled here until
            // explicit handlers are added.
            JobResult::Failed(JobError::Crypto("unhandled garbler action variant".into()))
        }
    }
}

// ============================================================================
// Heavy handlers (Setup)
// ============================================================================

async fn generate_polynomial_commitments(_ctx: &HandlerContext) -> JobResult {
    // TODO: generate polynomials from base seed, compute commitments
    // Returns: GarblerInput::PolynomialCommitmentsGenerated(commitments)
    unimplemented!()
}

async fn generate_shares(_ctx: &HandlerContext, _index: mosaic_cac_types::Index) -> JobResult {
    // TODO: evaluate polynomials at index to produce input/output shares
    // Returns: GarblerInput::SharesGenerated(index, input_shares, output_share)
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
    // Returns: GarblerInput::TableCommitmentGenerated(index, commitment)
    unimplemented!()
}

async fn transfer_garbling_table(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _seed: mosaic_cac_types::GarblingSeed,
) -> JobResult {
    // TODO: generate garbling table from seed and stream 43GB to peer
    // NOTE: routed through GarblingCoordinator for coordinated topology reads.
    //       Output is streamed via net-client bulk transfer.
    // Returns: GarblerInput::GarblingTableTransferred(seed, commitment)
    unimplemented!()
}

// ============================================================================
// Light handlers (Network I/O)
// ============================================================================

async fn send_commit_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _chunk: mosaic_cac_types::CommitMsgChunk,
) -> JobResult {
    // TODO: ctx.net_client.send(peer_id, chunk).await
    // Returns: GarblerInput::CommitMsgAcked
    unimplemented!()
}

async fn send_challenge_response_msg_chunk(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _chunk: mosaic_cac_types::ChallengeResponseMsgChunk,
) -> JobResult {
    // TODO: ctx.net_client.send(peer_id, chunk).await
    // Returns: GarblerInput::ChallengeResponseAcked
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn verify_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
    _data: mosaic_cac_types::state_machine::garbler::AdaptorVerificationData,
) -> JobResult {
    // TODO: verify adaptor signatures against commitments and sighashes
    // Returns: GarblerInput::DepositAdaptorVerificationResult(deposit_id, bool)
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn complete_adaptor_signatures(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
    _data: mosaic_cac_types::state_machine::garbler::CompleteAdaptorSignaturesData,
) -> JobResult {
    // TODO: complete adaptor signatures for disputed withdrawal
    // Returns: GarblerInput::AdaptorSignaturesCompleted(deposit_id, signatures)
    unimplemented!()
}

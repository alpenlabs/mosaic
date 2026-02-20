//! Handlers for evaluator state machine actions.
//!
//! Each handler executes a single evaluator action and produces an
//! [`ActionCompletion`]. Handlers retry internally until they succeed —
//! the caller always receives a valid completion.

use mosaic_cac_types::{
    GarblingTableCommitment,
    state_machine::evaluator::{Action, ActionId, ActionResult, ChunkIndex},
};
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;

use super::HandlerContext;

/// Build a successful evaluator completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> ActionCompletion {
    ActionCompletion::Evaluator { id, result }
}

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
        Action::VerifyOpenedInputShares => verify_opened_input_shares(ctx).await,

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, index, seed).await
        }
        Action::ReceiveGarblingTable(commitment) => {
            receive_garbling_table(ctx, peer_id, commitment).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::GenerateDepositAdaptors(deposit_id) => {
            generate_deposit_adaptors(ctx, deposit_id).await
        }
        Action::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx) => {
            generate_withdrawal_adaptors(ctx, deposit_id, chunk_idx).await
        }

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
    ctx: &HandlerContext,
    peer_id: &PeerId,
    msg: mosaic_cac_types::ChallengeMsg,
) -> ActionCompletion {
    loop {
        match ctx.net_client.send(*peer_id, msg.clone()).await {
            Ok(_ack) => {
                return completed(ActionId::SendChallengeMsg, ActionResult::ChallengeMsgAcked);
            }
            Err(e) => {
                tracing::warn!(%e, "send challenge msg failed, retrying")
            }
        }
    }
}

async fn send_adaptor_msg_chunk(
    ctx: &HandlerContext,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
    chunk: mosaic_cac_types::AdaptorMsgChunk,
) -> ActionCompletion {
    let id = ActionId::DepositSendAdaptorMsgChunk(deposit_id, chunk.chunk_index);
    loop {
        match ctx.net_client.send(*peer_id, chunk.clone()).await {
            Ok(_ack) => return completed(id, ActionResult::DepositAdaptorChunkSent(deposit_id)),
            Err(e) => {
                tracing::warn!(chunk_index = chunk.chunk_index, %e, "send adaptor chunk failed, retrying")
            }
        }
    }
}

// ============================================================================
// Heavy handlers (Setup)
// ============================================================================

async fn verify_opened_input_shares(
    _ctx: &HandlerContext,
    // challenge_indices: Box<mosaic_cac_types::ChallengeIndices>,
    // shares: Box<mosaic_cac_types::OpenedInputShares>,
    // commitments: Box<mosaic_cac_types::InputPolynomialCommitments>,
) -> ActionCompletion {
    unimplemented!()
    // FIXME(sapinb): load data from storage
    // Verify each opened share against its polynomial commitment.
    // Any failure aborts with a reason; success returns None.
    // let failure_reason = (|| {
    //     for idx in 0..N_OPEN_CIRCUITS {
    //         for wire in 0..N_INPUT_WIRES {
    //             for val in 0..WIDE_LABEL_VALUE_COUNT {
    //                 let share = shares[idx][wire][val].clone();
    //                 if commitments[wire][val].verify_share(share).is_err() {
    //                     return Some(format!(
    //                         "verify failed for circuit {}, wire {}, value {}",
    //                         challenge_indices[idx].get(),
    //                         wire,
    //                         val
    //                     ));
    //                 }
    //             }
    //         }
    //     }
    //     None
    // })();

    // completed(
    //     ActionId::VerifyOpenedInputShares,
    //     ActionResult::VerifyOpenedInputSharesResult(failure_reason),
    // )
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

async fn receive_garbling_table(
    _ctx: &HandlerContext,
    _peer_id: &PeerId,
    _commitment: GarblingTableCommitment,
) -> ActionCompletion {
    // TODO: register bulk transfer expectations with net-svc for each
    //       unchallenged circuit. Wait for all tables to arrive. Verify
    //       each table's hash matches the expected commitment.
    unimplemented!()
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn generate_deposit_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
) -> ActionCompletion {
    // TODO: generate adaptor signatures for deposit and withdrawal input wires
    //       using evaluator's secret key and input share commitments
    unimplemented!()
}

async fn generate_withdrawal_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
    _chunk_idx: ChunkIndex,
) -> ActionCompletion {
    // TODO: generate adaptor signatures for withdrawal input wires
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

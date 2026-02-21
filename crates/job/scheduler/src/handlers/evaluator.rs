//! Handlers for evaluator state machine actions.
//!
//! Each handler executes a single evaluator action and returns a
//! [`HandlerOutcome`]. On success, [`HandlerOutcome::Done`] carries the
//! [`ActionCompletion`] back to the SM. On transient failure (network
//! timeout, cache full, storage unavailable), [`HandlerOutcome::Retry`]
//! causes the worker to requeue the job so other peers can progress.

use mosaic_cac_types::state_machine::evaluator::{Action, ActionId, ActionResult, ChunkIndex};
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;

use super::{HandlerContext, HandlerOutcome};

/// Build a successful evaluator completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Evaluator { id, result })
}

/// Dispatch an evaluator action to the appropriate handler.
pub(crate) async fn execute<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    action: &Action,
) -> HandlerOutcome {
    match action {
        // ── Light (Network I/O) ─────────────────────────────────────
        Action::SendChallengeMsg(msg) => send_challenge_msg(ctx, peer_id, msg).await,

        // ── Heavy (Setup) ───────────────────────────────────────────
        Action::VerifyOpenedInputShares => verify_opened_input_shares(ctx).await,

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, *index, *seed).await
        }
        Action::ReceiveGarblingTable(commitment) => {
            receive_garbling_table(ctx, peer_id, *commitment).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::GenerateDepositAdaptors(deposit_id) => {
            generate_deposit_adaptors(ctx, *deposit_id).await
        }
        Action::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx) => {
            generate_withdrawal_adaptors_chunk(ctx, *deposit_id, chunk_idx).await
        }

        // ── Light (Deposit Network I/O) ─────────────────────────────
        Action::DepositSendAdaptorMsgChunk(deposit_id, chunk) => {
            send_adaptor_msg_chunk(ctx, peer_id, *deposit_id, chunk).await
        }

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::EvaluateGarblingTable(index, commitment) => {
            evaluate_garbling_table(ctx, *index, *commitment).await
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

async fn send_challenge_msg<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    msg: &mosaic_cac_types::ChallengeMsg,
) -> HandlerOutcome {
    match ctx.net_client.send(*peer_id, msg.clone()).await {
        Ok(_ack) => completed(ActionId::SendChallengeMsg, ActionResult::ChallengeMsgAcked),
        Err(e) => {
            tracing::warn!(%e, "send challenge msg failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

async fn send_adaptor_msg_chunk<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
    chunk: &mosaic_cac_types::AdaptorMsgChunk,
) -> HandlerOutcome {
    let id = ActionId::DepositSendAdaptorMsgChunk(deposit_id, chunk.chunk_index);
    match ctx.net_client.send(*peer_id, chunk.clone()).await {
        Ok(_ack) => completed(id, ActionResult::DepositAdaptorChunkSent(deposit_id)),
        Err(e) => {
            tracing::warn!(%e, "send adaptor chunk failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

// ============================================================================
// Heavy handlers (Setup)
// ============================================================================

async fn verify_opened_input_shares<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
) -> HandlerOutcome {
    // TODO(phase2): Load data from StateRead, run verification loop.
    //
    // Flow:
    //   1. Load challenge_indices, opened_input_shares, input_polynomial_commitments
    //      from storage via StateRead
    //   2. For each opened circuit × wire × value:
    //      commitments[wire][val].verify_share(shares[idx][wire][val])
    //   3. Return VerifyOpenedInputSharesResult(None) on success,
    //      or VerifyOpenedInputSharesResult(Some(reason)) on failure
    //   4. Return Retry if storage reads return None (data not ready)
    //
    // Reference: PR #68 setup_evaluator.rs exec_verify() step 1
    unimplemented!("verify_opened_input_shares: blocked on StateRead wiring")
}

// ============================================================================
// Garbling handlers (routed through GarblingCoordinator)
// ============================================================================

async fn generate_table_commitment<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _index: mosaic_vs3::Index,
    _seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    // TODO(phase5): Factor out garble_commit() from PR #68 setup_garbler.rs.
    //
    // Flow (same algorithm as garbler side):
    //   1. Load withdrawal wire shares + output share for circuit index from storage
    //   2. Truncate shares to 16-byte labels
    //   3. Derive delta + bit labels from garbling seed via ChaCha20
    //   4. Generate input/output translation material
    //   5. Run ckt-runner-exec::GarbleTask → writes gc_{index}.bin
    //   6. Hash: blake3(hash(ciphertext) || hash(translation) || output_label_ct)
    //   7. Return TableCommitmentGenerated(index, commitment)
    //   8. Return Retry if storage reads fail
    //
    // Reference: PR #68 setup_garbler.rs garble_commit()
    unimplemented!("generate_table_commitment: blocked on ckt integration")
}

async fn receive_garbling_table<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _peer_id: &PeerId,
    _commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    // TODO(phase5): Receive garbling table from peer via net-svc bulk transfer.
    //
    // Flow:
    //   1. Register bulk transfer expectation with net-svc
    //   2. Wait for table data from peer
    //   3. Hash received data with blake3
    //   4. Verify hash matches expected commitment
    //   5. Return GarblingTableReceived(index, commitment)
    //   6. Return Retry if peer hasn't sent yet or transfer fails
    //
    // Reference: PR #68 setup_evaluator.rs exec_verify() step 3b
    unimplemented!("receive_garbling_table: blocked on ckt integration + net-svc bulk")
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn generate_deposit_adaptors<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    // TODO(phase4): Load from StateRead, generate deposit wire adaptors.
    //
    // Flow:
    //   1. Load sighashes, deposit_inputs, evaluator sk/pk, reserved input
    //      share commitments (computed from polynomial commitments at index 0)
    //   2. For each deposit wire:
    //      Adaptor::generate(rng, share_commitment, sk, pk, sighash)
    //   3. Return DepositAdaptorsGenerated(deposit_id, DepositAdaptors)
    //   4. Return Retry if storage reads fail
    //
    // Reference: PR #68 deposit_evaluator.rs exec_generate_adaptors() (deposit section)
    unimplemented!("generate_deposit_adaptors: blocked on StateRead wiring")
}

async fn generate_withdrawal_adaptors_chunk<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _deposit_id: mosaic_cac_types::DepositId,
    _chunk_idx: &ChunkIndex,
) -> HandlerOutcome {
    // TODO(phase4): Load from StateRead, generate withdrawal wire adaptors for one chunk.
    //
    // Flow:
    //   1. Load sighashes, evaluator sk/pk, reserved input share commitments
    //   2. Determine which WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK wires this chunk covers
    //   3. For each wire in chunk, for each of 256 values:
    //      Adaptor::generate(rng, share_commitment, sk, pk, sighash)
    //   4. Return WithdrawalAdaptorsChunkGenerated(deposit_id, chunk_idx, chunk)
    //   5. Return Retry if storage reads fail
    //
    // Reference: PR #68 deposit_evaluator.rs exec_generate_adaptors() (withdrawal section)
    unimplemented!("generate_withdrawal_adaptors_chunk: blocked on StateRead wiring")
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn evaluate_garbling_table<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _index: mosaic_vs3::Index,
    _commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    // TODO(phase5): Factor out evaluate_gc_table() from PR #68 deposit_evaluator.rs.
    //
    // Flow:
    //   1. Load shares for this circuit via interpolation of opened + committed shares
    //   2. Truncate to 16-byte labels
    //   3. Read translation material from file
    //   4. Translate byte labels → bit labels
    //   5. Run ckt-runner-exec::EvalTask
    //   6. Translate output label → output share scalar
    //   7. Return TableEvaluationResult(commitment, Option<CircuitOutputShare>)
    //   8. Return Retry if storage reads or file I/O fails
    //
    // Reference: PR #68 deposit_evaluator.rs evaluate_gc_table()
    unimplemented!("evaluate_garbling_table: blocked on ckt integration")
}

//! Handlers for evaluator state machine actions.
//!
//! Each handler executes a single evaluator action and returns a
//! [`HandlerOutcome`]. On success, [`HandlerOutcome::Done`] carries the
//! [`ActionCompletion`] back to the SM. On transient failure (network
//! timeout, cache full, storage unavailable), [`HandlerOutcome::Retry`]
//! causes the worker to requeue the job so other peers can progress.

use mosaic_cac_types::{
    Adaptor, DepositAdaptors,
    state_machine::evaluator::{Action, ActionId, ActionResult, ChunkIndex, StateRead as _},
};
use mosaic_common::constants::{
    N_DEPOSIT_INPUT_WIRES, N_SETUP_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
    WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_heap_array::HeapArray;
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
        Action::VerifyOpenedInputShares => verify_opened_input_shares(ctx, peer_id).await,

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, *index, *seed).await
        }
        Action::ReceiveGarblingTable(commitment) => {
            receive_garbling_table(ctx, peer_id, *commitment).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::GenerateDepositAdaptors(deposit_id) => {
            generate_deposit_adaptors(ctx, peer_id, *deposit_id).await
        }
        Action::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx) => {
            generate_withdrawal_adaptors_chunk(ctx, peer_id, *deposit_id, chunk_idx).await
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
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
) -> HandlerOutcome {
    use mosaic_common::constants::{N_INPUT_WIRES, N_OPEN_CIRCUITS, WIDE_LABEL_VALUE_COUNT};

    let eval_state = ctx.storage.evaluator_state(peer_id);

    // Load all three data sets from storage. Retry if any are not yet available.
    let Some(challenge_indices) = eval_state.get_challenge_indices().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(shares) = eval_state.get_opened_input_shares().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(commitments) = eval_state
        .get_input_polynomial_commitments()
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    // Verify each opened share against its polynomial commitment.
    // Any failure produces a reason string; success returns None.
    let failure_reason = (|| {
        for idx in 0..N_OPEN_CIRCUITS {
            for wire in 0..N_INPUT_WIRES {
                for val in 0..WIDE_LABEL_VALUE_COUNT {
                    let share = shares[idx][wire][val].clone();
                    if commitments[wire][val].verify_share(share).is_err() {
                        return Some(format!(
                            "verify failed for circuit {}, wire {}, value {}",
                            challenge_indices[idx].get(),
                            wire,
                            val,
                        ));
                    }
                }
            }
        }
        None
    })();

    completed(
        ActionId::VerifyOpenedInputShares,
        ActionResult::VerifyOpenedInputSharesResult(failure_reason),
    )
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
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    let eval_state = ctx.storage.evaluator_state(peer_id);

    // Load required data. Retry if any reads return None (data not yet written by STF).
    let Some(deposit_state) = eval_state.get_deposit(&deposit_id).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(sighashes) = eval_state
        .get_deposit_sighashes(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(deposit_inputs) = eval_state
        .get_deposit_inputs(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(input_poly_commits) = eval_state
        .get_input_polynomial_commitments()
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    let sk = deposit_state.sk.0;
    let pk = deposit_state.sk.to_pubkey().0;
    let mut rng = rand::thread_rng();

    // Generate one adaptor per deposit wire, using the share commitment at
    // reserved index (= zeroth polynomial coefficient) for the wire's input value.
    let mut adaptors = Vec::with_capacity(N_DEPOSIT_INPUT_WIRES);
    for i in 0..N_DEPOSIT_INPUT_WIRES {
        let wire = N_SETUP_INPUT_WIRES + i;
        let val = deposit_inputs[i] as usize;
        // Zeroth coefficient of commitment polynomial = commitment to share at index 0
        let share_commitment = input_poly_commits[wire][val].get_zeroth_coefficient();
        let adaptor =
            Adaptor::generate(&mut rng, share_commitment, sk, pk, sighashes[i].0.as_ref())
                .expect("adaptor generation should not fail with valid inputs");
        adaptors.push(adaptor);
    }

    let deposit_adaptors: DepositAdaptors = HeapArray::from_vec(adaptors);
    completed(
        ActionId::GenerateDepositAdaptors(deposit_id),
        ActionResult::DepositAdaptorsGenerated(deposit_id, deposit_adaptors),
    )
}

async fn generate_withdrawal_adaptors_chunk<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
    chunk_idx: &ChunkIndex,
) -> HandlerOutcome {
    let eval_state = ctx.storage.evaluator_state(peer_id);

    // Load required data. Retry if any reads return None.
    let Some(deposit_state) = eval_state.get_deposit(&deposit_id).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(sighashes) = eval_state
        .get_deposit_sighashes(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(input_poly_commits) = eval_state
        .get_input_polynomial_commitments()
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    let sk = deposit_state.sk.0;
    let pk = deposit_state.sk.to_pubkey().0;
    let mut rng = rand::thread_rng();

    // Each chunk covers WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK consecutive withdrawal wires.
    let chunk_offset = chunk_idx.get() as usize * WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK;

    let mut wires = Vec::with_capacity(WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK);
    for wire_in_chunk in 0..WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK {
        let withdrawal_wire = chunk_offset + wire_in_chunk;
        let wire = N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES + withdrawal_wire;
        let sighash_idx = N_DEPOSIT_INPUT_WIRES + withdrawal_wire;

        let mut wire_adaptors = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
        for val in 0..WIDE_LABEL_VALUE_COUNT {
            // Zeroth coefficient = commitment to share at reserved index
            let share_commitment = input_poly_commits[wire][val].get_zeroth_coefficient();
            let adaptor = Adaptor::generate(
                &mut rng,
                share_commitment,
                sk,
                pk,
                sighashes[sighash_idx].0.as_ref(),
            )
            .expect("adaptor generation should not fail with valid inputs");
            wire_adaptors.push(adaptor);
        }
        wires.push(HeapArray::from_vec(wire_adaptors));
    }

    let chunk = HeapArray::from_vec(wires);
    completed(
        ActionId::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx.get()),
        ActionResult::WithdrawalAdaptorsChunkGenerated(
            deposit_id,
            ChunkIndex(chunk_idx.get()),
            chunk,
        ),
    )
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

//! Handlers for garbler state machine actions.
//!
//! Each handler executes a single garbler action and returns a
//! [`HandlerOutcome`]. On success, [`HandlerOutcome::Done`] carries the
//! [`ActionCompletion`] back to the SM. On transient failure (network
//! timeout, cache full, storage unavailable), [`HandlerOutcome::Retry`]
//! causes the worker to requeue the job so other peers can progress.

use mosaic_cac_types::{
    AllPolynomials, CompletedSignatures, InputPolynomials, OutputPolynomial, Seed,
    WideLabelWireShares,
    state_machine::garbler::{
        Action, ActionId, ActionResult, GeneratedPolynomialCommitments, StateRead as _, Wire,
    },
};
use mosaic_common::constants::{
    N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES,
    WIDE_LABEL_VALUE_COUNT,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use super::{HandlerContext, HandlerOutcome};

/// Build a successful garbler completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Garbler { id, result })
}

/// Dispatch a garbler action to the appropriate handler.
pub(crate) async fn execute<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    action: &Action,
) -> HandlerOutcome {
    match action {
        // ── Heavy (Setup) ───────────────────────────────────────────
        Action::GeneratePolynomialCommitments(seed, wire) => {
            generate_polynomial_commitments(ctx, *seed, *wire).await
        }
        Action::GenerateShares(seed, index) => generate_shares(ctx, *seed, *index).await,

        // ── Garbling (Coordinator) ──────────────────────────────────
        Action::GenerateTableCommitment(index, seed) => {
            generate_table_commitment(ctx, *index, *seed).await
        }
        Action::TransferGarblingTable(seed) => transfer_garbling_table(ctx, peer_id, *seed).await,

        // ── Light (Network I/O) ─────────────────────────────────────
        Action::SendCommitMsgHeader(header) => send_commit_msg_header(ctx, peer_id, header).await,
        Action::SendCommitMsgChunk(chunk) => send_commit_msg_chunk(ctx, peer_id, chunk).await,
        Action::SendChallengeResponseMsgHeader(header) => {
            send_challenge_response_msg_header(ctx, peer_id, header).await
        }
        Action::SendChallengeResponseMsgChunk(chunk) => {
            send_challenge_response_msg_chunk(ctx, peer_id, chunk).await
        }

        // ── Heavy (Deposit) ─────────────────────────────────────────
        Action::DepositVerifyAdaptors(deposit_id) => {
            verify_adaptors(ctx, peer_id, *deposit_id).await
        }

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::CompleteAdaptorSignatures(deposit_id) => {
            complete_adaptor_signatures(ctx, peer_id, *deposit_id).await
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

async fn generate_polynomial_commitments<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    seed: Seed,
    wire: Wire,
) -> HandlerOutcome {
    use crate::polynomial_cache::CacheResult;

    let polys = match ctx.polynomial_cache.get(&seed) {
        CacheResult::Hit(arc) => arc,
        CacheResult::Unavailable => return HandlerOutcome::Retry,
        CacheResult::Generate(guard) => {
            let generated = generate_polynomials_from_seed(seed);
            guard.complete(generated)
        }
    };

    let result = commit_for_wire(&polys, wire);
    ctx.polynomial_cache.mark_completed(&seed);
    let id = ActionId::GeneratePolynomialCommitments(seed, wire);
    completed(id, ActionResult::PolynomialCommitmentsGenerated(result))
}

async fn generate_shares<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    seed: Seed,
    index: Index,
) -> HandlerOutcome {
    use crate::polynomial_cache::CacheResult;

    let polys = match ctx.polynomial_cache.get(&seed) {
        CacheResult::Hit(arc) => arc,
        CacheResult::Unavailable => return HandlerOutcome::Retry,
        CacheResult::Generate(guard) => {
            let generated = generate_polynomials_from_seed(seed);
            guard.complete(generated)
        }
    };

    let (input_shares, output_share) = evaluate_polynomials_at_index(&polys, index);
    ctx.polynomial_cache.mark_completed(&seed);
    let id = ActionId::GenerateShares(seed, index);
    completed(
        id,
        ActionResult::SharesGenerated(index, input_shares, output_share),
    )
}

// ============================================================================
// Polynomial helpers
// ============================================================================

/// Generate all polynomials deterministically from a seed.
fn generate_polynomials_from_seed(seed: Seed) -> AllPolynomials {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.into());
    let input_polys: InputPolynomials =
        HeapArray::new(|_| HeapArray::new(|_| Polynomial::rand(&mut rng)));
    let output_poly: OutputPolynomial = Polynomial::rand(&mut rng);
    (input_polys, output_poly)
}

/// Compute polynomial commitments for a single wire.
///
/// For [`Wire::Input(idx)`]: commits all 256 polynomials for that input wire
/// (~270ms of EC scalar multiplications per wire).
///
/// For [`Wire::Output`]: commits the single output polynomial (~1.5ms).
fn commit_for_wire(polys: &AllPolynomials, wire: Wire) -> GeneratedPolynomialCommitments {
    let (input_polys, output_poly) = polys;
    match wire {
        Wire::Input(idx) => {
            let commits: Vec<PolynomialCommitment> = input_polys[idx as usize]
                .iter()
                .map(|p| p.commit())
                .collect();
            GeneratedPolynomialCommitments::Input {
                wire: idx,
                commitments: HeapArray::from_vec(commits),
            }
        }
        Wire::Output => {
            let commit = output_poly.commit();
            GeneratedPolynomialCommitments::Output(HeapArray::from_elem(commit))
        }
    }
}

/// Evaluate all polynomials at a single circuit index.
fn evaluate_polynomials_at_index(
    polys: &AllPolynomials,
    index: Index,
) -> (
    mosaic_cac_types::CircuitInputShares,
    mosaic_cac_types::CircuitOutputShare,
) {
    let (input_polys, output_poly) = polys;
    let mut circuit_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
    for wire in 0..N_INPUT_WIRES {
        let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
        for label in 0..WIDE_LABEL_VALUE_COUNT {
            wide_shares.push(input_polys[wire][label].eval(index));
        }
        circuit_shares.push(HeapArray::from_vec(wide_shares));
    }
    let input_shares = HeapArray::from_vec(circuit_shares);
    let output_share = output_poly.eval(index);
    (input_shares, output_share)
}

// ============================================================================
// Garbling handlers (routed through GarblingCoordinator)
// ============================================================================

async fn generate_table_commitment<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _index: mosaic_cac_types::Index,
    _seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    // TODO(phase5): Factor out garble_commit() from PR #68 setup_garbler.rs.
    //
    // Flow:
    //   1. Load withdrawal wire shares + output share for circuit index from storage
    //   2. Truncate shares to 16-byte labels
    //   3. Derive delta + bit labels from garbling seed via ChaCha20
    //   4. Generate input/output translation material
    //   5. Run ckt-runner-exec::GarbleTask → writes gc_{index}.bin
    //   6. Hash: blake3(hash(ciphertext) || hash(translation) || output_label_ct)
    //   7. Return TableCommitmentGenerated(index, commitment)
    unimplemented!("generate_table_commitment: blocked on ckt integration")
}

async fn transfer_garbling_table<SP: StorageProvider>(
    _ctx: &HandlerContext<SP>,
    _peer_id: &PeerId,
    _seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    // TODO(phase5): Read gc_{index}.bin + .translation, stream via net-svc bulk transfer.
    // Return Retry on network failure.
    unimplemented!("transfer_garbling_table: blocked on ckt integration + net-svc bulk")
}

// ============================================================================
// Light handlers (Network I/O)
// ============================================================================

async fn send_commit_msg_header<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    header: &mosaic_cac_types::CommitMsgHeader,
) -> HandlerOutcome {
    // NOTE: The garbler STF currently reuses CommitMsgChunkAcked for header acks.
    // The STF may need a dedicated result variant; for now we use the chunk ack
    // with the header's ActionId.
    let id = ActionId::SendCommitMsgHeader;
    match ctx.net_client.send(*peer_id, header.clone()).await {
        Ok(_ack) => completed(id, ActionResult::CommitMsgChunkAcked),
        Err(e) => {
            tracing::warn!(%e, "send commit msg header failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

async fn send_commit_msg_chunk<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    chunk: &mosaic_cac_types::CommitMsgChunk,
) -> HandlerOutcome {
    let id = ActionId::SendCommitMsgChunk(chunk.wire_index);
    match ctx.net_client.send(*peer_id, chunk.clone()).await {
        Ok(_ack) => completed(id, ActionResult::CommitMsgChunkAcked),
        Err(e) => {
            tracing::warn!(%e, "send commit chunk failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

async fn send_challenge_response_msg_header<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    header: &mosaic_cac_types::ChallengeResponseMsgHeader,
) -> HandlerOutcome {
    // NOTE: Same situation as commit header — STF reuses ChallengeResponseChunkAcked.
    let id = ActionId::SendChallengeResponseMsgHeader;
    match ctx.net_client.send(*peer_id, header.clone()).await {
        Ok(_ack) => completed(id, ActionResult::ChallengeResponseChunkAcked),
        Err(e) => {
            tracing::warn!(%e, "send challenge response header failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

async fn send_challenge_response_msg_chunk<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    chunk: &mosaic_cac_types::ChallengeResponseMsgChunk,
) -> HandlerOutcome {
    let id = ActionId::SendChallengeResponseMsgChunk(chunk.circuit_index);
    match ctx.net_client.send(*peer_id, chunk.clone()).await {
        Ok(_ack) => completed(id, ActionResult::ChallengeResponseChunkAcked),
        Err(e) => {
            tracing::warn!(%e, "send challenge response chunk failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

async fn verify_adaptors<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    let garb_state = ctx.storage.garbler_state(peer_id);

    // Load all required data. Retry if any reads return None (data not yet written).
    let Some(deposit_state) = garb_state.get_deposit(&deposit_id).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(deposit_adaptors) = garb_state
        .get_deposit_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(withdrawal_adaptors) = garb_state
        .get_withdrawal_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(sighashes) = garb_state
        .get_deposit_sighashes(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    let evaluator_pk = deposit_state.pk.0;
    let id = ActionId::DepositVerifyAdaptors(deposit_id);

    // Verify deposit adaptors (one per deposit wire)
    for (wire, adaptor) in deposit_adaptors.iter().enumerate() {
        if adaptor
            .verify(evaluator_pk, sighashes[wire].0.as_ref())
            .is_err()
        {
            return completed(
                id,
                ActionResult::DepositAdaptorVerificationResult(deposit_id, false),
            );
        }
    }

    // Verify withdrawal adaptors (each wire × 256 values)
    for (wire, wire_adaptors) in withdrawal_adaptors.iter().enumerate() {
        let sighash_idx = N_DEPOSIT_INPUT_WIRES + wire;
        for adaptor in wire_adaptors.iter() {
            if adaptor
                .verify(evaluator_pk, sighashes[sighash_idx].0.as_ref())
                .is_err()
            {
                return completed(
                    id,
                    ActionResult::DepositAdaptorVerificationResult(deposit_id, false),
                );
            }
        }
    }

    completed(
        id,
        ActionResult::DepositAdaptorVerificationResult(deposit_id, true),
    )
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn complete_adaptor_signatures<SP: StorageProvider>(
    ctx: &HandlerContext<SP>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    let garb_state = ctx.storage.garbler_state(peer_id);

    // Load all required data. Retry if any reads return None.
    let Some(deposit_adaptors) = garb_state
        .get_deposit_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(withdrawal_adaptors) = garb_state
        .get_withdrawal_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(reserved_input_shares) = garb_state.get_reserved_input_shares().await.ok().flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(deposit_inputs) = garb_state
        .get_deposit_inputs(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(withdrawal_input) = garb_state
        .get_withdrawal_input(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    let mut signatures = Vec::with_capacity(N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES);

    // Complete deposit adaptor signatures.
    // For each deposit wire, select the share at the known deposit input value
    // from the reserved (index 0) shares, and complete the adaptor with it.
    for wire in 0..N_DEPOSIT_INPUT_WIRES {
        let val = deposit_inputs[wire] as usize;
        let share_value = reserved_input_shares[N_SETUP_INPUT_WIRES + wire][val].value();
        signatures.push(deposit_adaptors[wire].complete(share_value));
    }

    // Complete withdrawal adaptor signatures.
    // For each withdrawal wire, select the adaptor and share at the withdrawal input value.
    for wire in 0..N_WITHDRAWAL_INPUT_WIRES {
        let val = withdrawal_input[wire] as usize;
        let share_value =
            reserved_input_shares[N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES + wire][val].value();
        signatures.push(withdrawal_adaptors[wire][val].complete(share_value));
    }

    let completed_sigs = CompletedSignatures::from_vec(signatures);
    completed(
        ActionId::CompleteAdaptorSignatures(deposit_id),
        ActionResult::AdaptorSignaturesCompleted(deposit_id, completed_sigs),
    )
}

//! Handlers for garbler state machine actions.
//!
//! Each handler executes a single garbler action and returns a
//! [`HandlerOutcome`]. On success, [`HandlerOutcome::Done`] carries the
//! [`ActionCompletion`] back to the SM. On transient failure (network
//! timeout, cache full, storage unavailable), [`HandlerOutcome::Retry`]
//! causes the worker to requeue the job so other peers can progress.

use std::sync::Arc;

use mosaic_cac_types::{
    AllPolynomialCommitments, AllPolynomials, InputPolynomialCommitments, InputPolynomials,
    OutputPolynomial, OutputPolynomialCommitment, Seed, WideLabelWirePolynomialCommitments,
    WideLabelWireShares,
    state_machine::garbler::{Action, ActionId, ActionResult, Wire},
};
use mosaic_common::constants::{N_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use super::{HandlerContext, HandlerOutcome};

/// Build a successful garbler completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Garbler { id, result })
}

/// Dispatch a garbler action to the appropriate handler.
pub(crate) async fn execute(
    ctx: &HandlerContext,
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
        Action::DepositVerifyAdaptors(deposit_id) => verify_adaptors(ctx, *deposit_id).await,

        // ── Heavy (Withdrawal — Critical) ───────────────────────────
        Action::CompleteAdaptorSignatures(deposit_id) => {
            complete_adaptor_signatures(ctx, *deposit_id).await
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

async fn generate_polynomial_commitments(
    _ctx: &HandlerContext,
    _seed: Seed,
    _wire: Wire,
) -> HandlerOutcome {
    // TODO(phase2): Implement with new polynomial cache (RAII guard + pending).
    //
    // Flow:
    //   1. ctx.polynomial_cache.get(&seed)
    //   2. Hit → commit requested wire, mark_completed, Done
    //   3. Unavailable → Retry
    //   4. Generate(guard) → generate_polynomials_from_seed, guard.complete, commit wire, Done
    unimplemented!("generate_polynomial_commitments: blocked on polynomial cache redesign")
}

async fn generate_shares(ctx: &HandlerContext, seed: Seed, index: Index) -> HandlerOutcome {
    // Try cache first, fall back to regenerating from seed.
    // TODO(phase2): Replace with new cache API (CacheResult::Hit/Unavailable/Generate).
    let polys = match ctx.polynomial_cache.get(&seed) {
        Some(arc) => arc,
        None => {
            tracing::warn!("polynomial cache miss for generate_shares, regenerating from seed");
            Arc::new(generate_polynomials_from_seed(seed))
        }
    };

    let (input_shares, output_share) = evaluate_polynomials_at_index(&polys, index);
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

/// Compute commitments for all polynomials (EC scalar multiplications).
#[expect(dead_code, reason = "will be used after polynomial cache redesign")]
fn commit_polynomials(polys: &AllPolynomials) -> AllPolynomialCommitments {
    let (input_polys, output_poly) = polys;
    let mut input_commits: Vec<WideLabelWirePolynomialCommitments> =
        Vec::with_capacity(N_INPUT_WIRES);
    for wire in 0..N_INPUT_WIRES {
        let commits: Vec<PolynomialCommitment> =
            input_polys[wire].iter().map(|p| p.commit()).collect();
        input_commits.push(HeapArray::from_vec(commits));
    }
    let input_commits: InputPolynomialCommitments = HeapArray::from_vec(input_commits);
    let output_commit: OutputPolynomialCommitment = HeapArray::from_elem(output_poly.commit());
    (input_commits, output_commit)
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

async fn generate_table_commitment(
    _ctx: &HandlerContext,
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

async fn transfer_garbling_table(
    _ctx: &HandlerContext,
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

async fn send_commit_msg_header(
    ctx: &HandlerContext,
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

async fn send_commit_msg_chunk(
    ctx: &HandlerContext,
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

async fn send_challenge_response_msg_header(
    ctx: &HandlerContext,
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

async fn send_challenge_response_msg_chunk(
    ctx: &HandlerContext,
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

async fn verify_adaptors(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    // TODO(phase4): Load from StateRead, verify each adaptor signature.
    //
    // Flow:
    //   1. Load deposit_adaptors, withdrawal_adaptors, sighashes, deposit pk from storage
    //   2. For each deposit adaptor: adaptor.verify(evaluator_pk, sighash)
    //   3. For each withdrawal adaptor (wire × 256): adaptor.verify(evaluator_pk, sighash)
    //   4. Return DepositAdaptorVerificationResult(deposit_id, bool)
    //   5. Return Retry if storage read fails
    //
    // Reference: PR #68 deposit_garbler.rs exec_verify_adaptors()
    unimplemented!("verify_adaptors: blocked on StateRead wiring")
}

// ============================================================================
// Heavy handlers (Withdrawal — Critical priority)
// ============================================================================

async fn complete_adaptor_signatures(
    _ctx: &HandlerContext,
    _deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    // TODO(phase4): Load from StateRead, complete adaptor signatures.
    //
    // Flow:
    //   1. Load deposit_adaptors, withdrawal_adaptors, reserved_input_shares,
    //      deposit_inputs, withdrawal_input from storage
    //   2. For each deposit wire: adaptor.complete(share.value())
    //   3. For each withdrawal wire: adaptor[val].complete(share[val].value())
    //   4. Return AdaptorSignaturesCompleted(deposit_id, CompletedSignatures)
    //   5. Return Retry if storage read fails
    //
    // Reference: PR #68 deposit_garbler.rs exec_sign()
    unimplemented!("complete_adaptor_signatures: blocked on StateRead wiring")
}

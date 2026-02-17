//! Handlers for garbler state machine actions.
//!
//! Each handler executes a single garbler action and produces an
//! [`ActionCompletion`]. Handlers retry internally until they succeed —
//! the caller always receives a valid completion.

use std::sync::Arc;

use mosaic_cac_types::state_machine::garbler::{Action, ActionId, ActionResult};
use mosaic_cac_types::{
    AllPolynomialCommitments, AllPolynomials, InputPolynomialCommitments, InputPolynomials,
    OutputPolynomial, OutputPolynomialCommitment, Seed, WideLabelWirePolynomialCommitments,
    WideLabelWireShares,
};
use mosaic_common::constants::{N_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::ActionCompletion;
use mosaic_net_svc_api::PeerId;
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use super::HandlerContext;

/// Build a successful garbler completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> ActionCompletion {
    ActionCompletion::Garbler { id, result }
}

/// Dispatch a garbler action to the appropriate handler.
pub(crate) async fn execute(
    ctx: &HandlerContext,
    peer_id: &PeerId,
    action: Action,
) -> ActionCompletion {
    match action {
        // ── Heavy (Setup) ───────────────────────────────────────────
        Action::GeneratePolynomialCommitments(seed) => {
            generate_polynomial_commitments(ctx, seed).await
        }
        Action::GenerateShares(seed, index) => generate_shares(ctx, seed, index).await,

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

async fn generate_polynomial_commitments(ctx: &HandlerContext, seed: Seed) -> ActionCompletion {
    let polys = generate_polynomials_from_seed(seed);

    // Cache for the subsequent GenerateShares calls.
    let arc = match ctx.polynomial_cache.insert(seed, polys) {
        Ok(arc) => arc,
        Err(_full) => {
            // Cache is at capacity — generate without caching.
            // This path is unlikely with max_entries = 4.
            tracing::warn!("polynomial cache full, generating without caching");
            Arc::new(generate_polynomials_from_seed(seed))
        }
    };

    let commitments = commit_polynomials(&arc);
    let id = ActionId::GeneratePolynomialCommitments(seed);
    completed(
        id,
        ActionResult::PolynomialCommitmentsGenerated(commitments),
    )
}

async fn generate_shares(ctx: &HandlerContext, seed: Seed, index: Index) -> ActionCompletion {
    // Try cache first, fall back to regenerating from seed.
    let polys = match ctx.polynomial_cache.get(&seed) {
        Some(arc) => arc,
        None => {
            tracing::warn!("polynomial cache miss, regenerating from seed");
            Arc::new(generate_polynomials_from_seed(seed))
        }
    };

    let (input_shares, output_share) = evaluate_polynomials_at_index(&polys, index);
    let id = ActionId::GenerateShares(seed, index);
    completed(
        id,
        ActionResult::SharesGenerated(index, Box::new(input_shares), Box::new(output_share)),
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
        std::array::from_fn(|_| HeapArray::new(|_| Polynomial::rand(&mut rng)));
    let output_poly: OutputPolynomial = Polynomial::rand(&mut rng);
    (Box::new(input_polys), Box::new(output_poly))
}

/// Compute commitments for all polynomials (EC scalar multiplications).
fn commit_polynomials(polys: &AllPolynomials) -> AllPolynomialCommitments {
    let (input_polys, output_poly) = polys;
    let mut input_commits: Vec<WideLabelWirePolynomialCommitments> =
        Vec::with_capacity(N_INPUT_WIRES);
    for wire in 0..N_INPUT_WIRES {
        let commits: Vec<PolynomialCommitment> =
            input_polys[wire].iter().map(|p| p.commit()).collect();
        input_commits.push(HeapArray::from_vec(commits));
    }
    let input_commits: InputPolynomialCommitments =
        input_commits.try_into().expect("N_INPUT_WIRES match");
    let output_commit: OutputPolynomialCommitment = output_poly.commit();
    (Box::new(input_commits), Box::new(output_commit))
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
    ctx: &HandlerContext,
    peer_id: &PeerId,
    chunk: mosaic_cac_types::CommitMsgChunk,
) -> ActionCompletion {
    let id = ActionId::SendCommitMsgChunk(chunk.wire_index);
    loop {
        match ctx.net_client.send(*peer_id, chunk.clone()).await {
            Ok(_ack) => return completed(id, ActionResult::CommitMsgChunkAcked),
            Err(e) => {
                tracing::warn!(wire = chunk.wire_index, %e, "send commit chunk failed, retrying")
            }
        }
    }
}

async fn send_challenge_response_msg_chunk(
    ctx: &HandlerContext,
    peer_id: &PeerId,
    chunk: mosaic_cac_types::ChallengeResponseMsgChunk,
) -> ActionCompletion {
    let id = ActionId::SendChallengeResponseMsgChunk(chunk.circuit_index);
    loop {
        match ctx.net_client.send(*peer_id, chunk.clone()).await {
            Ok(_ack) => return completed(id, ActionResult::ChallengeResponseChunkAcked),
            Err(e) => {
                tracing::warn!(circuit = chunk.circuit_index, %e, "send challenge response chunk failed, retrying")
            }
        }
    }
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

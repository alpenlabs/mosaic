//! Executors for garbler state machine actions.

use ckt_fmtv5_types::v5::c::ReaderV5c;
use mosaic_cac_types::{
    AllPolynomials, CompletedSignatures, InputPolynomials, OutputPolynomial, Seed,
    WideLabelWireShares,
    state_machine::garbler::{
        Action, ActionId, ActionResult, GeneratedPolynomialCommitments, StateRead as _, Step, Wire,
    },
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_SETUP_INPUT_WIRES,
    N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::{ActionCompletion, HandlerOutcome};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use super::MosaicExecutor;
use crate::garbling::{GarblingSession, compute_commitment};
use mosaic_storage_api::table_store::TableStore;

/// Build a successful garbler completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Garbler { id, result })
}

/// Dispatch a garbler action to the appropriate handler.
// ============================================================================

pub(crate) async fn handle_generate_polynomial_commitments<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_generate_shares<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

async fn generate_table_commitment<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    index: mosaic_cac_types::Index,
    seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    let garb_state = ctx.storage.garbler_state(peer_id);

    let Some(input_shares) = garb_state.get_input_shares().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(output_shares) = garb_state.get_output_shares().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };

    let idx = index.get();
    let withdrawal_shares: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES] = input_shares[idx]
        [N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
        .try_into()
        .expect("withdrawal shares slice length mismatch");
    let output_share = &output_shares[idx];

    let Ok(mut reader) = ReaderV5c::open(&ctx.circuit_path) else {
        return HandlerOutcome::Retry;
    };
    let header = *reader.header();
    let outputs = reader.outputs().to_vec();

    let setup = GarblingSession::begin(seed, withdrawal_shares, output_share, &header);
    let mut session = setup.session;

    let translate_hash = blake3::hash(&setup.translation_bytes);

    let mut ct_hasher = blake3::Hasher::new();
    while let Some(chunk) = reader
        .next_blocks_chunk()
        .await
        .expect("circuit read error")
    {
        for block in chunk.blocks_iter() {
            let ct_bytes = session.process_block(block);
            ct_hasher.update(ct_bytes);
        }
    }
    let ct_hash = ct_hasher.finalize();

    let finish = session.finish(&outputs);
    let commitment = compute_commitment(&ct_hash, &translate_hash, &finish.output_label_ct);

    completed(
        ActionId::GenerateTableCommitment(index),
        ActionResult::TableCommitmentGenerated(index, commitment),
    )
}

async fn transfer_garbling_table<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    let garb_state = ctx.storage.garbler_state(peer_id);

    // Resolve seed → (circuit_index, commitment) from the SM root state.
    // The eval_seeds and eval_commitments are stored in the TransferringGarblingTables step.
    let Some(root_state) = garb_state.get_root_state().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let (eval_seeds, eval_commitments) = match &root_state.step {
        Step::TransferringGarblingTables {
            eval_seeds,
            eval_commitments,
            ..
        } => (eval_seeds.clone(), eval_commitments.clone()),
        _ => return HandlerOutcome::Retry,
    };

    let Some(pos) = eval_seeds.iter().position(|s| *s == seed) else {
        // Seed not found among eval seeds — stale action or state mismatch.
        return HandlerOutcome::Retry;
    };
    let commitment = eval_commitments[pos];

    // Derive the circuit index from challenge indices.
    let Some(challenge_indices) = garb_state.get_challenge_indices().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let challenged: Vec<usize> = challenge_indices.iter().map(|ci| ci.get()).collect();
    let eval_indices: Vec<usize> = (1..=N_CIRCUITS)
        .filter(|i| !challenged.contains(i))
        .collect();
    let circuit_index = eval_indices[pos];

    // Load shares for this circuit.
    let Some(input_shares) = garb_state.get_input_shares().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(output_shares) = garb_state.get_output_shares().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };

    let withdrawal_shares: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES] = input_shares
        [circuit_index][N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
        .try_into()
        .expect("withdrawal shares slice length mismatch");
    let output_share = &output_shares[circuit_index];

    // Open circuit and set up garbling session.
    let Ok(mut reader) = ReaderV5c::open(&ctx.circuit_path) else {
        return HandlerOutcome::Retry;
    };
    let header = *reader.header();
    let outputs = reader.outputs().to_vec();

    let setup = GarblingSession::begin(seed, withdrawal_shares, output_share, &header);
    let mut session = setup.session;

    // Open a bulk transfer stream to the peer.
    // The commitment serves as the stream identifier — the evaluator registers
    // to receive using the same commitment via expect_bulk_transfer.
    let identifier: [u8; 32] = commitment
        .as_ref()
        .try_into()
        .expect("commitment is 32 bytes");

    let bulk_stream = ctx
        .net_client
        .handle()
        .open_bulk_stream(*peer_id, identifier, -1)
        .await;

    let Ok(mut stream) = bulk_stream else {
        return HandlerOutcome::Retry;
    };

    // Stream translation material first.
    if stream.write(setup.translation_bytes).await.is_err() {
        return HandlerOutcome::Retry;
    }

    // Stream ciphertext data block by block.
    loop {
        match reader.next_blocks_chunk().await {
            Ok(Some(chunk)) => {
                for block in chunk.blocks_iter() {
                    let ct_bytes = session.process_block(block);
                    if !ct_bytes.is_empty() && stream.write(ct_bytes.to_vec()).await.is_err() {
                        return HandlerOutcome::Retry;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => return HandlerOutcome::Retry,
        }
    }

    // Finalize the session (consumes it cleanly).
    let _finish = session.finish(&outputs);

    completed(
        ActionId::TransferGarblingTable(seed),
        ActionResult::GarblingTableTransferred(seed, commitment),
    )
}

// ============================================================================
// Light handlers (Network I/O)
// ============================================================================

pub(crate) async fn handle_send_commit_msg_header<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_send_commit_msg_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_send_challenge_response_header<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_send_challenge_response_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_verify_adaptors<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_complete_adaptor_signatures<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

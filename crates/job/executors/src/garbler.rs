//! Executors for garbler state machine actions.

use ckt_fmtv5_types::v5::c::ReaderV5c;
use mosaic_cac_types::{
    AllPolynomials, CommitMsgChunk, CompletedSignatures, DepositAdaptors, DepositInputs,
    GarblingSeed, InputPolynomials, OutputPolynomial, PubKey, ReservedDepositInputShares,
    ReservedInputShares, ReservedWithdrawalInputShares, Seed, WideLabelWireShares,
    WithdrawalAdaptors,
    state_machine::garbler::{
        ActionId, ActionResult, GeneratedPolynomialCommitments, StateRead as _, Step, Wire,
    },
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_SETUP_INPUT_WIRES,
    N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::{ActionCompletion, CircuitError, HandlerOutcome};
use mosaic_net_svc_api::{PeerId, StreamClosed};
use mosaic_storage_api::{StorageProvider, table_store::TableStore};
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};

use super::MosaicExecutor;
use crate::{circuit_sessions::TransferSession, garbling::GarblingSession};

/// Build a successful garbler completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Garbler { id, result })
}
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

    // ensure output polynomial has a valid schnorr public key at reserved index
    // this public key will be used for slashing condition
    // half of the points in the domain are valid public key
    let mut output_poly: OutputPolynomial = Polynomial::rand(&mut rng);
    loop {
        let output_poly_commit = output_poly.commit().get_zeroth_coefficient();
        if PubKey(output_poly_commit).valid() {
            break;
        }
        output_poly = Polynomial::rand(&mut rng);
    }

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
// Light handlers (Network I/O)
// ============================================================================

pub(crate) async fn handle_send_commit_msg_header<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    header: &mosaic_cac_types::CommitMsgHeader,
) -> HandlerOutcome {
    let id = ActionId::SendCommitMsgHeader;
    match ctx.net_client.send(*peer_id, header.clone()).await {
        Ok(_ack) => completed(id, ActionResult::CommitMsgHeaderAcked),
        Err(e) => {
            tracing::warn!(%e, "send commit msg header failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

pub(crate) async fn handle_send_commit_msg_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    wire_index: u16,
) -> HandlerOutcome {
    let garb_state = match ctx.storage.garbler_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

    // Load all required data. Retry if any reads return None (data not yet written).
    let Some(wire_poly_commitments) = garb_state
        .get_input_polynomial_commitment_by_wire(wire_index)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

    // Create commit message chunk for this wire.
    let chunk = CommitMsgChunk {
        wire_index,
        commitments: wire_poly_commitments,
    };

    let id = ActionId::SendCommitMsgChunk(wire_index);
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
    let id = ActionId::SendChallengeResponseMsgHeader;
    match ctx.net_client.send(*peer_id, header.clone()).await {
        Ok(_ack) => completed(id, ActionResult::ChallengeResponseHeaderAcked),
        Err(e) => {
            tracing::warn!(%e, "send challenge response header failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

pub(crate) async fn handle_send_challenge_response_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    index: &Index,
) -> HandlerOutcome {
    let id = ActionId::SendChallengeResponseMsgChunk(index.get() as u16);
    let garb_state = match ctx.storage.garbler_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

    let Some(shares) = garb_state
        .get_input_shares_for_circuit(index)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let chunk = mosaic_cac_types::ChallengeResponseMsgChunk {
        circuit_index: index.get() as u16,
        shares,
    };

    match ctx.net_client.send(*peer_id, chunk).await {
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

fn is_adaptor_derived_from_shares(
    reserved_input_shares: &ReservedInputShares,
    deposit_input: DepositInputs,
    deposit_adaptors: &DepositAdaptors,
    withdrawal_adaptors: &WithdrawalAdaptors,
) -> Result<(), std::string::String> {
    fn get_reserved_deposit_withdrawal_shares(
        reserved_input_shares: &ReservedInputShares,
        deposit_input: DepositInputs,
    ) -> (ReservedDepositInputShares, ReservedWithdrawalInputShares) {
        // select deposit input shares using deposit_input, one per wire
        let deposit_input_shares: ReservedDepositInputShares = std::array::from_fn(|wire| {
            reserved_input_shares[N_SETUP_INPUT_WIRES + wire][deposit_input[wire] as usize]
        });

        // withdrawal input not yet known, store one per value, per wire
        let withdrawal_input_shares: &ReservedWithdrawalInputShares = reserved_input_shares
            [N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
            .try_into()
            .expect("match length");

        (deposit_input_shares, withdrawal_input_shares.clone())
    }

    let (reserved_deposit_input_shares, reserved_withdrawal_input_shares) =
        get_reserved_deposit_withdrawal_shares(reserved_input_shares, deposit_input);

    let is_adaptor_of_deposit_input = reserved_deposit_input_shares
        .iter()
        .zip(deposit_adaptors)
        .all(|(share, adaptor)| share.commit().point() == adaptor.share_commitment);
    if !is_adaptor_of_deposit_input {
        return Err(String::from("deposit adaptor does not match deposit input"));
    }

    let is_adaptor_of_withdrawal_inputs = reserved_withdrawal_input_shares
        .iter()
        .zip(withdrawal_adaptors)
        .all(|(withdrawal_shares, withdrawal_adaptors)| {
            withdrawal_shares.iter().zip(withdrawal_adaptors).all(
                |(withdrawal_share, withdrawal_adaptor)| {
                    withdrawal_share.commit().point() == withdrawal_adaptor.share_commitment
                },
            )
        });
    if !is_adaptor_of_withdrawal_inputs {
        return Err(String::from("withdrawal adaptors do not match order"));
    }
    Ok(())
}

pub(crate) async fn handle_verify_adaptors<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    let garb_state = match ctx.storage.garbler_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

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

    let Some(deposit_input) = garb_state
        .get_deposit_inputs(&deposit_id)
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
    let link_share_to_adaptor = is_adaptor_derived_from_shares(
        &reserved_input_shares,
        deposit_input,
        &deposit_adaptors,
        &withdrawal_adaptors,
    );
    if link_share_to_adaptor.is_err() {
        return HandlerOutcome::Retry;
    }

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
    let garb_state = match ctx.storage.garbler_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

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

// ============================================================================
// Circuit session setup (called by MosaicExecutor trait impls)
// ============================================================================

/// Set up a [`TransferSession`] for G8 (`TransferGarblingTable`).
///
/// Performs all setup work (load shares, resolve seed → commitment, create
/// garbling session, open bulk stream, send translation) and returns the
/// session for the garbling coordinator to drive block-by-block.
pub(crate) async fn setup_transfer_session<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    seed: GarblingSeed,
) -> Result<TransferSession, CircuitError> {
    let garb_state = ctx
        .storage
        .garbler_state(peer_id)
        .await
        .map_err(|_| CircuitError::StorageUnavailable)?;

    // Resolve seed → (circuit_index, commitment) from the SM root state.
    let root_state = garb_state
        .get_root_state()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;

    let (eval_seeds, eval_commitments) = match &root_state.step {
        Step::TransferringGarblingTables {
            eval_seeds,
            eval_commitments,
            ..
        } => (eval_seeds.clone(), eval_commitments.clone()),
        _ => return Err(CircuitError::StorageUnavailable),
    };

    let pos = eval_seeds
        .iter()
        .position(|s| *s == seed)
        .ok_or(CircuitError::SetupFailed("seed not in eval_seeds".into()))?;
    let commitment = eval_commitments[pos];

    // Derive the circuit index from challenge indices.
    let challenge_indices = garb_state
        .get_challenge_indices()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let challenged: Vec<usize> = challenge_indices.iter().map(|ci| ci.get()).collect();
    let eval_indices: Vec<usize> = (1..=N_CIRCUITS)
        .filter(|i| !challenged.contains(i))
        .collect();
    let circuit_index = Index::new(eval_indices[pos]).unwrap();

    // Load shares for this circuit.
    let input_shares = garb_state
        .get_input_shares_for_circuit(&circuit_index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let output_share = garb_state
        .get_output_share_for_circuit(&circuit_index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;

    // Open circuit file for header + outputs only.
    // The coordinator handles the actual block reading via the shared reader.
    let reader = ReaderV5c::open(&ctx.circuit_path)
        .map_err(|e| CircuitError::SetupFailed(format!("circuit open: {e}")))?;
    let header = *reader.header();
    let outputs = reader.outputs().to_vec();

    // Create garbling session.
    let mut setup = GarblingSession::begin(seed, input_shares.as_ref(), &output_share, &header);

    // Open a bulk transfer stream to the evaluator.
    // The commitment serves as the stream identifier — the evaluator registers
    // to receive using the same commitment via expect_bulk_transfer.
    let identifier: [u8; 32] = commitment
        .as_ref()
        .try_into()
        .expect("commitment is 32 bytes");

    let mut stream = ctx
        .net_client
        .open_bulk_sender(*peer_id, identifier, -1)
        .await
        .map_err(|e| CircuitError::SetupFailed(format!("bulk stream open: {e:?}")))?;

    // Send translation material before the coordinator starts reading blocks.
    //
    // Translation is exactly 4 MiB (128 wires × 256 × 8 × 16 bytes), which
    // equals the net-svc wire frame limit (DEFAULT_MAX_FRAME_SIZE = 4 MiB).
    // The frame adds a 4-byte length prefix, so a single write would exceed
    // the limit. Split into chunks that fit comfortably within a frame.
    let translation_bytes = std::mem::take(&mut setup.translation_bytes);

    const MAX_CHUNK: usize = 2 * 1024 * 1024; // 2 MiB — well under 4 MiB frame limit
    for chunk in translation_bytes.chunks(MAX_CHUNK) {
        let _ = stream.write(chunk.to_vec()).await.map_err(|e| {
            match e {
                // Retry if PeerFinished error was sent. The PeerFinished error could have been
                // thrown because sender tried sending prematurely and stream was closed by the
                // receiver
                StreamClosed::PeerFinished => CircuitError::PeerNotReady,
                _ => CircuitError::SetupFailed(format!("translation send: {e:?}")),
            }
        })?;
    }

    Ok(TransferSession::new(
        setup.session,
        stream,
        seed,
        commitment,
        outputs,
    ))
}

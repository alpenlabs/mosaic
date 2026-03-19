//! Executors for evaluator state machine actions.

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{
    Ciphertext, Engine, InputTranslationMaterial, Label,
    traits::{EvaluationInstanceConfig, GobbleEngine},
    translate_input,
};
use mosaic_cac_types::{
    Adaptor, DepositAdaptors, GarblingTableCommitment,
    state_machine::evaluator::{ActionId, ActionResult, ChunkIndex, StateRead as _, Step},
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
    WIDE_LABEL_VALUE_COUNT, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::{ActionCompletion, CircuitError, HandlerOutcome};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{
    StorageProvider,
    table_store::{TableId, TableReader as _, TableStore, TableWriter as _},
};
use mosaic_vs3::{Index, Share, interpolate};

use super::MosaicExecutor;
use crate::{
    circuit_sessions::{CiphertextReaderAdapter, EvaluationSession},
    garbling::{compute_commitment, hash_garbling_params},
};

/// Build a successful evaluator completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Evaluator { id, result })
}
// ============================================================================

pub(crate) async fn handle_send_challenge_msg<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_send_challenge_response_receipt<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    msg: &mosaic_cac_types::ChallengeResponseReceipt,
) -> HandlerOutcome {
    match ctx.net_client.send(*peer_id, msg.clone()).await {
        Ok(_ack) => completed(
            ActionId::SendChallengeResponseReceipt,
            ActionResult::SendChallengeResponseReceiptAcked,
        ),
        Err(e) => {
            tracing::warn!(%e, "send challenge response receipt msg failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

pub(crate) async fn handle_send_table_transfer_receipt<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    msg: &Index,
) -> HandlerOutcome {
    match ctx.net_client.send(*peer_id, *msg).await {
        Ok(_ack) => completed(
            ActionId::SendTableTransferReceipt(*msg),
            ActionResult::GarblingTableTransferReceiptAcked(*msg),
        ),
        Err(e) => {
            tracing::warn!(%e, "send garbling table transfer receipt msg failed, will retry");
            HandlerOutcome::Retry
        }
    }
}

pub(crate) async fn handle_send_adaptor_msg_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

pub(crate) async fn handle_verify_opened_input_shares<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
) -> HandlerOutcome {
    use mosaic_common::constants::{N_INPUT_WIRES, N_OPEN_CIRCUITS, WIDE_LABEL_VALUE_COUNT};

    let eval_state = match ctx.storage.evaluator_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

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
                    let share = shares[idx][wire][val];
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
// Network handler (E4 — pool action, not circuit session)
// ============================================================================

pub(crate) async fn handle_receive_garbling_table<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    expected_commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    use mosaic_storage_api::table_store::{TableId, TableMetadata};

    let eval_state = match ctx.storage.evaluator_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

    // Resolve the commitment → circuit index from the evaluator root state.
    let Some(root_state) = eval_state.get_root_state().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let (eval_indices, eval_commitments) = match &root_state.step {
        mosaic_cac_types::state_machine::evaluator::Step::ReceivingGarblingTables {
            eval_indices,
            eval_commitments,
            ..
        } => (*eval_indices, eval_commitments.clone()),
        _ => return HandlerOutcome::Retry,
    };

    let Some(pos) = eval_commitments
        .iter()
        .position(|c| *c == expected_commitment)
    else {
        // Commitment not found — stale action or state mismatch.
        return HandlerOutcome::Retry;
    };
    let index = eval_indices[pos];

    // Register to receive the bulk transfer using the commitment as identifier.
    let identifier: [u8; 32] = expected_commitment
        .as_ref()
        .try_into()
        .expect("commitment is 32 bytes");

    let expectation = ctx
        .net_client
        .expect_bulk_receiver(*peer_id, identifier)
        .await;

    let Ok(expectation) = expectation else {
        return HandlerOutcome::Retry;
    };

    // Wait for the garbler to open the stream.
    let Ok(mut stream) = expectation.recv().await else {
        return HandlerOutcome::Retry;
    };

    // The garbler sends: translation bytes first, then ciphertext data.
    // Translation covers ALL input wires (setup + deposit + withdrawal).
    let translation_size: usize = N_INPUT_WIRES * 256 * 8 * 16;

    // Open a table writer for persistent storage.
    let table_id = TableId {
        peer_id: *peer_id,
        index,
    };
    let writer = ctx.table_store.create(&table_id).await;
    let Ok(mut writer) = writer else {
        return HandlerOutcome::Retry;
    };

    // Receive and process all data from the stream.
    let mut translate_hasher = blake3::Hasher::new();
    let mut ct_hasher = blake3::Hasher::new();
    let mut translation_buf = Vec::with_capacity(translation_size);
    let mut translation_remaining = translation_size;

    loop {
        let chunk = match stream.read().await {
            Ok(data) => data,
            Err(_closed) => break,
        };

        if chunk.is_empty() {
            break;
        }

        if translation_remaining > 0 {
            // Still reading translation material.
            let take = chunk.len().min(translation_remaining);
            let (translate_part, ct_part) = chunk.split_at(take);

            translation_buf.extend_from_slice(translate_part);
            translate_hasher.update(translate_part);
            translation_remaining -= take;

            // Any overflow goes to ciphertext.
            if !ct_part.is_empty() {
                ct_hasher.update(ct_part);
                if writer.write_ciphertext(ct_part).await.is_err() {
                    let _ = ctx.table_store.delete(&table_id).await;
                    return HandlerOutcome::Retry;
                }
            }
        } else {
            // All translation received — remaining data is ciphertext.
            ct_hasher.update(&chunk);
            if writer.write_ciphertext(&chunk).await.is_err() {
                let _ = ctx.table_store.delete(&table_id).await;
                return HandlerOutcome::Retry;
            }
        }
    }

    // Verify we received enough translation data.
    if translation_remaining > 0 {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    }

    let translate_hash = translate_hasher.finalize();
    let ct_hash = ct_hasher.finalize();
    // Load metadata from evaluator state. These were stored when the garbler's
    // CommitMsgHeader (aes keys, public S) and ChallengeResponseMsgHeader
    // (output label ciphertexts) were processed by the STF.
    let Some(aes_key) = eval_state.get_aes128_key(index).await.ok().flatten() else {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(public_s) = eval_state.get_public_s(index).await.ok().flatten() else {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(output_label_ct) = eval_state.get_output_label_ct(index).await.ok().flatten() else {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(constant_zero) = eval_state
        .get_constant_zero_label(index)
        .await
        .ok()
        .flatten()
    else {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(constant_one) = eval_state
        .get_constant_one_label(index)
        .await
        .ok()
        .flatten()
    else {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    // Verify the received data matches the expected commitment.
    let params_hash = hash_garbling_params(&aes_key, &public_s, &constant_one, &constant_zero);
    let computed = compute_commitment(&ct_hash, &translate_hash, &output_label_ct, &params_hash);
    if computed != expected_commitment {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    }
    let metadata = TableMetadata {
        output_label_ct,
        aes_key,
        public_s,
    };

    if writer.finish(&translation_buf, metadata).await.is_err() {
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    }
    completed(
        ActionId::ReceiveGarblingTable(expected_commitment),
        ActionResult::GarblingTableReceived(index, expected_commitment),
    )
}

// ============================================================================
// Heavy handlers (Deposit)
// ============================================================================

pub(crate) async fn handle_generate_deposit_adaptors<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
) -> HandlerOutcome {
    let eval_state = match ctx.storage.evaluator_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

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

pub(crate) async fn handle_generate_withdrawal_adaptors_chunk<
    SP: StorageProvider,
    TS: TableStore,
>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    deposit_id: mosaic_cac_types::DepositId,
    chunk_idx: &ChunkIndex,
) -> HandlerOutcome {
    let eval_state = match ctx.storage.evaluator_state(peer_id).await {
        Ok(state) => state,
        Err(_) => return HandlerOutcome::Retry,
    };

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
// Circuit session setup (called by MosaicExecutor trait impls)
// ============================================================================

/// Set up an [`EvaluationSession`] for E8 (`EvaluateGarblingTable`).
///
/// Performs all setup work (share interpolation, label translation, evaluation
/// instance creation, table reader opening) and returns the session for the
/// garbling coordinator to drive block-by-block.
///
/// This is the most complex session setup because it must:
/// 1. Interpolate shares across opened + committed circuits to find labels at the target evaluation
///    index.
/// 2. Load and parse input translation material from the table store.
/// 3. Translate byte-level labels to bit-level labels for the evaluation instance.
/// 4. Create the `EvaluationInstance` with all configuration.
/// 5. Leave the table reader positioned at ciphertext data for streaming during `process_chunk`.
pub(crate) async fn setup_evaluation_session<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    index: Index,
    commitment: GarblingTableCommitment,
) -> Result<EvaluationSession, CircuitError> {
    let eval_state = ctx
        .storage
        .evaluator_state(peer_id)
        .await
        .map_err(|_| CircuitError::StorageUnavailable)?;

    // ── Resolve deposit_id from root state ──────────────────────────────
    let root_state = eval_state
        .get_root_state()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let deposit_id = match &root_state.step {
        Step::EvaluatingTables { deposit_id, .. } => *deposit_id,
        _ => return Err(CircuitError::StorageUnavailable),
    };

    // ── Load all data needed for interpolation ──────────────────────────
    let root_config = root_state
        .config
        .as_ref()
        .ok_or(CircuitError::StorageUnavailable)?;
    let setup_input = root_config.setup_inputs;

    let challenge_indices = eval_state
        .get_challenge_indices()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let opened_input_shares = eval_state
        .get_opened_input_shares()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let deposit_inputs = eval_state
        .get_deposit_inputs(&deposit_id)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let withdrawal_inputs = eval_state
        .get_withdrawal_inputs(&deposit_id)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let reserved_setup_shares = eval_state
        .get_reserved_setup_input_shares()
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let deposit_adaptors = eval_state
        .get_deposit_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let withdrawal_adaptors = eval_state
        .get_withdrawal_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let signatures = eval_state
        .get_completed_signatures(&deposit_id)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;

    // ── Build selected input values (which value index per wire) ────────
    let mut selected_input: [u8; N_INPUT_WIRES] = [0; N_INPUT_WIRES];
    selected_input[..N_SETUP_INPUT_WIRES].copy_from_slice(&setup_input);
    selected_input[N_SETUP_INPUT_WIRES..N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES]
        .copy_from_slice(&deposit_inputs);
    selected_input[N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
        .copy_from_slice(&withdrawal_inputs);

    // ── Select opened shares at the known input values ──────────────────
    let selected_opened: Vec<[Share; N_INPUT_WIRES]> = (0..N_OPEN_CIRCUITS)
        .map(|i| {
            std::array::from_fn(|wire| {
                let val = selected_input[wire] as usize;
                opened_input_shares[i][wire][val]
            })
        })
        .collect();

    // ── Extract committed shares from signatures via adaptors ───────────
    let mut committed: Vec<Share> = reserved_setup_shares.to_vec();
    for (wire, adaptor) in deposit_adaptors.iter().enumerate() {
        let share_value = adaptor.extract_share(&signatures[wire]);
        committed.push(Share::new(Index::reserved(), share_value));
    }
    for (wire, wire_adaptors) in withdrawal_adaptors.iter().enumerate() {
        let val = withdrawal_inputs[wire] as usize;
        let share_value =
            wire_adaptors[val].extract_share(&signatures[N_DEPOSIT_INPUT_WIRES + wire]);
        committed.push(Share::new(Index::reserved(), share_value));
    }

    // ── Interpolate to find shares at missing (evaluation) indices ───────
    let challenged: Vec<usize> = challenge_indices.iter().map(|ci| ci.get()).collect();
    let eval_indices: Vec<usize> = (1..=N_CIRCUITS)
        .filter(|i| !challenged.contains(i))
        .collect();

    if !eval_indices.iter().any(|&i| i == index.get()) {
        return Err(CircuitError::SetupFailed(
            "index not in evaluation indices".into(),
        ));
    }

    let mut input_labels: Vec<Label> = Vec::with_capacity(N_INPUT_WIRES);

    for wire in 0..N_INPUT_WIRES {
        // Combine opened + committed shares for this wire.
        let mut shares_for_wire: Vec<Share> = Vec::with_capacity(N_OPEN_CIRCUITS + 1);
        for opened_circuit in selected_opened.iter().take(N_OPEN_CIRCUITS) {
            shares_for_wire.push(opened_circuit[wire]);
        }
        shares_for_wire.push(committed[wire]);

        let missing = interpolate(&shares_for_wire).map_err(|_| {
            CircuitError::SetupFailed(format!("interpolation failed for wire {wire}"))
        })?;

        // Find the share for our specific circuit index.
        let share =
            missing
                .iter()
                .find(|s| s.index() == index)
                .ok_or(CircuitError::SetupFailed(format!(
                    "interpolation did not produce share for index {}",
                    index.get()
                )))?;

        // Truncate share scalar to 16-byte label for all input wires.
        input_labels.push(share.truncate());
    }

    // ── Load evaluation parameters from state ───────────────────────────
    let aes_key = eval_state
        .get_aes128_key(index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let public_s = eval_state
        .get_public_s(index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let constant_zero = eval_state
        .get_constant_zero_label(index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let constant_one = eval_state
        .get_constant_one_label(index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;
    let output_label_ct = eval_state
        .get_output_label_ct(index)
        .await
        .ok()
        .flatten()
        .ok_or(CircuitError::StorageUnavailable)?;

    // ── Open circuit file for header + outputs ──────────────────────────
    // The coordinator handles actual block reading via the shared reader.
    let reader = ReaderV5c::open(&ctx.circuit_path)
        .map_err(|e| CircuitError::SetupFailed(format!("circuit open: {e}")))?;
    let header = *reader.header();
    let outputs = reader.outputs().to_vec();

    // ── Load translation material from table store ──────────────────────
    let table_id = TableId {
        peer_id: *peer_id,
        index,
    };
    let mut table_reader = ctx
        .table_store
        .open(&table_id)
        .await
        .map_err(|_e| CircuitError::StorageUnavailable)?;
    let translation_bytes = table_reader
        .read_translation()
        .await
        .map_err(|e| CircuitError::SetupFailed(format!("translation read: {e}")))?;

    // ── Parse translation material from bytes ───────────────────────────
    let mut translation_material: Vec<InputTranslationMaterial> = Vec::with_capacity(N_INPUT_WIRES);
    let bytes_per_ct = 16usize;
    let cts_per_row = 8usize;
    let rows_per_wire = 256usize;
    let bytes_per_wire = rows_per_wire * cts_per_row * bytes_per_ct;

    for wire in 0..N_INPUT_WIRES {
        let wire_offset = wire * bytes_per_wire;
        let mut material = [[Ciphertext::from([0u8; 16]); 8]; 256];
        for (row_idx, material_row) in material.iter_mut().enumerate() {
            for (ct_idx, ciphertext) in material_row.iter_mut().enumerate() {
                let offset = wire_offset + (row_idx * cts_per_row + ct_idx) * bytes_per_ct;
                let mut ct_bytes = [0u8; 16];
                ct_bytes.copy_from_slice(&translation_bytes[offset..offset + 16]);
                *ciphertext = Ciphertext::from(ct_bytes);
            }
        }
        translation_material.push(material);
    }

    // ── Translate byte labels → bit labels ──────────────────────────────
    let num_primary = header.primary_inputs as usize;
    let mut bit_labels: Vec<[u8; 16]> = Vec::with_capacity(num_primary);
    let mut input_values_bits = BitVec::new();
    let mut bit_count = 0;

    for byte_pos in 0..N_INPUT_WIRES {
        let byte_label = input_labels[byte_pos];
        let byte_value = selected_input[byte_pos];

        let translated = translate_input(
            byte_pos as u64,
            byte_label,
            byte_value,
            translation_material[byte_pos],
        );

        for (bit_pos, translated_label) in translated.iter().enumerate() {
            if bit_count >= num_primary {
                break;
            }
            let bit_value = ((byte_value >> bit_pos) & 1) == 1;
            input_values_bits.push(bit_value);
            bit_labels.push((*translated_label).into());
            bit_count += 1;
        }
        if bit_count >= num_primary {
            break;
        }
    }

    // ── Create evaluation instance ──────────────────────────────────────
    let config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: &bit_labels,
        selected_primary_input_values: &input_values_bits,
        aes128_key: aes_key,
        public_s,
        constant_zero_label: constant_zero,
        constant_one_label: constant_one,
    };

    let engine = Engine::new();
    let instance = engine.new_evaluation_instance(config);

    // ── Wrap table reader for ciphertext streaming ──────────────────────
    // The reader has already delivered translation material. Subsequent
    // read_ciphertext calls will stream AND-gate ciphertexts in circuit
    // execution order, synchronized with the coordinator's block delivery.
    let ct_reader = Box::new(CiphertextReaderAdapter::new(table_reader));

    let output_label_ct_bytes: [u8; 32] = output_label_ct.into();

    Ok(EvaluationSession::new(
        instance,
        ct_reader,
        index,
        commitment,
        outputs,
        output_label_ct_bytes,
    ))
}

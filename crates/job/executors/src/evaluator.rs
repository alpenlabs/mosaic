//! Executors for evaluator state machine actions.

use ark_ff::{BigInteger, PrimeField};
use bitvec::vec::BitVec;
use ckt_fmtv5_types::{
    GateType,
    v5::c::{ReaderV5c, get_block_num_gates},
};
use ckt_gobble::{
    Ciphertext, Engine, InputTranslationMaterial, Label, OutputTranslationMaterial,
    traits::{
        EvaluationInstance as EvaluationInstanceTrait, EvaluationInstanceConfig, GobbleEngine,
    },
    translate_input, translate_output,
};
use mosaic_cac_types::{
    Adaptor, DepositAdaptors, WideLabelWireShares,
    state_machine::evaluator::{Action, ActionId, ActionResult, ChunkIndex, StateRead as _, Step},
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
    N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::{ActionCompletion, HandlerOutcome};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_vs3::{Index, Scalar, Share, interpolate};

use super::MosaicExecutor;
use crate::garbling::{GarblingSession, compute_commitment};
use mosaic_storage_api::table_store::{TableId, TableReader as _, TableStore, TableWriter as _};

/// Build a successful evaluator completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Evaluator { id, result })
}

/// Dispatch an evaluator action to the appropriate handler.
// Light handlers (Network I/O)
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

async fn generate_table_commitment<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    index: mosaic_vs3::Index,
    seed: mosaic_cac_types::GarblingSeed,
) -> HandlerOutcome {
    let eval_state = ctx.storage.evaluator_state(peer_id);

    // Load opened shares and challenge indices.
    let Some(challenge_indices) = eval_state.get_challenge_indices().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(opened_input_shares) = eval_state.get_opened_input_shares().await.ok().flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(opened_output_shares) = eval_state.get_opened_output_shares().await.ok().flatten()
    else {
        return HandlerOutcome::Retry;
    };

    // Find which position in the opened arrays corresponds to this index.
    let Some(pos) = challenge_indices.iter().position(|ci| *ci == index) else {
        // This index is not among the challenged circuits — shouldn't happen.
        return HandlerOutcome::Retry;
    };

    // Extract withdrawal wire shares for this opened circuit.
    let withdrawal_shares: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES] = opened_input_shares
        [pos][N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
        .try_into()
        .expect("withdrawal shares slice length mismatch");
    let output_share = &opened_output_shares[pos];

    // Open circuit and garble.
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

async fn receive_garbling_table<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    expected_commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    use mosaic_storage_api::table_store::{TableId, TableMetadata};

    let eval_state = ctx.storage.evaluator_state(peer_id);

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
        .handle()
        .expect_bulk_transfer(*peer_id, identifier)
        .await;

    let Ok(expectation) = expectation else {
        return HandlerOutcome::Retry;
    };

    // Wait for the garbler to open the stream.
    let Ok(mut stream) = expectation.recv().await else {
        return HandlerOutcome::Retry;
    };

    // The garbler sends: translation bytes first, then ciphertext data.
    // Translation size is a protocol constant.
    let translation_size: usize = N_WITHDRAWAL_INPUT_WIRES * 256 * 8 * 16;

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

    // Verify the received data matches the expected commitment.
    let computed = compute_commitment(&ct_hash, &translate_hash, &output_label_ct);
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

pub(crate) async fn handle_generate_withdrawal_adaptors_chunk<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
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

async fn evaluate_garbling_table<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    index: Index,
    commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    let eval_state = ctx.storage.evaluator_state(peer_id);

    // ── Resolve deposit_id from root state ──────────────────────────────
    let Some(root_state) = eval_state.get_root_state().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let deposit_id = match &root_state.step {
        Step::EvaluatingTables { deposit_id, .. } => *deposit_id,
        _ => return HandlerOutcome::Retry,
    };

    // ── Load all data needed for interpolation ──────────────────────────
    let Some(root_config) = root_state.config.as_ref() else {
        return HandlerOutcome::Retry;
    };
    let setup_input = root_config.setup_inputs;

    let Some(challenge_indices) = eval_state.get_challenge_indices().await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(opened_input_shares) = eval_state.get_opened_input_shares().await.ok().flatten()
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
    let Some(withdrawal_inputs) = eval_state
        .get_withdrawal_inputs(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(reserved_setup_shares) = eval_state
        .get_reserved_setup_input_shares()
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(deposit_adaptors) = eval_state
        .get_deposit_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(withdrawal_adaptors) = eval_state
        .get_withdrawal_adaptors(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(signatures) = eval_state
        .get_completed_signatures(&deposit_id)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };

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
                opened_input_shares[i][wire][val].clone()
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

    let Some(_eval_pos) = eval_indices.iter().position(|&i| i == index.get()) else {
        return HandlerOutcome::Retry;
    };

    let mut withdrawal_labels: Vec<[u8; 16]> = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);

    for wire in 0..N_INPUT_WIRES {
        // Combine opened + committed shares for this wire.
        let mut shares_for_wire: Vec<Share> = Vec::with_capacity(N_OPEN_CIRCUITS + 1);
        for opened_circuit in selected_opened.iter().take(N_OPEN_CIRCUITS) {
            shares_for_wire.push(opened_circuit[wire].clone());
        }
        shares_for_wire.push(committed[wire].clone());

        let missing = match interpolate(&shares_for_wire) {
            Ok(m) => m,
            Err(_) => return HandlerOutcome::Retry,
        };

        // Find the share for our specific circuit index.
        if let Some(share) = missing.iter().find(|s| s.index() == index) {
            if wire >= N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES {
                // Withdrawal wire — truncate to 16-byte label.
                let full: Vec<u8> = share.value().into_bigint().to_bytes_le();
                let mut label = [0u8; 16];
                label.copy_from_slice(&full[..16]);
                withdrawal_labels.push(label);
            }
        } else {
            return HandlerOutcome::Retry;
        }
    }

    // ── Load evaluation parameters from state ───────────────────────────
    let Some(aes_key) = eval_state.get_aes128_key(index).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(public_s) = eval_state.get_public_s(index).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };
    let Some(constant_zero) = eval_state
        .get_constant_zero_label(index)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(constant_one) = eval_state
        .get_constant_one_label(index)
        .await
        .ok()
        .flatten()
    else {
        return HandlerOutcome::Retry;
    };
    let Some(output_label_ct) = eval_state.get_output_label_ct(index).await.ok().flatten() else {
        return HandlerOutcome::Retry;
    };

    // ── Open circuit file for gate structure ─────────────────────────────
    let Ok(mut circuit_reader) = ReaderV5c::open(&ctx.circuit_path) else {
        return HandlerOutcome::Retry;
    };
    let header = *circuit_reader.header();
    let outputs = circuit_reader.outputs().to_vec();
    let total_gates = header.total_gates();

    // ── Load translation material from table store ──────────────────────
    let table_id = TableId {
        peer_id: *peer_id,
        index,
    };
    let Ok(mut table_reader) = ctx.table_store.open(&table_id).await else {
        return HandlerOutcome::Retry;
    };
    let Ok(translation_bytes) = table_reader.read_translation().await else {
        return HandlerOutcome::Retry;
    };

    // ── Parse translation material from bytes ───────────────────────────
    let mut translation_material: Vec<InputTranslationMaterial> =
        Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
    let bytes_per_ct = 16usize;
    let cts_per_row = 8usize;
    let rows_per_wire = 256usize;
    let bytes_per_wire = rows_per_wire * cts_per_row * bytes_per_ct;

    for wire in 0..N_WITHDRAWAL_INPUT_WIRES {
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

    for byte_pos in 0..N_WITHDRAWAL_INPUT_WIRES {
        let byte_label = Label::from(withdrawal_labels[byte_pos]);
        let byte_value = withdrawal_inputs[byte_pos];

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
    let mut instance = engine.new_evaluation_instance(config);

    // ── Evaluation loop: feed gates + ciphertexts ───────────────────────
    //
    // For each chunk of blocks from the circuit reader (up to 16 blocks per
    // chunk), we first count the total AND gates across all blocks in that
    // chunk, then pre-read exactly that many ciphertexts (16 bytes each) from
    // the table store in a single call. This keeps the number of storage
    // reads proportional to circuit chunks (~34K reads), not AND gates (~2.9B).
    let mut block_idx: usize = 0;

    while let Some(chunk) = circuit_reader
        .next_blocks_chunk()
        .await
        .expect("circuit read error")
    {
        // Collect block metadata for this chunk so we can pre-compute the
        // total ciphertext bytes needed.
        let blocks: Vec<_> = chunk.blocks_iter().collect();
        let block_gate_counts: Vec<usize> = blocks
            .iter()
            .enumerate()
            .map(|(i, _)| get_block_num_gates(total_gates, block_idx + i))
            .collect();

        // Count AND gates across all blocks in this chunk.
        let mut and_count: usize = 0;
        for (block, &gate_count) in blocks.iter().zip(&block_gate_counts) {
            for i in 0..gate_count {
                if matches!(block.gate_type(i), GateType::AND) {
                    and_count += 1;
                }
            }
        }

        // Pre-read all ciphertexts for this chunk in one storage call.
        let ct_bytes_needed = and_count * 16;
        let mut ct_data = vec![0u8; ct_bytes_needed];
        if ct_bytes_needed > 0 {
            let mut filled = 0;
            while filled < ct_bytes_needed {
                let n = match table_reader.read_ciphertext(&mut ct_data[filled..]).await {
                    Ok(n) => n,
                    Err(_) => return HandlerOutcome::Retry,
                };
                if n == 0 {
                    return HandlerOutcome::Retry;
                }
                filled += n;
            }
        }

        // Process all blocks in this chunk, consuming pre-read ciphertexts.
        let mut ct_offset = 0;
        for (block, &gate_count) in blocks.iter().zip(&block_gate_counts) {
            for i in 0..gate_count {
                let gate = &block.gates[i];
                let in1 = gate.in1 as usize;
                let in2 = gate.in2 as usize;
                let out = gate.out as usize;

                match block.gate_type(i) {
                    GateType::XOR => {
                        instance.feed_xor_gate(in1, in2, out);
                    }
                    GateType::AND => {
                        let mut ct_bytes = [0u8; 16];
                        ct_bytes.copy_from_slice(&ct_data[ct_offset..ct_offset + 16]);
                        ct_offset += 16;
                        instance.feed_and_gate(in1, in2, out, Ciphertext::from(ct_bytes));
                    }
                }
            }
        }

        debug_assert_eq!(ct_offset, ct_bytes_needed);
        block_idx += blocks.len();
    }

    // ── Extract output and translate ────────────────────────────────────
    let output_wire_ids: Vec<u64> = outputs.iter().map(|&w| w as u64).collect();
    let mut output_labels = vec![[0u8; 16]; outputs.len()];
    let mut output_values = vec![false; outputs.len()];
    instance.get_labels(&output_wire_ids, &mut output_labels);
    instance.get_values(&output_wire_ids, &mut output_values);

    // Construct output translation material from the stored output_label_ct.
    // OutputTranslationCiphertext is [u8; 32] — the full encrypted share.
    let output_label_bytes: [u8; 32] = output_label_ct.into();
    let output_translation_material: OutputTranslationMaterial = vec![output_label_bytes];
    let output_label_vec: Vec<Label> = output_labels.iter().map(|l| Label::from(*l)).collect();
    let output_result = translate_output(
        &output_label_vec,
        &output_values,
        &output_translation_material,
    );

    let output_share = match output_result {
        Ok(ref results) if !results.is_empty() => match &results[0] {
            Some(bytes) => {
                let scalar = Scalar::from_le_bytes_mod_order(bytes);
                Some(Share::new(index, scalar))
            }
            None => None,
        },
        _ => None,
    };

    completed(
        ActionId::EvaluateGarblingTable(index),
        ActionResult::TableEvaluationResult(commitment, output_share),
    )
}

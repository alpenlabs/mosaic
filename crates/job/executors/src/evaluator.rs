//! Executors for evaluator state machine actions.

use std::time::{Duration, Instant};

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{
    Ciphertext, Engine, InputTranslationMaterial, Label,
    traits::{EvaluationInstanceConfig, GobbleEngine},
    translate_input,
};
use mosaic_cac_types::{
    Adaptor, ChallengeIndices, CircuitInputShares, DepositAdaptors, GarblingTableCommitment,
    TableTransferReceiptMsg, TableTransferRequestMsg, WideLabelWirePolynomialCommitments,
    state_machine::evaluator::{ActionId, ActionResult, ChunkIndex, StateRead as _, Step},
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
    WIDE_LABEL_VALUE_COUNT, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_heap_array::HeapArray;
use mosaic_job_api::{ActionCompletion, CircuitError, HandlerOutcome};
use mosaic_net_client::{BulkReadError, BulkReceiveError};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{
    StorageProvider,
    table_store::{TableId, TableReader as _, TableStore, TableWriter as _},
};
use mosaic_vs3::{Index, Share, batch_verify_shares, interpolate};
use tracing::{debug, error, warn};

use super::MosaicExecutor;
use crate::{
    circuit_sessions::{CiphertextReaderAdapter, EvaluationSession},
    garbling::{compute_commitment, hash_garbling_params},
};

const BULK_OPEN_WARN_AFTER: Duration = Duration::from_secs(5);
const BULK_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const BULK_READ_WARN_AFTER: Duration = Duration::from_secs(5);
const BULK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a successful evaluator completion from an action ID and result.
fn completed(id: ActionId, result: ActionResult) -> HandlerOutcome {
    HandlerOutcome::Done(ActionCompletion::Evaluator { id, result })
}

/// Load opened input shares for challenged circuits.
pub(crate) async fn load_opened_input_shares<SP: StorageProvider>(
    storage: &SP,
    peer_id: &PeerId,
    challenge_indices: &ChallengeIndices,
) -> Result<Vec<CircuitInputShares>, CircuitError> {
    let mut items = Vec::with_capacity(N_OPEN_CIRCUITS);
    let store = storage
        .evaluator_state(peer_id)
        .await
        .map_err(|_| CircuitError::StorageUnavailable)?;

    for challenge_idx in challenge_indices {
        let circuit_idx = challenge_idx.get() as u16;
        let ckt_shares = store
            .get_opened_input_shares_for_circuit(circuit_idx)
            .await
            .map_err(|_| CircuitError::StorageUnavailable)?
            .ok_or(CircuitError::StorageUnavailable)?;
        items.push(ckt_shares);
    }

    Ok(items)
}

/// Load input polynomial commitments for all wires.
pub(crate) async fn load_polynomial_commitments<SP: StorageProvider>(
    storage: &SP,
    peer_id: &PeerId,
) -> Result<Vec<WideLabelWirePolynomialCommitments>, CircuitError> {
    let mut items = Vec::with_capacity(N_INPUT_WIRES);
    let store = storage
        .evaluator_state(peer_id)
        .await
        .map_err(|_| CircuitError::StorageUnavailable)?;

    for wire_idx in 0..N_INPUT_WIRES as u16 {
        let commitment = store
            .get_input_polynomial_commitments_for_wire(wire_idx)
            .await
            .map_err(|_| CircuitError::StorageUnavailable)?
            .ok_or(CircuitError::StorageUnavailable)?;
        items.push(commitment);
    }

    Ok(items)
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

pub(crate) async fn handle_send_table_transfer_receipt<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    msg: &TableTransferReceiptMsg,
) -> HandlerOutcome {
    match ctx.net_client.send(*peer_id, msg.clone()).await {
        Ok(_ack) => completed(
            ActionId::SendTableTransferReceipt(msg.garbling_table_commitment),
            ActionResult::TableTransferReceiptAcked,
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
    let Ok(opened_input_shares) =
        load_opened_input_shares(&ctx.storage, peer_id, &challenge_indices).await
    else {
        return HandlerOutcome::Retry;
    };

    let Ok(commitments) = load_polynomial_commitments(&ctx.storage, peer_id).await else {
        return HandlerOutcome::Retry;
    };

    // Batch-verify all opened shares against their polynomial commitments via RLC.
    // Collects (commitment, shares) pairs and verifies in a single MSM.
    #[allow(clippy::needless_range_loop)]
    let failure_reason = {
        let mut share_bufs: Vec<Vec<Share>> =
            Vec::with_capacity(N_INPUT_WIRES * WIDE_LABEL_VALUE_COUNT);

        for wire in 0..N_INPUT_WIRES {
            for val in 0..WIDE_LABEL_VALUE_COUNT {
                let wire_val_shares: Vec<Share> = (0..N_OPEN_CIRCUITS)
                    .map(|idx| opened_input_shares[idx][wire][val])
                    .collect();
                share_bufs.push(wire_val_shares);
            }
        }

        let pairs: Vec<_> = (0..N_INPUT_WIRES)
            .flat_map(|wire| (0..WIDE_LABEL_VALUE_COUNT).map(move |val| (wire, val)))
            .zip(share_bufs.iter())
            .map(|((wire, val), buf)| (&commitments[wire][val], buf.as_slice()))
            .collect();

        let mut rng = rand::rngs::OsRng;
        match batch_verify_shares(&pairs, &mut rng) {
            Ok(()) => None,
            Err(_) => Some("batch verification of opened input shares failed".to_string()),
        }
    };

    completed(
        ActionId::VerifyOpenedInputShares,
        ActionResult::VerifyOpenedInputSharesResult(failure_reason),
    )
}

// ============================================================================
// Network handler (E4 — pool action, not circuit session)
// ============================================================================

/// Minimal stream interface used by [`drain_table_payload`]. Lets tests inject
/// a scripted chunk source without spinning up a real QUIC stream.
trait PayloadStream {
    async fn read_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<mosaic_net_svc_api::PayloadBuf, BulkReadError>;
}

impl PayloadStream for mosaic_net_client::BulkReceiver {
    async fn read_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<mosaic_net_svc_api::PayloadBuf, BulkReadError> {
        mosaic_net_client::BulkReceiver::read_with_timeout(self, timeout).await
    }
}

/// Outcome of [`drain_table_payload`]. The caller maps these onto
/// `HandlerOutcome` + stream/store cleanup; the helper itself is I/O-free
/// beyond the trait read.
#[derive(Debug)]
enum DrainOutcome {
    /// Stream sent exactly `translation_size + expected_ciphertext_bytes`
    /// bytes followed by FIN (or an empty frame), and every chunk was
    /// successfully forwarded to the writer.
    Complete {
        translation_buf: Vec<u8>,
        translate_hash: blake3::Hash,
        ct_hash: blake3::Hash,
    },
    /// Stream sent more ciphertext bytes than the circuit header allowed.
    OversizedCiphertext { received: usize, expected: usize },
    /// Stream closed before all translation bytes were received.
    TranslationIncomplete { remaining: usize },
    /// Stream closed cleanly but the ciphertext count was short.
    LengthMismatch { received: usize, expected: usize },
    /// Writer rejected a chunk.
    WriteFailed {
        /// `true` if the failing chunk was the ciphertext spill-over from the
        /// same frame that completed the translation segment; `false` for a
        /// steady-state ciphertext chunk. Preserved so the caller can keep
        /// the two paths distinguishable in logs/alerting.
        during_translation_overflow: bool,
    },
    /// `read_with_timeout` returned `TimedOut` before the next chunk arrived.
    ReadTimedOut,
}

/// Consume a bulk stream carrying translation bytes followed by ciphertext
/// bytes, hashing each domain and forwarding the ciphertext to `writer`.
///
/// Termination is via:
/// - `BulkReadError::Closed` (FIN) → fall through to the post-loop length checks; either
///   `Complete`, `TranslationIncomplete`, or `LengthMismatch`.
/// - Empty chunk → treated as Closed.
/// - `BulkReadError::TimedOut` → returns `ReadTimedOut` immediately.
/// - Trailing bytes past `expected_ciphertext_bytes` → returns `OversizedCiphertext` immediately
///   (closing the trailing-garbage acceptance hole that earlier versions had with an early-equality
///   `break`).
#[allow(clippy::too_many_arguments)]
async fn drain_table_payload<S, W>(
    stream: &mut S,
    writer: &mut W,
    translation_size: usize,
    expected_ciphertext_bytes: usize,
    read_timeout: Duration,
    read_warn_after: Duration,
    peer_id: &PeerId,
    index: Index,
) -> DrainOutcome
where
    S: PayloadStream,
    W: mosaic_storage_api::table_store::TableWriter,
{
    let mut translate_hasher = blake3::Hasher::new();
    let mut ct_hasher = blake3::Hasher::new();
    let mut translation_buf = Vec::with_capacity(translation_size);
    let mut translation_remaining = translation_size;
    let mut ciphertext_bytes_received = 0usize;

    loop {
        let read_started = Instant::now();
        let chunk = match stream.read_with_timeout(read_timeout).await {
            Ok(data) => {
                let elapsed = read_started.elapsed();
                if elapsed >= read_warn_after {
                    warn!(
                        %peer_id,
                        ?index,
                        ?elapsed,
                        "bulk stream read was slower than expected for receive_garbling_table"
                    );
                }
                data
            }
            Err(BulkReadError::TimedOut) => return DrainOutcome::ReadTimedOut,
            Err(BulkReadError::Closed(_)) => break,
        };

        if chunk.is_empty() {
            break;
        }

        if translation_remaining > 0 {
            // Still reading translation material; split the chunk on the
            // boundary so each domain hashes independently.
            let take = chunk.len().min(translation_remaining);
            let (translate_part, ct_part) = chunk.split_at(take);

            translation_buf.extend_from_slice(translate_part);
            translate_hasher.update(translate_part);
            translation_remaining -= take;

            if !ct_part.is_empty() {
                let next_ciphertext_bytes = ciphertext_bytes_received + ct_part.len();
                if next_ciphertext_bytes > expected_ciphertext_bytes {
                    return DrainOutcome::OversizedCiphertext {
                        received: next_ciphertext_bytes,
                        expected: expected_ciphertext_bytes,
                    };
                }
                ciphertext_bytes_received = next_ciphertext_bytes;
                ct_hasher.update(ct_part);
                if writer.write_ciphertext(ct_part).await.is_err() {
                    return DrainOutcome::WriteFailed {
                        during_translation_overflow: true,
                    };
                }
            }
        } else {
            // Translation already consumed — everything else is ciphertext.
            // Don't break on equality with `expected`; let the next iteration's
            // `>` check catch any trailing bytes and exit via `Closed` /
            // empty-chunk / timeout otherwise.
            let next_ciphertext_bytes = ciphertext_bytes_received + chunk.len();
            if next_ciphertext_bytes > expected_ciphertext_bytes {
                return DrainOutcome::OversizedCiphertext {
                    received: next_ciphertext_bytes,
                    expected: expected_ciphertext_bytes,
                };
            }
            ciphertext_bytes_received = next_ciphertext_bytes;
            ct_hasher.update(&chunk);
            if writer.write_ciphertext(&chunk).await.is_err() {
                return DrainOutcome::WriteFailed {
                    during_translation_overflow: false,
                };
            }
        }
    }

    if translation_remaining > 0 {
        return DrainOutcome::TranslationIncomplete {
            remaining: translation_remaining,
        };
    }
    if ciphertext_bytes_received != expected_ciphertext_bytes {
        return DrainOutcome::LengthMismatch {
            received: ciphertext_bytes_received,
            expected: expected_ciphertext_bytes,
        };
    }

    DrainOutcome::Complete {
        translation_buf,
        translate_hash: translate_hasher.finalize(),
        ct_hash: ct_hasher.finalize(),
    }
}

pub(crate) async fn handle_receive_garbling_table<SP: StorageProvider, TS: TableStore>(
    ctx: &MosaicExecutor<SP, TS>,
    peer_id: &PeerId,
    expected_commitment: mosaic_cac_types::GarblingTableCommitment,
) -> HandlerOutcome {
    use mosaic_storage_api::table_store::{TableId, TableMetadata};

    let eval_state = match ctx.storage.evaluator_state(peer_id).await {
        Ok(state) => state,
        Err(e) => {
            warn!(%peer_id, ?e, "failed to load evaluator state for receive_garbling_table");
            return HandlerOutcome::Retry;
        }
    };

    // Resolve the commitment → circuit index from the evaluator root state.
    let Some(root_state) = eval_state.get_root_state().await.ok().flatten() else {
        warn!(%peer_id, "root state not available for receive_garbling_table");
        return HandlerOutcome::Retry;
    };
    let (eval_indices, eval_commitments) = match &root_state.step {
        mosaic_cac_types::state_machine::evaluator::Step::ReceivingGarblingTables {
            eval_indices,
            eval_commitments,
            ..
        } => (*eval_indices, eval_commitments.clone()),
        _ => {
            warn!(%peer_id, step = ?root_state.step, "unexpected step in receive_garbling_table");
            return HandlerOutcome::Retry;
        }
    };

    let Some(pos) = eval_commitments
        .iter()
        .position(|c| *c == expected_commitment)
    else {
        // Commitment not found — stale action or state mismatch.
        warn!(%peer_id, "commitment not found in eval_commitments for receive_garbling_table");
        return HandlerOutcome::Retry;
    };
    let index = eval_indices[pos];
    let expected_ciphertext_bytes = match ctx.expected_table_ciphertext_bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(%peer_id, ?index, ?e, "failed to compute expected ciphertext length for receive_garbling_table");
            return HandlerOutcome::Retry;
        }
    };

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
        warn!(%peer_id, "bulk receiver registration failed for receive_garbling_table");
        return HandlerOutcome::Retry;
    };

    // Registration succeeded — now tell the garbler to start the transfer.
    let request_msg = TableTransferRequestMsg::new(expected_commitment);
    if let Err(e) = ctx.net_client.send(*peer_id, request_msg).await {
        tracing::warn!(%e, "send table transfer request failed, will retry");
        return HandlerOutcome::Retry;
    }

    // Wait for the garbler to open the stream.
    let open_started = Instant::now();
    let mut stream = match expectation.recv_with_timeout(BULK_OPEN_TIMEOUT).await {
        Ok(stream) => {
            let elapsed = open_started.elapsed();
            if elapsed >= BULK_OPEN_WARN_AFTER {
                warn!(
                    %peer_id,
                    ?index,
                    ?elapsed,
                    "bulk stream open was slower than expected for receive_garbling_table"
                );
            }
            stream
        }
        Err(BulkReceiveError::TimedOut) => {
            warn!(
                %peer_id,
                ?index,
                timeout = ?BULK_OPEN_TIMEOUT,
                "timed out waiting for bulk stream in receive_garbling_table"
            );
            return HandlerOutcome::Retry;
        }
        Err(BulkReceiveError::Closed) => {
            warn!(%peer_id, ?index, "bulk stream receive failed for receive_garbling_table");
            return HandlerOutcome::Retry;
        }
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
        warn!(%peer_id, "table writer creation failed for receive_garbling_table");
        return HandlerOutcome::Retry;
    };

    // Drain the bulk stream into `writer` and the translation buffer, hashing
    // each domain along the way. The helper returns one of several outcomes;
    // we apply stream-reset / table cleanup at this layer based on the outcome
    // so the helper itself stays I/O-free below the read trait.
    let (translation_buf, translate_hash, ct_hash) = match drain_table_payload(
        &mut stream,
        &mut writer,
        translation_size,
        expected_ciphertext_bytes,
        BULK_READ_TIMEOUT,
        BULK_READ_WARN_AFTER,
        peer_id,
        index,
    )
    .await
    {
        DrainOutcome::Complete {
            translation_buf,
            translate_hash,
            ct_hash,
        } => (translation_buf, translate_hash, ct_hash),
        DrainOutcome::ReadTimedOut => {
            warn!(
                %peer_id,
                ?index,
                timeout = ?BULK_READ_TIMEOUT,
                "timed out waiting for bulk payload in receive_garbling_table"
            );
            stream.reset(0).await;
            let _ = ctx.table_store.delete(&table_id).await;
            return HandlerOutcome::Retry;
        }
        DrainOutcome::OversizedCiphertext { received, expected } => {
            error!(
                %peer_id,
                ?index,
                received,
                expected,
                "received oversized ciphertext stream for receive_garbling_table"
            );
            stream.reset(0).await;
            let _ = ctx.table_store.delete(&table_id).await;
            return HandlerOutcome::Retry;
        }
        DrainOutcome::WriteFailed {
            during_translation_overflow,
        } => {
            if during_translation_overflow {
                error!(
                    %peer_id,
                    "ciphertext write failed (translation overflow) for receive_garbling_table"
                );
            } else {
                error!(%peer_id, "ciphertext write failed for receive_garbling_table");
            }
            let _ = ctx.table_store.delete(&table_id).await;
            return HandlerOutcome::Retry;
        }
        DrainOutcome::TranslationIncomplete { remaining } => {
            error!(
                %peer_id,
                translation_remaining = remaining,
                "incomplete translation data for receive_garbling_table"
            );
            let _ = ctx.table_store.delete(&table_id).await;
            return HandlerOutcome::Retry;
        }
        DrainOutcome::LengthMismatch { received, expected } => {
            error!(
                %peer_id,
                ?index,
                received,
                expected,
                "ciphertext length mismatch for receive_garbling_table"
            );
            let _ = ctx.table_store.delete(&table_id).await;
            return HandlerOutcome::Retry;
        }
    };

    // Load metadata from evaluator state. These were stored when the garbler's
    // CommitMsgHeader (aes keys, public S) and ChallengeResponseMsgHeader
    // (output label ciphertexts) were processed by the STF.
    let Some(aes_key) = eval_state.get_aes128_key(index).await.ok().flatten() else {
        warn!(%peer_id, ?index, "aes128_key not available for receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(public_s) = eval_state.get_public_s(index).await.ok().flatten() else {
        warn!(%peer_id, ?index, "public_s not available for receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(output_label_ct) = eval_state.get_output_label_ct(index).await.ok().flatten() else {
        warn!(%peer_id, ?index, "output_label_ct not available for receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(constant_zero) = eval_state
        .get_constant_zero_label(index)
        .await
        .ok()
        .flatten()
    else {
        warn!(%peer_id, ?index, "constant_zero_label not available for receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    let Some(constant_one) = eval_state
        .get_constant_one_label(index)
        .await
        .ok()
        .flatten()
    else {
        warn!(%peer_id, ?index, "constant_one_label not available for receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    };
    // Verify the received data matches the expected commitment.
    let params_hash = hash_garbling_params(&aes_key, &public_s, &constant_one, &constant_zero);
    let computed = compute_commitment(&ct_hash, &translate_hash, &output_label_ct, &params_hash);
    if computed != expected_commitment {
        error!(%peer_id, ?index, "commitment mismatch in receive_garbling_table");
        let _ = ctx.table_store.delete(&table_id).await;
        return HandlerOutcome::Retry;
    }
    let metadata = TableMetadata {
        output_label_ct,
        aes_key,
        public_s,
    };

    if writer.finish(&translation_buf, metadata).await.is_err() {
        error!(%peer_id, ?index, "table writer finish failed for receive_garbling_table");
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

    let Ok(deposit_input_wire_zero_coefficients) = eval_state
        .get_input_polynomial_zeroth_coefficients(
            // deposit input wire range
            N_SETUP_INPUT_WIRES..N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES,
        )
        .await
    else {
        return HandlerOutcome::Retry;
    };

    let sk = deposit_state.sk.0;
    let pk = deposit_state.sk.to_pubkey().0;
    let mut rng = rand::rngs::OsRng;

    // Generate one adaptor per deposit wire, using the share commitment at
    // reserved index (= zeroth polynomial coefficient) for the wire's input value.
    let mut adaptors = Vec::with_capacity(N_DEPOSIT_INPUT_WIRES);
    for deposit_wire in 0..N_DEPOSIT_INPUT_WIRES {
        let val = deposit_inputs[deposit_wire] as usize;
        // Zeroth coefficient of commitment polynomial = commitment to share at index 0
        let share_commitment = deposit_input_wire_zero_coefficients[deposit_wire][val];
        let adaptor = Adaptor::generate(
            &mut rng,
            share_commitment,
            sk,
            pk,
            sighashes[deposit_wire].0.as_ref(),
        )
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

    // Each chunk covers WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK consecutive withdrawal wires.
    let chunk_offset = chunk_idx.get() as usize * WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK;

    // load only coefficients corresponding to chunk range
    let withdrawal_offset = N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES;
    let chunk_range_start = withdrawal_offset + chunk_offset;
    let chunk_range_end = chunk_range_start + WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK;
    let Ok(chunk_zero_coefficients) = eval_state
        .get_input_polynomial_zeroth_coefficients(
            // withdrawal input wire range for current chunk
            chunk_range_start..chunk_range_end,
        )
        .await
    else {
        return HandlerOutcome::Retry;
    };

    let sk = deposit_state.sk.0;
    let pk = deposit_state.sk.to_pubkey().0;
    let mut rng = rand::rngs::OsRng;

    let mut wires = Vec::with_capacity(WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK);
    #[expect(clippy::needless_range_loop, reason = "uniformity")]
    for wire_in_chunk in 0..WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK {
        let withdrawal_wire = chunk_offset + wire_in_chunk;
        let sighash_idx = N_DEPOSIT_INPUT_WIRES + withdrawal_wire;

        let mut wire_adaptors = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
        for val in 0..WIDE_LABEL_VALUE_COUNT {
            // Zeroth coefficient = commitment to share at reserved index
            let share_commitment = chunk_zero_coefficients[wire_in_chunk][val];
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
    let opened_input_shares =
        load_opened_input_shares(&ctx.storage, peer_id, &challenge_indices).await?;
    // ── Build selected input values (which value index per wire) ────────
    let mut selected_input: [u8; N_INPUT_WIRES] = [0; N_INPUT_WIRES];
    selected_input[..N_SETUP_INPUT_WIRES].copy_from_slice(&setup_input);
    selected_input[N_SETUP_INPUT_WIRES..N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES]
        .copy_from_slice(&deposit_inputs);
    selected_input[N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
        .copy_from_slice(&withdrawal_inputs);

    debug!(%peer_id, %index, ?selected_input, "selected input values for evaluation");

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
        header.total_gates(),
    ))
}

// ============================================================================
// Tests for the bulk-payload drain helper
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use mosaic_storage_api::table_store::{TableMetadata, TableWriter};

    use super::*;

    /// Scripted `PayloadStream` for tests. Each `read_with_timeout` call pops
    /// from the front of the queue; an empty queue returns `Closed` (FIN).
    struct ScriptedStream {
        chunks: VecDeque<StreamReply>,
    }

    enum StreamReply {
        Chunk(Vec<u8>),
        TimedOut,
    }

    impl ScriptedStream {
        fn from_chunks<I>(chunks: I) -> Self
        where
            I: IntoIterator<Item = Vec<u8>>,
        {
            Self {
                chunks: chunks.into_iter().map(StreamReply::Chunk).collect(),
            }
        }
    }

    impl PayloadStream for ScriptedStream {
        async fn read_with_timeout(
            &mut self,
            _timeout: Duration,
        ) -> Result<mosaic_net_svc_api::PayloadBuf, BulkReadError> {
            match self.chunks.pop_front() {
                Some(StreamReply::Chunk(c)) => Ok(c),
                Some(StreamReply::TimedOut) => Err(BulkReadError::TimedOut),
                // Empty queue = FIN. Build a `Closed(StreamClosed)` via the
                // PeerFinished variant which models a clean stream close.
                None => Err(BulkReadError::Closed(
                    mosaic_net_svc_api::StreamClosed::PeerFinished,
                )),
            }
        }
    }

    /// In-memory [`TableWriter`] that just records what was written. Lets us
    /// verify the helper passed every accepted ciphertext byte through to the
    /// writer in order.
    struct CollectingWriter {
        ciphertext: Vec<u8>,
        /// When set, `write_ciphertext` returns `Err` after this many calls
        /// (used to test the WriteFailed outcome).
        fail_after_calls: Option<usize>,
        calls: usize,
    }

    impl CollectingWriter {
        fn new() -> Self {
            Self {
                ciphertext: Vec::new(),
                fail_after_calls: None,
                calls: 0,
            }
        }
        fn failing_at(call: usize) -> Self {
            Self {
                ciphertext: Vec::new(),
                fail_after_calls: Some(call),
                calls: 0,
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("collecting-writer test failure")]
    struct CollectingWriterError;

    impl TableWriter for CollectingWriter {
        type Error = CollectingWriterError;

        async fn write_ciphertext(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            if let Some(threshold) = self.fail_after_calls
                && self.calls > threshold
            {
                return Err(CollectingWriterError);
            }
            self.ciphertext.extend_from_slice(data);
            Ok(())
        }

        async fn finish(
            &mut self,
            _translation: &[u8],
            _metadata: TableMetadata,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn peer() -> PeerId {
        PeerId::from_bytes([0xAB; 32])
    }
    fn idx() -> Index {
        Index::new(1).unwrap()
    }

    const TRANSLATION_SIZE: usize = 32;
    const READ_TIMEOUT: Duration = Duration::from_secs(1);
    const READ_WARN: Duration = Duration::from_secs(1);

    fn translation_input() -> Vec<u8> {
        (0..TRANSLATION_SIZE as u8).collect()
    }

    fn ciphertext_input(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(7)).collect()
    }

    #[tokio::test]
    async fn complete_on_exact_bytes_with_fin() {
        let translation = translation_input();
        let ciphertext = ciphertext_input(48);
        let mut stream = ScriptedStream::from_chunks([translation.clone(), ciphertext.clone()]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                translate_hash,
                ct_hash,
            } => {
                assert_eq!(translation_buf, translation);
                assert_eq!(translate_hash, blake3::hash(&translation));
                assert_eq!(ct_hash, blake3::hash(&ciphertext));
                assert_eq!(writer.ciphertext, ciphertext);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_ciphertext_in_later_frame_is_rejected() {
        // This is the trailing-bytes attack from the codex P2 finding: peer
        // sends exactly the expected count, then a *separate* trailing frame.
        let translation = translation_input();
        let ciphertext = ciphertext_input(48);
        let trailing = vec![0xCC; 8];
        let mut stream =
            ScriptedStream::from_chunks([translation, ciphertext.clone(), trailing.clone()]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::OversizedCiphertext { received, expected } => {
                assert_eq!(expected, ciphertext.len());
                assert_eq!(received, ciphertext.len() + trailing.len());
            }
            other => panic!("expected OversizedCiphertext, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_ciphertext_in_same_frame_is_rejected() {
        // Single chunk that includes trailing bytes past the expected count.
        let translation = translation_input();
        let mut combined = ciphertext_input(48);
        combined.extend_from_slice(&[0xDD; 4]);
        let mut stream = ScriptedStream::from_chunks([translation, combined]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            48,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        assert!(
            matches!(outcome, DrainOutcome::OversizedCiphertext { .. }),
            "expected OversizedCiphertext, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn translation_ciphertext_boundary_within_a_single_chunk() {
        // One chunk straddles the translation/ciphertext boundary: the
        // helper must hash the first `TRANSLATION_SIZE` bytes into
        // `translate_hasher` and the rest into `ct_hasher`.
        let translation = translation_input();
        let ciphertext = ciphertext_input(16);
        let mut combined = translation.clone();
        combined.extend_from_slice(&ciphertext);
        let mut stream = ScriptedStream::from_chunks([combined]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                translate_hash,
                ct_hash,
            } => {
                assert_eq!(translation_buf, translation);
                assert_eq!(translate_hash, blake3::hash(&translation));
                assert_eq!(ct_hash, blake3::hash(&ciphertext));
                assert_eq!(writer.ciphertext, ciphertext);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn translation_incomplete_when_stream_closes_early() {
        // Stream closes after partial translation.
        let mut partial = vec![0u8; TRANSLATION_SIZE - 4];
        partial[0] = 0x10;
        let mut stream = ScriptedStream::from_chunks([partial]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            16,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::TranslationIncomplete { remaining } => assert_eq!(remaining, 4),
            other => panic!("expected TranslationIncomplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn length_mismatch_when_ciphertext_short_then_close() {
        let translation = translation_input();
        let short = ciphertext_input(40);
        let mut stream = ScriptedStream::from_chunks([translation, short]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            48,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::LengthMismatch { received, expected } => {
                assert_eq!(received, 40);
                assert_eq!(expected, 48);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_failed_surfaces_writer_error() {
        let translation = translation_input();
        let ciphertext = ciphertext_input(48);
        let mut stream = ScriptedStream::from_chunks([translation, ciphertext.clone()]);
        // Fail on the very first ciphertext write call.
        let mut writer = CollectingWriter::failing_at(0);

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        assert!(
            matches!(
                outcome,
                DrainOutcome::WriteFailed {
                    during_translation_overflow: false,
                }
            ),
            "expected WriteFailed{{during_translation_overflow: false}}, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn write_failed_during_translation_overflow_keeps_discriminator() {
        // Single chunk straddling the translation/ciphertext boundary, so the
        // first ciphertext write happens inside the translation-still-remaining
        // branch. The writer is rigged to fail on that very call.
        let mut combined = translation_input();
        combined.extend_from_slice(&ciphertext_input(8));
        let mut stream = ScriptedStream::from_chunks([combined]);
        let mut writer = CollectingWriter::failing_at(0);

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            8,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        assert!(
            matches!(
                outcome,
                DrainOutcome::WriteFailed {
                    during_translation_overflow: true,
                }
            ),
            "expected WriteFailed{{during_translation_overflow: true}}, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn boundary_byte_lands_in_ciphertext_hash_not_translation() {
        // Negative-direction boundary check: put a distinctive sentinel byte
        // at the *first* ciphertext position in a chunk that straddles the
        // translation/ciphertext boundary. If `split_at(take)` were ever
        // flipped or off-by-one'd, the sentinel would leak into the
        // translation hash instead of the ciphertext hash.
        let translation = translation_input();
        let mut chunk = translation.clone();
        let sentinel: u8 = 0xAA;
        chunk.push(sentinel); // first ciphertext byte
        chunk.extend_from_slice(&[0u8; 7]); // pad to 8 bytes of ciphertext
        let expected_ct: Vec<u8> = std::iter::once(sentinel).chain([0u8; 7]).collect();

        let mut stream = ScriptedStream::from_chunks([chunk]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            8,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                translate_hash,
                ct_hash,
            } => {
                assert_eq!(translation_buf, translation);
                // Translation hash must NOT include the sentinel.
                assert_eq!(translate_hash, blake3::hash(&translation));
                // Ciphertext hash MUST include the sentinel as its first byte.
                assert_eq!(ct_hash, blake3::hash(&expected_ct));
                assert_eq!(writer.ciphertext, expected_ct);
                assert_eq!(writer.ciphertext[0], sentinel);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_timed_out_returns_timeout_outcome() {
        let translation = translation_input();
        let mut stream = ScriptedStream {
            chunks: [StreamReply::Chunk(translation), StreamReply::TimedOut]
                .into_iter()
                .collect(),
        };
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            16,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        assert!(
            matches!(outcome, DrainOutcome::ReadTimedOut),
            "expected ReadTimedOut, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn empty_chunk_terminates_loop_like_fin() {
        let translation = translation_input();
        let ciphertext = ciphertext_input(16);
        let mut stream = ScriptedStream::from_chunks([
            translation.clone(),
            ciphertext.clone(),
            Vec::new(), // empty frame = treat as FIN
        ]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                translate_hash,
                ct_hash,
            } => {
                assert_eq!(translation_buf, translation);
                assert_eq!(translate_hash, blake3::hash(&translation));
                assert_eq!(ct_hash, blake3::hash(&ciphertext));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zero_expected_ciphertext_completes_on_translation_only() {
        // Edge case: a circuit with zero AND gates produces
        // `expected_ciphertext_bytes == 0`. Stream sends only translation
        // bytes followed by FIN; the helper must accept it.
        let translation = translation_input();
        let mut stream = ScriptedStream::from_chunks([translation.clone()]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            0,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                ct_hash,
                ..
            } => {
                assert_eq!(translation_buf, translation);
                assert_eq!(ct_hash, blake3::hash(b""));
                assert!(writer.ciphertext.is_empty());
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zero_expected_ciphertext_rejects_any_trailing_bytes() {
        let mut combined = translation_input();
        combined.push(0xFF); // one extra byte past translation
        let mut stream = ScriptedStream::from_chunks([combined]);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            0,
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::OversizedCiphertext { received, expected } => {
                assert_eq!(received, 1);
                assert_eq!(expected, 0);
            }
            other => panic!("expected OversizedCiphertext, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn many_small_chunks_accumulate_correctly() {
        let translation = translation_input();
        let ciphertext = ciphertext_input(64);
        // Break each into 4-byte pieces to stress the chunk-handling loop.
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        for c in translation.chunks(4) {
            chunks.push(c.to_vec());
        }
        for c in ciphertext.chunks(4) {
            chunks.push(c.to_vec());
        }
        let mut stream = ScriptedStream::from_chunks(chunks);
        let mut writer = CollectingWriter::new();

        let outcome = drain_table_payload(
            &mut stream,
            &mut writer,
            TRANSLATION_SIZE,
            ciphertext.len(),
            READ_TIMEOUT,
            READ_WARN,
            &peer(),
            idx(),
        )
        .await;

        match outcome {
            DrainOutcome::Complete {
                translation_buf,
                translate_hash,
                ct_hash,
            } => {
                assert_eq!(translation_buf, translation);
                assert_eq!(translate_hash, blake3::hash(&translation));
                assert_eq!(ct_hash, blake3::hash(&ciphertext));
                assert_eq!(writer.ciphertext, ciphertext);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }
}

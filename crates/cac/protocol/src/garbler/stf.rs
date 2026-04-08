use std::pin::pin;

use futures::StreamExt;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingSeeds, AllOutputLabelCts, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgHeader, CircuitInputShares, CircuitOutputShare, CommitMsgHeader, DepositId,
    EvalGarblingSeeds, EvaluationIndices, GarblingTableCommitment, HeapArray, Index,
    OpenedGarblingSeeds, OpenedOutputShares, OutputShares, ReservedSetupInputShares, Seed,
    state_machine::garbler::*,
};
use mosaic_common::constants::{
    N_CIRCUITS, N_INPUT_WIRES, SEED_CONTEXT_GENERATE_GARBLING_TABLE_SEEDS,
    SEED_CONTEXT_GENERATE_POLYNOMIAL,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{debug, error, info, warn};

use super::emit;
use crate::{
    ResultOptionExt, SMError, SMResult,
    common::{derive_stage_seed, get_eval_commitments, get_eval_indices},
};

// ============================================================================
// External event handler
// ============================================================================

/// Handle an external event input (delivered via [`fasm::Input::Normal`]).
///
/// External events are messages from peers, bridge triggers, and initialization
/// — anything that originates outside the state machine.
pub(crate) async fn handle_event<S: StateMut>(
    state: &mut S,
    input: Input,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let mut root_state = state
        .get_root_state()
        .await
        .map_err(SMError::storage)?
        .unwrap_or_default();

    match input {
        Input::Init(data) => {
            match root_state.step {
                Step::Uninit => {
                    info!("garbler init: generating polynomial commitments");

                    // state update
                    root_state.config = Some(Config {
                        seed: data.seed,
                        setup_inputs: data.setup_inputs,
                    });

                    // Polynomial generation + commitment is handled entirely
                    // by the job handler. Polynomials are cached job-side for
                    // the subsequent GenerateShares calls.
                    root_state.step = Step::GeneratingPolynomialCommitments {
                        inputs: HeapArray::from_elem(false),
                        output: false,
                    };

                    // All input and output polynomials are generated from
                    // mutating rng initialized with stage seed
                    let stage_seed = generate_polynomial_seed(data.seed);

                    emit(
                        actions,
                        Action::GeneratePolynomialCommitments(stage_seed, Wire::Output),
                    );
                    for wire_idx in 0..N_INPUT_WIRES {
                        emit(
                            actions,
                            Action::GeneratePolynomialCommitments(
                                stage_seed,
                                Wire::Input(wire_idx as u16),
                            ),
                        );
                    }
                }
                _ => {
                    warn!(
                        step = root_state.step.step_name(),
                        "garbler init in unexpected step"
                    );
                    return Err(SMError::unexpected_input());
                }
            }
        }
        Input::RecvChallengeMsg(challenge_msg) => match root_state.step {
            // Final commit chunk ack and challenge message is sent in same step by evaluator, so
            // allow challenge to be received early if it is valid.
            Step::SendingCommit { .. } | Step::WaitingForChallenge => {
                if is_valid_challenge(&challenge_msg) {
                    info!("garbler received valid challenge, sending response");

                    let reserved_setup_input_shares = state
                        .get_reserved_setup_input_shares()
                        .await
                        .require("expected reserved setup input shares")?;
                    let output_shares = state
                        .get_output_shares()
                        .await
                        .require("expected output shares")?;
                    let config = require_config(&root_state)?;
                    let seeds = generate_garbling_table_seeds(config.seed);

                    let all_output_label_cts = state
                        .get_all_output_label_cts()
                        .await
                        .require("expected garbling table metadata")?;

                    let challenge_indices = challenge_msg.challenge_indices;

                    let header = create_challenge_response_msg_header(
                        &challenge_indices,
                        reserved_setup_input_shares,
                        &output_shares,
                        seeds,
                        all_output_label_cts,
                    );
                    state
                        .put_challenge_indices(&challenge_indices)
                        .await
                        .map_err(SMError::storage)?;

                    root_state.step = Step::SendingChallengeResponse {
                        header_acked: false,
                        chunk_acked: HeapArray::from_elem(false),
                    };

                    emit(actions, Action::SendChallengeResponseMsgHeader(header));
                    for circuit_idx in challenge_indices {
                        emit(actions, Action::SendChallengeResponseMsgChunk(circuit_idx));
                    }
                } else {
                    warn!("garbler received invalid challenge, aborting");
                    root_state.step = Step::Aborted {
                        reason: "invalid challenge msg".into(),
                    };
                }
            }
            // ack on all steps after WaitingForChallenge
            step if step.phase() > StepPhase::WaitingForChallenge => {
                warn!("garbler received challenge after completion, ack and ignore");
                return Ok(());
            }
            _ => return Err(SMError::unexpected_input()),
        },
        Input::RecvTableTransferRequest(request_msg) => match &root_state.step {
            Step::TransferringGarblingTables {
                eval_seeds,
                eval_commitments,
                transferred: _,
            } => {
                // Note: Not checking for already transferred tables here.
                // Evaluator can request same table multiple times until it has notified that all
                // tables have been read.

                let Some((seed, _commitment)) =
                    eval_seeds
                        .iter()
                        .zip(eval_commitments)
                        .find(|(_seed, commitment)| {
                            commitment == &&request_msg.garbling_table_commitment
                        })
                else {
                    error!(commitment = %request_msg.garbling_table_commitment, "Got table transfer request for invalid table commitment");
                    return Err(SMError::invalid_input_data());
                };

                // Only begin table transfer after getting request from evaluator.
                debug!(commitment = %request_msg.garbling_table_commitment, "garbler received table transfer request");
                emit(actions, Action::TransferGarblingTable(*seed));
            }
            step if step.phase() > StepPhase::TransferringGarblingTables => {
                warn!("garbler received table transfer request after completion, ack and ignore");
                return Ok(());
            }
            _ => return Err(SMError::unexpected_input()),
        },
        Input::RecvTableTransferReceipt(receipt_msg) => match &mut root_state.step {
            Step::TransferringGarblingTables {
                eval_commitments,
                transferred,
                ..
            } => {
                let Some((pos, _commitment)) =
                    eval_commitments
                        .iter()
                        .enumerate()
                        .find(|(_pos, commitment)| {
                            commitment == &&receipt_msg.garbling_table_commitment
                        })
                else {
                    error!(commitment = %receipt_msg.garbling_table_commitment, "Got table transfer receipt for invalid table commitment");
                    return Err(SMError::invalid_input_data());
                };

                transferred[pos] = true;
                debug!(
                    pos,
                    done = transferred.count_ones(),
                    total = transferred.len(),
                    "garbler received table transfer receipt"
                );

                if transferred.all() {
                    info!("all garbling tables transferred, setup complete");
                    root_state.step = Step::SetupComplete;
                }
            }
            step if step.phase() > StepPhase::TransferringGarblingTables => {
                warn!("garbler received table transfer receipt after completion, ack and ignore");
                return Ok(());
            }
            _ => return Err(SMError::unexpected_input()),
        },
        Input::DepositInit(
            deposit_id,
            GarblerDepositInitData {
                pk,
                sighashes,
                deposit_inputs,
            },
        ) => match root_state.step {
            Step::SetupComplete => {
                if state
                    .get_deposit(&deposit_id)
                    .await
                    .map_err(SMError::storage)?
                    .is_some()
                {
                    warn!(%deposit_id, "garbler deposit already exists");
                    return Err(SMError::deposit_already_exists(deposit_id));
                }

                info!(%deposit_id, "garbler initializing deposit");
                let deposit_state = DepositState {
                    step: DepositStep::WaitingForAdaptors {
                        chunks: HeapArray::from_elem(false),
                    },
                    pk,
                };

                state
                    .put_sighashes_for_deposit(&deposit_id, &sighashes)
                    .await
                    .map_err(SMError::storage)?;
                state
                    .put_inputs_for_deposit(&deposit_id, &deposit_inputs)
                    .await
                    .map_err(SMError::storage)?;

                state
                    .put_deposit(deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;
            }
            _ => return Err(SMError::unexpected_input()),
        },
        Input::DepositRecvAdaptorMsgChunk(deposit_id, adaptor_msg_chunk) => {
            handle_recv_deposit_adaptor_msg_chunk(
                &mut root_state,
                state,
                deposit_id,
                adaptor_msg_chunk,
                actions,
            )
            .await?;
        }
        Input::DepositUndisputedWithdrawal(deposit_id) => match root_state.step {
            Step::SetupComplete => {
                let mut deposit_state = require_deposit(state, &deposit_id).await?;

                match &mut deposit_state.step {
                    DepositStep::DepositReady => {
                        info!(%deposit_id, "garbler deposit undisputed withdrawal");
                        deposit_state.step = DepositStep::WithdrawnUndisputed;
                    }
                    _ => return Err(SMError::unexpected_input()),
                }

                state
                    .put_deposit(deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;
            }
            _ => return Err(SMError::unexpected_input()),
        },
        Input::DisputedWithdrawal(deposit_id, withdrawal_input) => {
            match &mut root_state.step {
                Step::SetupComplete => {
                    let mut deposit_state = require_deposit(state, &deposit_id).await?;

                    match &mut deposit_state.step {
                        DepositStep::DepositReady => {
                            info!(%deposit_id, "garbler disputed withdrawal, completing adaptors");
                            // next step
                            root_state.step = Step::CompletingAdaptors { deposit_id };

                            state
                                .put_withdrawal_input(&deposit_id, &withdrawal_input)
                                .await
                                .map_err(SMError::storage)?;

                            emit(actions, Action::CompleteAdaptorSignatures(deposit_id));
                        }
                        _ => return Err(SMError::unexpected_input()),
                    }

                    state
                        .put_deposit(deposit_id, &deposit_state)
                        .await
                        .map_err(SMError::storage)?;
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
    };

    state
        .put_root_state(&root_state)
        .await
        .map_err(SMError::storage)?;

    Ok(())
}

// ============================================================================
// Action result handler
// ============================================================================

/// Handle a tracked action completion (delivered via
/// [`fasm::Input::TrackedActionCompleted`]).
///
/// Each action emitted by the STF eventually completes and its result is
/// routed back here with the [`ActionId`] used to correlate it.
pub(crate) async fn handle_action_result<S: StateMut>(
    state: &mut S,
    id: ActionId,
    result: ActionResult,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let mut root_state = state
        .get_root_state()
        .await
        .map_err(SMError::storage)?
        .unwrap_or_default();

    match result {
        ActionResult::PolynomialCommitmentsGenerated(generated) => {
            handle_polynomial_commitments_generated(&mut root_state, state, generated, actions)
                .await?;
        }
        ActionResult::SharesGenerated(index, input_shares, output_share) => {
            handle_shares_generated(
                &mut root_state,
                state,
                index,
                input_shares,
                output_share,
                actions,
            )
            .await?;
        }
        ActionResult::TableCommitmentGenerated(index, commitment, metadata) => {
            handle_table_commitment_generated(
                &mut root_state,
                state,
                index,
                commitment,
                metadata,
                actions,
            )
            .await?;
        }
        ActionResult::CommitMsgHeaderAcked => {
            match &mut root_state.step {
                Step::SendingCommit {
                    chunk_acked,
                    header_acked: header,
                } => {
                    let ActionId::SendCommitMsgHeader = id else {
                        return Err(SMError::invalid_input_data());
                    };

                    if *header {
                        // already acked header
                        return Err(SMError::duplicate_action());
                    }

                    *header = true;
                    debug!("garbler commit msg header acked");

                    if chunk_acked.all() {
                        info!("all commit msg parts acked, waiting for challenge");
                        root_state.step = Step::WaitingForChallenge;
                    }
                }
                step if step.phase() > StepPhase::SendingCommit => {
                    warn!("garbler received commit header ack after completion, ignore");
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        ActionResult::CommitMsgChunkAcked => {
            match &mut root_state.step {
                Step::SendingCommit {
                    chunk_acked: acked,
                    header_acked: header,
                } => {
                    let ActionId::SendCommitMsgChunk(wire_index) = id else {
                        return Err(SMError::invalid_input_data());
                    };
                    let idx = wire_index as usize;
                    if acked[idx] {
                        // already acked this chunk
                        return Err(SMError::duplicate_action());
                    }

                    acked[idx] = true;
                    debug!(
                        wire_index,
                        done = acked.count_ones(),
                        total = acked.len(),
                        "garbler commit msg chunk acked"
                    );

                    if *header && acked.all() {
                        info!("all commit msg parts acked, waiting for challenge");
                        root_state.step = Step::WaitingForChallenge;
                    }
                }
                step if step.phase() > StepPhase::SendingCommit => {
                    warn!("garbler received commit chunk ack after completion, ignore");
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }

        ActionResult::ChallengeResponseHeaderAcked => {
            match &mut root_state.step {
                Step::SendingChallengeResponse {
                    chunk_acked,
                    header_acked,
                } => {
                    if *header_acked {
                        // already acked this chunk
                        return Err(SMError::invalid_input_data());
                    }

                    *header_acked = true;
                    debug!("garbler challenge response header acked");

                    if chunk_acked.all() {
                        handle_post_sending_challenge_response(&mut root_state, state, actions)
                            .await?;
                    }
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }

        ActionResult::ChallengeResponseChunkAcked => {
            match &mut root_state.step {
                Step::SendingChallengeResponse {
                    chunk_acked,
                    header_acked,
                } => {
                    let ActionId::SendChallengeResponseMsgChunk(circuit_index) = id else {
                        return Err(SMError::invalid_input_data());
                    };
                    let challenge_indices = state
                        .get_challenge_indices()
                        .await
                        .require("expected challenge indices")?;
                    let challenge_index_pos = challenge_indices
                        .iter()
                        .position(|x| x.get() == circuit_index as usize)
                        .ok_or(SMError::StateInconsistency(format!("Circuit index differs from one present in current state {circuit_index}")))?;
                    if chunk_acked[challenge_index_pos] {
                        // already acked this chunk
                        return Err(SMError::invalid_input_data());
                    }

                    chunk_acked[challenge_index_pos] = true;
                    debug!(
                        circuit_index,
                        done = chunk_acked.count_ones(),
                        total = chunk_acked.len(),
                        "garbler challenge response chunk acked"
                    );

                    if *header_acked && chunk_acked.all() {
                        handle_post_sending_challenge_response(&mut root_state, state, actions)
                            .await?;
                    }
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        ActionResult::GarblingTableTransferred(garbling_seed, commitment) => {
            match &mut root_state.step {
                Step::TransferringGarblingTables {
                    eval_seeds,
                    eval_commitments,
                    ..
                } => {
                    let Some(index) = eval_seeds.iter().enumerate().find_map(|(idx, seed)| {
                        if seed == &garbling_seed {
                            Some(idx)
                        } else {
                            None
                        }
                    }) else {
                        return Err(SMError::invalid_input_data());
                    };

                    if eval_commitments[index] != commitment {
                        return Err(SMError::invalid_input_data());
                    }

                    // Informational only. We mark a table as transferred once we get corresponding
                    // [`TableTransferReceiptMsg`](mosaic_cac_types::TableTransferReceiptMsg) from
                    // evaluator.
                    info!(%commitment, "garbling table transferred")
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }

        ActionResult::DepositAdaptorVerificationResult(deposit_id, verification_success) => {
            match root_state.step {
                Step::SetupComplete => {
                    let mut deposit_state = require_deposit(state, &deposit_id).await?;
                    match &mut deposit_state.step {
                        DepositStep::VerifyingAdaptors => {
                            if verification_success {
                                info!(%deposit_id, "garbler adaptor verification succeeded, deposit ready");
                                deposit_state.step = DepositStep::DepositReady;
                            } else {
                                warn!(%deposit_id, "garbler adaptor verification failed, aborting deposit");
                                deposit_state.step = DepositStep::Aborted {
                                    reason: "adaptor verification failed".into(),
                                };
                            }
                        }
                        _ => return Err(SMError::unexpected_input()),
                    }
                    state
                        .put_deposit(deposit_id, &deposit_state)
                        .await
                        .map_err(SMError::storage)?;
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        ActionResult::AdaptorSignaturesCompleted(signature_deposit_id, signatures) => {
            match root_state.step {
                Step::CompletingAdaptors { deposit_id } => {
                    // just in case
                    if signature_deposit_id != deposit_id {
                        return Err(SMError::unexpected_input());
                    }

                    state
                        .put_completed_signatures(&deposit_id, &signatures)
                        .await
                        .map_err(SMError::storage)?;

                    info!(%deposit_id, "garbler adaptor signatures completed, setup consumed");
                    // next step
                    root_state.step = Step::SetupConsumed { deposit_id };
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
    };

    state
        .put_root_state(&root_state)
        .await
        .map_err(SMError::storage)?;

    Ok(())
}

// ============================================================================
// Deposit adaptor chunk handler (helper for handle_event)
// ============================================================================

async fn handle_polynomial_commitments_generated<S: StateMut>(
    root_state: &mut GarblerState,
    state: &mut S,
    generated: GeneratedPolynomialCommitments,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::GeneratingPolynomialCommitments { inputs, output } => {
            match generated {
                GeneratedPolynomialCommitments::Input { wire, commitments } => {
                    let Some(&seen) = inputs.get(wire as usize) else {
                        return Err(SMError::invalid_input_data());
                    };
                    if seen {
                        // already seen
                        return Err(SMError::duplicate_action());
                    }
                    inputs[wire as usize] = true;
                    debug!(
                        wire,
                        done = inputs.count_ones(),
                        total = inputs.len(),
                        "polynomial commitment generated (input)"
                    );
                    state
                        .put_input_polynomial_commitments_chunk(wire, &commitments)
                        .await
                        .map_err(SMError::storage)?;
                }
                GeneratedPolynomialCommitments::Output(output_commitment) => {
                    if *output {
                        // already seen
                        return Err(SMError::duplicate_action());
                    }
                    *output = true;
                    debug!("polynomial commitment generated (output)");
                    state
                        .put_output_polynomial_commitment(&output_commitment)
                        .await
                        .map_err(SMError::storage)?;
                }
            }

            if !*output || !inputs.all() {
                // not all commitments saved, continue
                return Ok(());
            }
            // all commitments generated; go to next step
            let config = require_config(root_state)?;
            let stage_seed = generate_polynomial_seed(config.seed);
            // NOTE: 0 is reserved index
            emit(
                actions,
                Action::GenerateShares(stage_seed, Index::reserved()),
            );
            for idx in 1..N_CIRCUITS + 1 {
                let index = Index::new(idx).expect("valid ckt index");
                emit(actions, Action::GenerateShares(stage_seed, index));
            }
            info!("all polynomial commitments generated, generating shares");
            root_state.step = Step::GeneratingShares {
                generated: HeapArray::from_elem(false),
            };
        }
        _ => return Err(SMError::unexpected_input()),
    };
    Ok(())
}

async fn handle_shares_generated<S: StateMut>(
    root_state: &mut GarblerState,
    state: &mut S,
    index: Index,
    input_shares: CircuitInputShares,
    output_share: CircuitOutputShare,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::GeneratingShares { generated } => {
            if generated[index.get()] {
                // already have this data
                return Err(SMError::duplicate_action());
            }

            // state update
            generated[index.get()] = true;
            debug!(%index, done = generated.count_ones(), total = generated.len(), "shares generated");
            state
                .put_shares_for_index(index, &input_shares, &output_share)
                .await
                .map_err(SMError::storage)?;

            if !generated.all() {
                // not all shares generated
                return Ok(());
            }
            // all shares generate; go to next step

            let config = require_config(root_state)?;
            let seeds = generate_garbling_table_seeds(config.seed);

            // generate actions
            for (tracker_idx, seed) in seeds.iter().enumerate() {
                // NOTE: ckt index and tracker index offset by 1
                let index = Index::new(tracker_idx + 1).expect("valid index");
                emit(actions, Action::GenerateTableCommitment(index, *seed));
            }

            info!("all shares generated, generating table commitments");
            root_state.step = Step::GeneratingTableCommitments {
                seeds,
                generated: HeapArray::from_elem(false),
            };
        }
        _ => return Err(SMError::unexpected_input()),
    };
    Ok(())
}

async fn handle_table_commitment_generated<S: StateMut>(
    root_state: &mut GarblerState,
    state: &mut S,
    index: Index,
    commitment: GarblingTableCommitment,
    metadata: GarblingMetadata,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::GeneratingTableCommitments { generated, .. } => {
            let idx = index.get().checked_sub(1).ok_or_else(|| {
                // not expecting reserved (0) index
                SMError::invalid_input_data()
            })?;
            if generated[idx] {
                // already have this data
                return Err(SMError::duplicate_action());
            }

            // state update
            generated[idx] = true;
            debug!(%index, done = generated.count_ones(), total = generated.len(), "table commitment generated");
            state
                .put_garbling_table_commitment(index, &commitment)
                .await
                .map_err(SMError::storage)?;
            state
                .put_garbling_table_metadata(index, &metadata)
                .await
                .map_err(SMError::storage)?;

            if !generated.all() {
                // wait for all commitments to be generated.
                return Ok(());
            }
            info!("all table commitments generated, sending commit msg");
            root_state.step = Step::SendingCommit {
                header_acked: false,
                chunk_acked: HeapArray::from_elem(false),
            };

            // generate actions
            let header = build_commit_msg_header(state).await?;
            emit(actions, Action::SendCommitMsgHeader(header));

            for wire in 0..N_INPUT_WIRES {
                emit(actions, Action::SendCommitMsgChunk(wire as u16));
            }
        }
        _ => return Err(SMError::unexpected_input()),
    };

    Ok(())
}

async fn handle_recv_deposit_adaptor_msg_chunk<S: StateMut>(
    root_state: &mut GarblerState,
    state: &mut S,
    deposit_id: DepositId,
    adaptor_msg_chunk: AdaptorMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::SetupComplete => {
            if adaptor_msg_chunk.deposit_id != deposit_id {
                return Err(SMError::invalid_input_data());
            }

            let mut deposit_state = require_deposit(state, &deposit_id).await?;

            let all_chunks_received = {
                let DepositStep::WaitingForAdaptors { chunks } = &mut deposit_state.step else {
                    // WaitingForAdaptors is first step of deposit state machine. All other steps
                    // are after it.
                    warn!("garbler received adaptor chunk after completion, ack and ignore");
                    return Ok(());
                };

                let chunk_idx = adaptor_msg_chunk.chunk_index as usize;

                if chunks[chunk_idx] {
                    warn!("garbler received duplicate adaptor chunk, ack and ignore");
                    return Ok(());
                }

                state
                    .put_adaptor_msg_chunk_for_deposit(&deposit_id, &adaptor_msg_chunk)
                    .await
                    .map_err(SMError::storage)?;

                chunks[chunk_idx] = true;
                debug!(%deposit_id, chunk_idx, done = chunks.count_ones(), total = chunks.len(), "adaptor chunk received");

                chunks.all()
            };

            if all_chunks_received {
                info!(%deposit_id, "all adaptor chunks received, verifying");
                deposit_state.step = DepositStep::VerifyingAdaptors;
                emit(actions, Action::DepositVerifyAdaptors(deposit_id));
            }

            state
                .put_deposit(deposit_id, &deposit_state)
                .await
                .map_err(SMError::storage)?;

            if !all_chunks_received {
                // stay on same step and wait for more
                debug!("waiting for adaptor chunks");
                return Ok(());
            }
        }
        step if step.phase() > StepPhase::SetupComplete => {
            warn!("garbler received adaptor chunk after completion, ack and ignore");
            return Ok(());
        }

        _ => return Err(SMError::unexpected_input()),
    };

    Ok(())
}

// ============================================================================
// Restore
// ============================================================================

pub(crate) async fn restore<S: StateRead>(
    state: &S,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let root_state = state
        .get_root_state()
        .await
        .map_err(SMError::storage)?
        .unwrap_or_default();

    info!(
        step = root_state.step.step_name(),
        "garbler restoring state"
    );

    match &root_state.step {
        Step::Uninit => {}
        Step::GeneratingPolynomialCommitments { inputs, output } => {
            let config = require_config(&root_state)?;
            let stage_seed = generate_polynomial_seed(config.seed);
            if !output {
                emit(
                    actions,
                    Action::GeneratePolynomialCommitments(stage_seed, Wire::Output),
                );
            }
            for (wire_idx, generated) in inputs.iter().enumerate() {
                if *generated {
                    continue;
                }
                emit(
                    actions,
                    Action::GeneratePolynomialCommitments(stage_seed, Wire::Input(wire_idx as u16)),
                );
            }
        }
        Step::GeneratingShares { generated } => {
            let config = require_config(&root_state)?;
            let stage_seed = generate_polynomial_seed(config.seed);
            for idx in 0..N_CIRCUITS + 1 {
                if generated[idx] {
                    continue;
                }
                let index = if idx == 0 {
                    Index::reserved()
                } else {
                    Index::new(idx).expect("valid index")
                };
                emit(actions, Action::GenerateShares(stage_seed, index));
            }
        }
        Step::GeneratingTableCommitments { seeds, generated } => {
            for idx in 0..N_CIRCUITS {
                if generated[idx] {
                    continue;
                }
                let index = Index::new(idx + 1).expect("valid index");
                let seed = seeds[idx];
                emit(actions, Action::GenerateTableCommitment(index, seed));
            }
        }
        Step::SendingCommit {
            chunk_acked,
            header_acked,
        } => {
            if !header_acked {
                let header = build_commit_msg_header(state).await?;
                emit(actions, Action::SendCommitMsgHeader(header));
            }
            for wire in 0..N_INPUT_WIRES {
                if !chunk_acked[wire] {
                    emit(actions, Action::SendCommitMsgChunk(wire as u16));
                }
            }
        }
        Step::WaitingForChallenge => {}
        Step::SendingChallengeResponse {
            chunk_acked,
            header_acked,
        } => {
            let challenge_indices = state
                .get_challenge_indices()
                .await
                .require("expected challenge indices")?;
            let reserved_setup_input_shares = state
                .get_reserved_setup_input_shares()
                .await
                .require("expected reserved setup input shares")?;
            let output_shares = state
                .get_output_shares()
                .await
                .require("expected output shares")?;
            let config = require_config(&root_state)?;
            let seeds = generate_garbling_table_seeds(config.seed);

            let all_output_label_cts = state
                .get_all_output_label_cts()
                .await
                .require("expected garbling table metadata")?;

            let header = create_challenge_response_msg_header(
                &challenge_indices,
                reserved_setup_input_shares,
                &output_shares,
                seeds,
                all_output_label_cts,
            );

            if !*header_acked {
                emit(actions, Action::SendChallengeResponseMsgHeader(header));
            }

            for (index, acked) in challenge_indices.iter().zip(chunk_acked.iter()) {
                if !acked {
                    emit(actions, Action::SendChallengeResponseMsgChunk(*index));
                }
            }
        }
        Step::TransferringGarblingTables { .. } => {
            // NOTE: we dont automatically start transferring garbling tables, but wait for
            // corresponding [`TableTransferRequestMsg`](mosaic_cac_types::TableTransferRequestMsg)
            // from evaluator to begin transfer.
        }
        Step::SetupComplete => {
            let mut all_deposits = pin!(state.stream_all_deposits());
            while let Some(res) = all_deposits.next().await {
                let (deposit_id, deposit_state) = res.map_err(SMError::storage)?;
                match &deposit_state.step {
                    DepositStep::WaitingForAdaptors { .. } => {}
                    DepositStep::VerifyingAdaptors => {
                        emit(actions, Action::DepositVerifyAdaptors(deposit_id));
                    }
                    DepositStep::DepositReady => {}
                    DepositStep::WithdrawnUndisputed => {}
                    DepositStep::Aborted { .. } => {}
                }
            }
        }
        Step::CompletingAdaptors { deposit_id } => {
            let deposit_state = state
                .get_deposit(deposit_id)
                .await
                .require("CompletingAdaptors: missing expected deposit")?;

            if !matches!(&deposit_state.step, DepositStep::DepositReady) {
                return Err(SMError::state_inconsistency(
                    "CompletingAdaptors: unexpected deposit state",
                ));
            }

            emit(actions, Action::CompleteAdaptorSignatures(*deposit_id));
        }
        Step::SetupConsumed { .. } => {}
        Step::Aborted { .. } => {}
    };

    Ok(())
}

async fn handle_post_sending_challenge_response<S: StateMut>(
    root_state: &mut GarblerState,
    state: &mut S,
    _actions: &mut ActionContainer,
) -> SMResult<()> {
    let challenge_indices = state
        .get_challenge_indices()
        .await
        .require("expected challenge indices")?;
    let eval_indices = get_eval_indices(&challenge_indices);

    let garbling_table_commitments = state
        .get_all_garbling_table_commitments()
        .await
        .require("expected garbling table commitments")?;

    let eval_commitments = get_eval_commitments(&eval_indices, &garbling_table_commitments);

    let config = require_config(root_state)?;
    let garbling_seeds = generate_garbling_table_seeds(config.seed);
    let eval_seeds = get_eval_seeds(&eval_indices, &garbling_seeds);

    // NOTE: we dont automatically start transferring garbling tables, but wait for corresponding
    // [`TableTransferRequestMsg`](mosaic_cac_types::TableTransferRequestMsg) from evaluator to
    // begin transfer.
    info!(
        eval_count = eval_seeds.len(),
        "challenge response complete, ready for table transfers"
    );
    root_state.step = Step::TransferringGarblingTables {
        eval_seeds,
        eval_commitments,
        transferred: HeapArray::from_elem(false),
    };

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

fn require_config(state: &GarblerState) -> SMResult<&Config> {
    state
        .config
        .as_ref()
        .ok_or_else(|| SMError::state_inconsistency("expected config to not be None"))
}

async fn require_deposit<S: StateRead>(
    state: &S,
    deposit_id: &DepositId,
) -> SMResult<DepositState> {
    state
        .get_deposit(deposit_id)
        .await
        .map_err(SMError::storage)?
        .ok_or_else(|| SMError::unknown_deposit(*deposit_id))
}

async fn build_commit_msg_header<S: StateRead>(state: &S) -> SMResult<CommitMsgHeader> {
    let output_polynomial_commitment = state
        .get_output_polynomial_commitment()
        .await
        .require("expected output polynomial commitment")?;
    let garbling_table_commitments = state
        .get_all_garbling_table_commitments()
        .await
        .require("expected garbling table commitments")?;
    let all_aes128_keys = state
        .get_all_aes128_keys()
        .await
        .require("expected all aes128 keys")?;
    let all_public_s = state
        .get_all_public_s_values()
        .await
        .require("expected all public_s values")?;
    let all_constant_zero_labels = state
        .get_all_constant_zero_labels()
        .await
        .require("expected all constant zero labels")?;
    let all_constant_one_labels = state
        .get_all_constant_one_labels()
        .await
        .require("expected all constant one labels")?;

    Ok(CommitMsgHeader {
        garbling_table_commitments,
        output_polynomial_commitment,
        all_aes128_keys,
        all_public_s,
        all_constant_zero_labels,
        all_constant_one_labels,
    })
}

fn generate_polynomial_seed(base_seed: Seed) -> Seed {
    derive_stage_seed(base_seed, SEED_CONTEXT_GENERATE_POLYNOMIAL, None)
}

fn generate_garbling_table_seeds(base_seed: Seed) -> AllGarblingSeeds {
    let stage_seed = derive_stage_seed(base_seed, SEED_CONTEXT_GENERATE_GARBLING_TABLE_SEEDS, None);
    let mut rng = ChaCha20Rng::from_seed(stage_seed.into()); // modify base seed ?
    let garbling_seeds = (0..N_CIRCUITS)
        .map(|_| {
            let mut bytes: [u8; 32] = [0; 32];
            rng.fill_bytes(&mut bytes);
            Seed::from(bytes)
        })
        .collect::<Vec<_>>();
    HeapArray::from_vec(garbling_seeds)
}

/// challenge indices must be in range, must not include 0, etc
fn is_valid_challenge(challenge: &ChallengeMsg) -> bool {
    !challenge
        .challenge_indices
        .iter()
        .any(|x| *x == Index::reserved())
    // does not include reserved index
    // ChallengeMsg in itself includes `Index` struct which can only be initialized within valid
    // bounds so the range check is done during deserialization itself
}

fn create_challenge_response_msg_header(
    challenge_idxs: &ChallengeIndices,
    reserved_setup_input_shares: ReservedSetupInputShares,
    all_output_shares: &OutputShares,
    garbling_seeds: AllGarblingSeeds,
    all_output_label_cts: AllOutputLabelCts,
) -> ChallengeResponseMsgHeader {
    let eval_indices = get_eval_indices(challenge_idxs);

    // evaluate the output false polynomial at the challenge indices
    let opened_output_shares: OpenedOutputShares = HeapArray::from_vec(
        challenge_idxs
            .map(|idx| all_output_shares[idx.get()])
            .to_vec(),
    );

    // opened garbling seeds
    let opened_garbling_seeds: OpenedGarblingSeeds = HeapArray::from_vec(
        challenge_idxs
            // challenge index i+1 corresponds to i_th entry in self.garbling_seeds
            // therefore subtract by 1 here; better way ? maybe GC tables should be stored as map
            // from Index to Value as the data structure can not be indexed in the
            // conventional array sense
            .map(|idx| garbling_seeds[idx.get() - 1])
            .to_vec(),
    );

    let unchallenged_output_label_cts = HeapArray::from_vec(
        eval_indices
            .iter()
            .map(|i| all_output_label_cts[i.get() - 1])
            .collect(),
    );

    ChallengeResponseMsgHeader {
        reserved_setup_input_shares,
        opened_output_shares,
        opened_garbling_seeds,
        unchallenged_output_label_cts,
    }
}

fn get_eval_seeds(
    eval_indices: &EvaluationIndices,
    garbling_seeds: &AllGarblingSeeds,
) -> EvalGarblingSeeds {
    HeapArray::new(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_seeds are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_seeds[seed_idx]
    })
}

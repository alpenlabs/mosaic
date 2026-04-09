use std::pin::pin;

use futures::StreamExt;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk, CommitMsgHeader,
    CompletedSignatures, DepositAdaptors, DepositId, GarblingTableCommitment, HeapArray, Index,
    OpenedGarblingTableCommitments, PubKey, ReservedSetupInputShares, Seed, SetupInputs,
    TableTransferReceiptMsg, WideLabelWirePolynomialCommitments,
    WideLabelZerothPolynomialCoefficients, WithdrawalAdaptors, WithdrawalAdaptorsChunk,
    WithdrawalInputs, state_machine::evaluator::*,
};
use mosaic_common::constants::{
    N_ADAPTOR_MSG_CHUNKS, N_CHALLENGE_RESPONSE_CHUNKS, N_CIRCUITS, N_DEPOSIT_INPUT_WIRES,
    N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES,
    SEED_CONTEXT_SAMPLE_CHALLENGE_INDICES, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK, WideLabelValue,
};
use mosaic_vs3::{Share, interpolate};
use rand::SeedableRng;
use tracing::{debug, info, warn};

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
        Input::Init(data) => match root_state.step {
            Step::Uninit => {
                info!("evaluator init: waiting for commit");
                root_state.config = Some(Config {
                    seed: data.seed,
                    setup_inputs: data.setup_inputs,
                });
                root_state.step = Step::WaitingForCommit {
                    header: false,
                    chunks: HeapArray::from_elem(false),
                };
            }
            _ => {
                warn!(
                    step = root_state.step.step_name(),
                    "evaluator init in unexpected step"
                );
                return Err(SMError::UnexpectedInput);
            }
        },
        Input::RecvCommitMsgHeader(commit_msg_header) => {
            handle_commit_msg_header(&mut root_state, state, commit_msg_header, actions).await?;
        }
        Input::RecvCommitMsgChunk(commit_msg) => {
            handle_commit_msg_chunk(&mut root_state, state, commit_msg, actions).await?;
        }
        Input::RecvChallengeResponseMsgHeader(response_msg_header) => {
            handle_recv_challenge_response_header(
                &mut root_state,
                state,
                response_msg_header,
                actions,
            )
            .await?;
        }
        Input::RecvChallengeResponseMsgChunk(response_msg) => {
            handle_recv_challenge_response_msg(&mut root_state, state, response_msg, actions)
                .await?;
        }
        Input::DepositInit(
            deposit_id,
            EvaluatorDepositInitData {
                sk,
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
                    warn!(%deposit_id, "evaluator deposit already exists");
                    return Err(SMError::deposit_already_exists(deposit_id));
                }

                info!(%deposit_id, "evaluator initializing deposit, generating adaptors");
                let deposit_state = DepositState {
                    step: DepositStep::GeneratingAdaptors {
                        deposit: false,
                        withdrawal_chunks: HeapArray::from_elem(false),
                    },
                    sk,
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
                    .put_deposit(&deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;

                emit(actions, Action::GenerateDepositAdaptors(deposit_id));
                for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
                    emit(
                        actions,
                        Action::GenerateWithdrawalAdaptorsChunk(
                            deposit_id,
                            ChunkIndex(chunk_idx as u8),
                        ),
                    );
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DepositUndisputedWithdrawal(deposit_id) => match root_state.step {
            Step::SetupComplete => {
                let mut deposit_state = require_deposit(state, &deposit_id).await?;

                match deposit_state.step {
                    DepositStep::DepositReady => {
                        info!(%deposit_id, "evaluator deposit undisputed withdrawal");
                        deposit_state.step = DepositStep::WithdrawnUndisputed;
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }

                state
                    .put_deposit(&deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DisputedWithdrawal(deposit_id, EvaluatorDisputedWithdrawalData { signatures }) => {
            match root_state.step {
                Step::SetupComplete => {
                    let deposit_state = require_deposit(state, &deposit_id).await?;

                    match deposit_state.step {
                        DepositStep::DepositReady => {
                            info!(%deposit_id, "evaluator disputed withdrawal, evaluating tables");
                            state
                                .put_completed_signatures(&deposit_id, &signatures)
                                .await
                                .map_err(SMError::storage)?;

                            let withdrawal_adaptors = state
                                .get_withdrawal_adaptors(&deposit_id)
                                .await
                                .require("expected withdrawal adaptors")?;
                            let withdrawal_wires_start =
                                N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES;
                            let withdrawal_wires_end = N_INPUT_WIRES;
                            let withdrawal_input_zeroth_coeffs = state
                                .get_input_polynomial_zeroth_coefficients(
                                    withdrawal_wires_start..withdrawal_wires_end,
                                )
                                .await
                                .map_err(SMError::storage)?;

                            let withdrawal_input = extract_withdrawal_input_from_signatures(
                                signatures,
                                withdrawal_adaptors,
                                withdrawal_input_zeroth_coeffs,
                            )
                            .map_err(SMError::StateInconsistency)?;
                            // returns state inconsistency error here because adaptor signature was
                            // correctly submitted but doesn't agree
                            // with values saved in our state

                            state
                                .put_withdrawal_inputs(&deposit_id, &withdrawal_input)
                                .await
                                .map_err(SMError::storage)?;

                            let challenge_indices = state
                                .get_challenge_indices()
                                .await
                                .require("expected challenge indices")?;
                            let garbling_commitments = state
                                .get_garbling_table_commitments()
                                .await
                                .require("expected garbling table commitments")?;

                            let eval_indices = get_eval_indices(&challenge_indices);
                            let eval_commitments =
                                get_eval_commitments(&eval_indices, &garbling_commitments);

                            for idx in 0..N_EVAL_CIRCUITS {
                                let index = eval_indices[idx];
                                let commitment = eval_commitments[idx];
                                emit(actions, Action::EvaluateGarblingTable(index, commitment));
                            }

                            root_state.step = Step::EvaluatingTables {
                                deposit_id,
                                eval_indices,
                                eval_commitments,
                                evaluated: HeapArray::from_elem(false),
                            };
                        }
                        _ => return Err(SMError::UnexpectedInput),
                    }

                    state
                        .put_deposit(&deposit_id, &deposit_state)
                        .await
                        .map_err(SMError::storage)?;
                }
                _ => return Err(SMError::UnexpectedInput),
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
        ActionResult::ChallengeMsgAcked => {
            // The challenge message was sent. No further state change needed —
            // state was already advanced to WaitingForChallengeResponse when
            // we emitted the SendChallengeMsg action.
        }
        ActionResult::VerifyOpenedInputSharesResult(failure) => match root_state.step {
            Step::VerifyingOpenedInputShares => {
                if let Some(failure_reason) = failure {
                    warn!(reason = %failure_reason, "evaluator opened input shares verification failed, aborting");
                    root_state.step = Step::Aborted {
                        reason: format!("invalid opened input shares: {}", failure_reason),
                    };
                } else {
                    info!("evaluator opened input shares verified, verifying table commitments");
                    let opened_indices = state
                        .get_challenge_indices()
                        .await
                        .require("expected challenge indices")?;

                    let opened_seeds = state
                        .get_opened_garbling_seeds()
                        .await
                        .require("expected opened garbling seeds")?;

                    let all_table_commitments = state
                        .get_garbling_table_commitments()
                        .await
                        .require("expected garbling tables commitments")?;

                    let opened_commitments =
                        get_opened_commitments(&opened_indices, &all_table_commitments);

                    for ii in 0..N_OPEN_CIRCUITS {
                        let index = opened_indices[ii];
                        let seed = opened_seeds[ii];

                        emit(actions, Action::GenerateTableCommitment(index, seed));
                    }

                    root_state.step = Step::VerifyingTableCommitments {
                        opened_indices,
                        opened_seeds,
                        opened_commitments,
                        verified: HeapArray::from_elem(false),
                    };
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::TableCommitmentGenerated(index, table_commitment) => {
            handle_table_commitment_generated(
                &mut root_state,
                state,
                index,
                table_commitment,
                actions,
            )
            .await?;
        }
        ActionResult::GarblingTableReceived(index, table_commitment) => {
            handle_table_received(&mut root_state, state, index, table_commitment, actions).await?;
        }
        ActionResult::TableTransferReceiptAcked => {
            // The table transfer receipt message was sent. No further state change needed —
            // state was already advanced to SetupComplete when
            // we emitted the SendTableTransferReceipt action.
        }
        ActionResult::DepositAdaptorsGenerated(deposit_id, deposit_adaptors) => {
            match root_state.step {
                Step::SetupComplete => {
                    let mut deposit_state = require_deposit(state, &deposit_id).await?;

                    match &mut deposit_state.step {
                        DepositStep::GeneratingAdaptors {
                            deposit,
                            withdrawal_chunks,
                        } => {
                            state
                                .put_deposit_adaptors(&deposit_id, &deposit_adaptors)
                                .await
                                .map_err(SMError::storage)?;

                            *deposit = true;
                            debug!(%deposit_id, "evaluator deposit adaptors generated");

                            if withdrawal_chunks.all() {
                                info!(%deposit_id, "all adaptors generated, sending");
                                deposit_state.step = DepositStep::SendingAdaptors {
                                    acked: HeapArray::from_elem(false),
                                };

                                let withdrawal_adaptors = state
                                    .get_withdrawal_adaptors(&deposit_id)
                                    .await
                                    .map_err(SMError::storage)?
                                    .ok_or_else(|| {
                                        SMError::state_inconsistency("expected withdrawal adaptors")
                                    })?;

                                for chunk in create_adaptor_message_chunks(
                                    deposit_id,
                                    deposit_adaptors,
                                    withdrawal_adaptors,
                                ) {
                                    emit(
                                        actions,
                                        Action::DepositSendAdaptorMsgChunk(deposit_id, chunk),
                                    );
                                }
                            }
                        }
                        _ => return Err(SMError::UnexpectedInput),
                    }

                    state
                        .put_deposit(&deposit_id, &deposit_state)
                        .await
                        .map_err(SMError::storage)?;
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        ActionResult::WithdrawalAdaptorsChunkGenerated(
            deposit_id,
            chunk_idx,
            withdrawal_adaptor_chunk,
        ) => match root_state.step {
            Step::SetupComplete => {
                let mut deposit_state = require_deposit(state, &deposit_id).await?;

                match &mut deposit_state.step {
                    DepositStep::GeneratingAdaptors {
                        deposit,
                        withdrawal_chunks,
                    } => {
                        match withdrawal_chunks.get(chunk_idx.get() as usize) {
                            None => return Err(SMError::invalid_input_data()),
                            Some(true) => return Err(SMError::duplicate_action()),
                            Some(false) => {}
                        }

                        state
                            .put_withdrawal_adaptors_chunk(
                                &deposit_id,
                                chunk_idx.get(),
                                &withdrawal_adaptor_chunk,
                            )
                            .await
                            .map_err(SMError::storage)?;

                        withdrawal_chunks[chunk_idx.get() as usize] = true;
                        debug!(%deposit_id, chunk = chunk_idx.get(), done = withdrawal_chunks.count_ones(), total = withdrawal_chunks.len(), "evaluator withdrawal adaptor chunk generated");

                        if *deposit && withdrawal_chunks.all() {
                            info!(%deposit_id, "all adaptors generated, sending");
                            deposit_state.step = DepositStep::SendingAdaptors {
                                acked: HeapArray::from_elem(false),
                            };

                            let deposit_adaptors = state
                                .get_deposit_adaptors(&deposit_id)
                                .await
                                .require("expected deposit adaptors")?;

                            let withdrawal_adaptors = state
                                .get_withdrawal_adaptors(&deposit_id)
                                .await
                                .require("expected withdrawal adaptors")?;

                            for chunk in create_adaptor_message_chunks(
                                deposit_id,
                                deposit_adaptors,
                                withdrawal_adaptors,
                            ) {
                                emit(
                                    actions,
                                    Action::DepositSendAdaptorMsgChunk(deposit_id, chunk),
                                );
                            }
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }

                state
                    .put_deposit(&deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::DepositAdaptorChunkSent(deposit_id) => match root_state.step {
            Step::SetupComplete => {
                let mut deposit_state = require_deposit(state, &deposit_id).await?;

                match &mut deposit_state.step {
                    DepositStep::SendingAdaptors { acked } => {
                        let ActionId::DepositSendAdaptorMsgChunk(_, chunk_index) = id else {
                            return Err(SMError::InvalidInputData);
                        };
                        let idx = chunk_index as usize;
                        if acked[idx] {
                            return Err(SMError::InvalidInputData);
                        }

                        acked[idx] = true;
                        debug!(%deposit_id, chunk = idx, done = acked.count_ones(), total = acked.len(), "evaluator adaptor chunk sent");

                        if acked.all() {
                            info!(%deposit_id, "all adaptor chunks sent, deposit ready");
                            deposit_state.step = DepositStep::DepositReady;
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }

                state
                    .put_deposit(&deposit_id, &deposit_state)
                    .await
                    .map_err(SMError::storage)?;
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::TableEvaluationResult(commitment, output_share) => {
            match &mut root_state.step {
                Step::EvaluatingTables {
                    deposit_id,
                    eval_indices: _,
                    eval_commitments,
                    evaluated,
                } => {
                    let Some(idx) = eval_commitments.iter().position(|c| *c == commitment) else {
                        return Err(SMError::InvalidInputData);
                    };

                    evaluated[idx] = true;
                    debug!(%commitment, done = evaluated.count_ones(), total = evaluated.len(), "evaluator table evaluation result");

                    let success = if let Some(output_share) = output_share {
                        // output_share is Some only if the evaluation yielded False value as result
                        // Now interpolate to find share corresponding to reserved index of output
                        // wire
                        let mut opened_output_shares = state
                            .get_opened_output_shares()
                            .await
                            .require("expected opened output shares")?
                            .to_vec();
                        opened_output_shares.push(output_share);

                        let evals_at_missing_indices =
                            interpolate(&opened_output_shares).expect("should interpolate");
                        let evals_at_zeroth_index = evals_at_missing_indices
                            .iter()
                            .find(|x| x.index() == Index::reserved())
                            .expect("should include zeroth index evaluation");
                        let calc_commitment = evals_at_zeroth_index.commit().point();

                        let output_poly_commit = state
                            .get_output_polynomial_commitment()
                            .await
                            .require("expected output poly commit")?[0]
                            .get_zeroth_coefficient();

                        let fault_secret_found = calc_commitment == output_poly_commit;
                        if fault_secret_found {
                            state
                                .put_fault_secret_share(evals_at_zeroth_index)
                                .await
                                .map_err(SMError::storage)?;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if success || evaluated.all() {
                        info!(%deposit_id, success, "evaluator table evaluations complete, setup consumed");
                        root_state.step = Step::SetupConsumed {
                            deposit_id: *deposit_id,
                            success,
                        };
                    }
                    // else stay on same step and wait for more evaluations
                }
                Step::SetupConsumed { .. } => {}
                _ => return Err(SMError::UnexpectedInput),
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
// Helpers for handle_event
// ============================================================================

async fn handle_commit_msg_header<S: StateMut>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    commit_msg_header: CommitMsgHeader,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut state.step {
        Step::WaitingForCommit { header, chunks, .. } => {
            if *header {
                debug!("evaluator received duplicate commit header, ack and ignore");
                return Ok(());
            }

            if !is_valid_commit_header(&commit_msg_header) {
                warn!("evaluator received invalid commit msg header, aborting");
                state.step = Step::Aborted {
                    reason: "invalid commit msg header".into(),
                };
                return Ok(());
            }
            let CommitMsgHeader {
                garbling_table_commitments,
                output_polynomial_commitment,
                all_aes128_keys,
                all_public_s,
                all_constant_zero_labels,
                all_constant_one_labels,
            } = commit_msg_header;

            artifact_store
                .put_garbling_table_commitments(&garbling_table_commitments)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_output_polynomial_commitment(&output_polynomial_commitment)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_all_aes128_keys(&all_aes128_keys)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_all_public_s(&all_public_s)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_all_constant_zero_labels(&all_constant_zero_labels)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_all_constant_one_labels(&all_constant_one_labels)
                .await
                .map_err(SMError::storage)?;

            *header = true;
            debug!("evaluator commit msg header received");

            if !chunks.all() {
                return Ok(());
            }

            post_handle_commit_msg(state, artifact_store, actions).await
        }
        step if step.phase() > StepPhase::WaitingForCommit => {
            debug!("evaluator received commit header after completion, ack and ignore");
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_commit_msg_chunk<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    commit_msg_chunk: CommitMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::WaitingForCommit { header, chunks } => {
            let chunk_idx = commit_msg_chunk.wire_index as usize;
            match chunks.get(chunk_idx) {
                Some(false) => {
                    // expected chunk
                }
                Some(true) => {
                    // already seen chunk
                    debug!(%chunk_idx, "evaluator received duplicate commit chunk, ack and ignore");
                    return Ok(());
                }
                None => {
                    // unexpected chunk idx
                    return Err(SMError::InvalidInputData);
                }
            };

            chunks[chunk_idx] = true;
            debug!(
                wire = chunk_idx,
                done = chunks.count_ones(),
                total = chunks.len(),
                "evaluator commit msg chunk received"
            );

            state
                .put_input_polynomial_commitment_zeroth_coeffs(
                    commit_msg_chunk.wire_index,
                    &extract_zeroth_coefficients(&commit_msg_chunk.commitments),
                )
                .await
                .map_err(SMError::storage)?;

            state
                .put_input_polynomial_commitments_chunk(
                    commit_msg_chunk.wire_index,
                    &commit_msg_chunk.commitments,
                )
                .await
                .map_err(SMError::storage)?;

            if !*header || !chunks.all() {
                return Ok(());
            }

            post_handle_commit_msg(root_state, state, actions).await
        }
        step if step.phase() > StepPhase::WaitingForCommit => {
            debug!("evaluator received commit chunk after completion, ack and ignore");
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn post_handle_commit_msg<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    // header and all chunks received
    let config = require_config(root_state)?;
    let challenge_indices = sample_challenge_indices(config.seed);
    debug_assert!(is_sorted(challenge_indices.as_slice()));

    state
        .put_challenge_indices(&challenge_indices)
        .await
        .map_err(SMError::storage)?;

    info!("evaluator commit msg complete, sending challenge");
    root_state.step = Step::WaitingForChallengeResponse {
        header: false,
        remaining_chunks: get_remaining_challenge_response_chunks(&challenge_indices),
    };

    let challenge_msg = ChallengeMsg { challenge_indices };
    emit(actions, Action::SendChallengeMsg(challenge_msg));
    Ok(())
}

async fn handle_recv_challenge_response_header<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    response_msg_header: ChallengeResponseMsgHeader,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::WaitingForChallengeResponse {
            header,
            remaining_chunks,
        } => {
            if *header {
                debug!("evaluator received duplicate challenge response header, ack and ignore");
                return Ok(());
            }

            // NOTE: header validity is checked after header and all chunks are received.

            let challenge_idxs = state
                .get_challenge_indices()
                .await
                .require("expected challenge indices")?;
            let eval_indices = get_eval_indices(&challenge_idxs);

            let ChallengeResponseMsgHeader {
                reserved_setup_input_shares,
                opened_output_shares,
                opened_garbling_seeds,
                unchallenged_output_label_cts,
            } = response_msg_header;

            state
                .put_reserved_setup_input_shares(&reserved_setup_input_shares)
                .await
                .map_err(SMError::storage)?;
            state
                .put_opened_output_shares(&opened_output_shares)
                .await
                .map_err(SMError::storage)?;
            state
                .put_opened_garbling_seeds(&opened_garbling_seeds)
                .await
                .map_err(SMError::storage)?;
            state
                .put_unchallenged_output_label_cts(&eval_indices, &unchallenged_output_label_cts)
                .await
                .map_err(SMError::storage)?;

            *header = true;
            debug!("evaluator challenge response header received");
            if remaining_chunks.count_ones() > 0 {
                return Ok(());
            }

            post_handle_challenge_response(root_state, state, actions).await
        }
        step if step.phase() > StepPhase::WaitingForChallengeResponse => {
            debug!("evaluator received challenge response header after completion, ack and ignore");
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_recv_challenge_response_msg<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    response_msg_chunk: ChallengeResponseMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::WaitingForChallengeResponse {
            header,
            remaining_chunks,
        } => {
            let challenge_idxs = state
                .get_challenge_indices()
                .await
                .require("expected challenge indices")?;

            if !challenge_idxs
                .iter()
                .any(|idx| idx.get() == response_msg_chunk.circuit_index as usize)
            {
                return Err(SMError::InvalidInputData);
            }

            let chunk_idx = (response_msg_chunk.circuit_index as usize)
                .checked_sub(1)
                .unwrap();
            match remaining_chunks.get(chunk_idx) {
                Some(true) => {
                    // expected chunk
                }
                Some(false) => {
                    // already seen expected chunk
                    debug!(
                        %chunk_idx,
                        "evaluator received duplicate challenge response chunk, ack and ignore"
                    );
                    return Ok(());
                }
                None => {
                    // unexpected chunk idx
                    return Err(SMError::InvalidInputData);
                }
            };
            remaining_chunks[chunk_idx] = false;
            debug!(
                circuit_index = response_msg_chunk.circuit_index,
                remaining = remaining_chunks.count_ones(),
                total = remaining_chunks.len(),
                "evaluator challenge response chunk received"
            );

            state
                .put_opened_input_shares_chunk(
                    response_msg_chunk.circuit_index,
                    &response_msg_chunk.shares,
                )
                .await
                .map_err(SMError::storage)?;

            if !*header || remaining_chunks.count_ones() > 0 {
                return Ok(());
            }

            post_handle_challenge_response(root_state, state, actions).await
        }
        step if step.phase() > StepPhase::WaitingForChallengeResponse => {
            debug!("evaluator received challenge response chunk after completion, ack and ignore");
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn post_handle_challenge_response<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    // all chunks received
    let config = require_config(root_state)?;
    let reserved_setup_input_shares = state
        .get_reserved_setup_input_shares()
        .await
        .require("expected reserved setup input shares")?;

    let setup_wire_zeroth_coefficients = state
        .get_input_polynomial_zeroth_coefficients(0..N_SETUP_INPUT_WIRES)
        .await
        .map_err(SMError::storage)?;

    if let Some(failure_reason) = verify_reserved_setup_input_shares(
        &reserved_setup_input_shares,
        &config.setup_inputs,
        &setup_wire_zeroth_coefficients,
    ) {
        warn!(reason = %failure_reason, "evaluator reserved input share verification failed, aborting");
        root_state.step = Step::Aborted {
            reason: format!(
                "reserved input share verification failed: {}",
                failure_reason
            ),
        };
        return Ok(());
    }

    info!("evaluator challenge response verified, verifying opened input shares");
    root_state.step = Step::VerifyingOpenedInputShares;

    emit(actions, Action::VerifyOpenedInputShares);

    Ok(())
}

// ============================================================================
// Helpers for handle_action_result
// ============================================================================

async fn handle_table_commitment_generated<S: StateMut>(
    root_state: &mut EvaluatorState,
    state: &mut S,
    index: Index,
    table_commitment: GarblingTableCommitment,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::VerifyingTableCommitments {
            opened_indices,
            opened_commitments,
            verified,
            ..
        } => {
            let Ok(idx) = opened_indices.binary_search(&index) else {
                return Err(SMError::InvalidInputData);
            };

            let expected_commitment = opened_commitments[idx];
            if table_commitment != expected_commitment {
                warn!(%index, "evaluator table commitment mismatch, aborting");
                root_state.step = Step::Aborted {
                    reason: format!("invalid table seed for index {}", index),
                };
                return Ok(());
            }

            verified[idx] = true;
            debug!(%index, done = verified.count_ones(), total = verified.len(), "evaluator table commitment verified");

            if verified.all() {
                info!("all table commitments verified, requesting garbling tables");
                let eval_indices = get_eval_indices(opened_indices);
                debug_assert!(is_sorted(&eval_indices));

                let garbling_commitments = state
                    .get_garbling_table_commitments()
                    .await
                    .require("expected garbling table commitments")?;

                let eval_commitments = get_eval_commitments(&eval_indices, &garbling_commitments);

                for commitment in &eval_commitments {
                    // Combined action: registers bulk-transfer expectation, sends
                    // the request, then receives, verifies, and persists the table.
                    emit(actions, Action::ReceiveGarblingTable(*commitment));
                }
                root_state.step = Step::ReceivingGarblingTables {
                    eval_indices,
                    eval_commitments,
                    received: HeapArray::from_elem(false),
                };
            }

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_table_received<S: StateMut>(
    root_state: &mut EvaluatorState,
    _state: &mut S,
    index: Index,
    table_commitment: GarblingTableCommitment,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut root_state.step {
        Step::ReceivingGarblingTables {
            eval_indices: eval_idxs,
            eval_commitments,
            received,
        } => {
            let Some(pos) = eval_idxs.iter().position(|&x| x == index) else {
                return Err(SMError::InvalidInputData);
            };

            let expected_commitment = eval_commitments[pos];
            if table_commitment != expected_commitment {
                warn!(%index, "evaluator received garbling table with mismatched commitment, aborting");
                root_state.step = Step::Aborted {
                    reason: format!("invalid table for index {}", index),
                };
                return Ok(());
            }

            emit(
                actions,
                Action::SendTableTransferReceipt(TableTransferReceiptMsg::new(table_commitment)),
            );

            received[pos] = true;
            debug!(%index, done = received.count_ones(), total = received.len(), "evaluator garbling table received");

            if received.all() {
                info!("all garbling tables received, setup complete");
                root_state.step = Step::SetupComplete;
            }

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
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
        "evaluator restoring state"
    );

    match &root_state.step {
        Step::Uninit => {}
        Step::WaitingForCommit { .. } => {}
        Step::WaitingForChallengeResponse {
            header,
            remaining_chunks,
        } => {
            // Replay challenge send only if no response material was observed yet.
            // Once any response data is stored, re-sending can cause duplicate
            // challenge handling on the garbler side.
            if !header && remaining_chunks.count_ones() == N_CHALLENGE_RESPONSE_CHUNKS {
                let challenge_indices = state
                    .get_challenge_indices()
                    .await
                    .require("expected challenge indices")?;
                let challenge_msg = ChallengeMsg { challenge_indices };
                emit(actions, Action::SendChallengeMsg(challenge_msg));
            }
        }
        Step::VerifyingOpenedInputShares => {
            emit(actions, Action::VerifyOpenedInputShares);
        }
        Step::VerifyingTableCommitments {
            opened_indices,
            opened_seeds,
            verified,
            ..
        } => {
            for ii in 0..N_OPEN_CIRCUITS {
                if verified[ii] {
                    continue;
                }
                let index = opened_indices[ii];
                let seed = opened_seeds[ii];

                emit(actions, Action::GenerateTableCommitment(index, seed));
            }
        }
        Step::ReceivingGarblingTables {
            eval_commitments,
            received,
            ..
        } => {
            for (commitment, received) in eval_commitments.iter().zip(received.iter()) {
                if *received {
                    // Notify the garbler that these tables have been received already.
                    emit(
                        actions,
                        Action::SendTableTransferReceipt(TableTransferReceiptMsg::new(*commitment)),
                    );
                    continue;
                }
                // Combined action: registers expectation, sends request, receives table.
                emit(actions, Action::ReceiveGarblingTable(*commitment));
            }
        }
        Step::SetupComplete => {
            let mut all_deposits = pin!(state.stream_all_deposits());

            while let Some(res) = all_deposits.next().await {
                let (deposit_id, deposit_state) = res.map_err(SMError::storage)?;

                match &deposit_state.step {
                    DepositStep::GeneratingAdaptors {
                        deposit,
                        withdrawal_chunks,
                    } => {
                        if !deposit {
                            emit(actions, Action::GenerateDepositAdaptors(deposit_id));
                        }
                        for (idx, generated) in withdrawal_chunks.iter().enumerate() {
                            if !*generated {
                                emit(
                                    actions,
                                    Action::GenerateWithdrawalAdaptorsChunk(
                                        deposit_id,
                                        ChunkIndex(idx as u8),
                                    ),
                                );
                            }
                        }
                    }
                    DepositStep::SendingAdaptors { acked } => {
                        let deposit_adaptors = state
                            .get_deposit_adaptors(&deposit_id)
                            .await
                            .require("expected deposit adaptors")?;

                        let withdrawal_adaptors = state
                            .get_withdrawal_adaptors(&deposit_id)
                            .await
                            .require("expected withdrawal adaptors")?;

                        for chunk in create_adaptor_message_chunks(
                            deposit_id,
                            deposit_adaptors,
                            withdrawal_adaptors,
                        ) {
                            if !acked[chunk.chunk_index as usize] {
                                emit(
                                    actions,
                                    Action::DepositSendAdaptorMsgChunk(deposit_id, chunk),
                                );
                            }
                        }
                    }
                    DepositStep::DepositReady => {}
                    DepositStep::WithdrawnUndisputed => {}
                    DepositStep::Aborted { .. } => {}
                }
            }
        }
        Step::EvaluatingTables {
            eval_indices,
            eval_commitments,
            evaluated,
            ..
        } => {
            for ii in 0..N_EVAL_CIRCUITS {
                if evaluated[ii] {
                    continue;
                }
                emit(
                    actions,
                    Action::EvaluateGarblingTable(eval_indices[ii], eval_commitments[ii]),
                );
            }
        }
        Step::SetupConsumed { .. } => {}
        Step::Aborted { .. } => {}
    }

    Ok(())
}

// ============================================================================
// Pure helper functions
// ============================================================================

fn require_config(state: &EvaluatorState) -> SMResult<&Config> {
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

fn is_valid_commit_header(commit_header: &CommitMsgHeader) -> bool {
    // zeroth polynomial coefficient corresponds to share commitment at reserved index
    // since this Point corresponds to verifying key, we need to validate that it is a proper
    // schnorr pubkey
    let poly = commit_header.output_polynomial_commitment[0].get_zeroth_coefficient();
    PubKey(poly).valid()
}

fn sample_challenge_indices(base_seed: Seed) -> ChallengeIndices {
    let seed = derive_stage_seed(base_seed, SEED_CONTEXT_SAMPLE_CHALLENGE_INDICES, None);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.into());
    let sampled_indices = rand::seq::index::sample(&mut rng, N_CIRCUITS, N_OPEN_CIRCUITS); // samples N_OPEN_CIRCUITS many values from the domain [0, N_CIRCUITS]
    let mut challenge_indices: ChallengeIndices = HeapArray::from_vec(
        sampled_indices
            .into_iter()
            .map(|x| Index::new(x + 1).expect("within bounds")) // sampled values displaced to domain [1, N_CIRCUITS+1] as 0 is reserved index
            .collect::<Vec<_>>(),
    );
    challenge_indices.sort_by_key(|k| k.get());
    challenge_indices
}

/// Verify reserved setup input shares and return failure reason or None.
fn verify_reserved_setup_input_shares(
    reserved_setup_input_shares: &ReservedSetupInputShares,
    setup_inputs: &SetupInputs,
    setup_wire_zeroth_coefficients: &[WideLabelZerothPolynomialCoefficients],
) -> Option<String> {
    for wire in 0..N_SETUP_INPUT_WIRES {
        let val = setup_inputs[wire];
        let reserved_share = reserved_setup_input_shares[wire];
        if setup_wire_zeroth_coefficients[wire][val as usize] != reserved_share.commit().point() {
            return Some(format!(
                "verify reserved setup shares failed for wire {wire}",
            ));
        }
    }
    None
}

fn get_opened_commitments(
    challenge_indices: &ChallengeIndices,
    garbling_commitments: &AllGarblingTableCommitments,
) -> OpenedGarblingTableCommitments {
    HeapArray::new(|i| {
        let seed_idx = challenge_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    })
}

/// Returns a boolean mask over chunks, where `true` marks chunks that still
/// need to be received. Challenge indices are 1-based, so each is decremented
/// by 1 to map to the 0-based chunk index.
pub(super) fn get_remaining_challenge_response_chunks(
    challenge_indices: &ChallengeIndices,
) -> HeapArray<bool, N_CIRCUITS> {
    let mut remaining_chunks = HeapArray::from_elem(false);
    challenge_indices.iter().for_each(|challenge_idx| {
        let chunk_idx = challenge_idx.get().checked_sub(1).expect("non zero");
        remaining_chunks[chunk_idx] = true;
    });
    remaining_chunks
}

fn is_sorted<T: Ord>(slice: &[T]) -> bool {
    slice.windows(2).all(|w| w[0] <= w[1])
}

fn create_adaptor_message_chunks(
    deposit_id: DepositId,
    deposit_adaptors: DepositAdaptors,
    withdrawal_adaptors: WithdrawalAdaptors,
) -> Vec<AdaptorMsgChunk> {
    // take 1 deposit adaptor wire and N withdrawal adaptor wires
    let mut adaptor_msg_chunks = vec![];
    for chunk_index in 0..N_DEPOSIT_INPUT_WIRES {
        let withdrawal_adaptors: WithdrawalAdaptorsChunk = HeapArray::from_vec(
            withdrawal_adaptors[chunk_index * WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK
                ..(chunk_index + 1) * WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK]
                .to_vec(),
        );
        adaptor_msg_chunks.push(AdaptorMsgChunk {
            deposit_id,
            chunk_index: chunk_index as u8,
            deposit_adaptor: deposit_adaptors[chunk_index],
            withdrawal_adaptors,
        });
    }
    adaptor_msg_chunks
}

fn extract_withdrawal_input_from_signatures(
    completed_signatures: CompletedSignatures,
    withdrawal_adaptors: WithdrawalAdaptors,
    withdrawal_input_zeroth_coeffs: Vec<WideLabelZerothPolynomialCoefficients>,
) -> Result<WithdrawalInputs, String> {
    let withdrawal_sigs = &completed_signatures[N_DEPOSIT_INPUT_WIRES..];
    let mut withdrawal_input: WithdrawalInputs = [0; N_WITHDRAWAL_INPUT_WIRES];

    for wire_idx in 0..N_WITHDRAWAL_INPUT_WIRES {
        let sig = withdrawal_sigs[wire_idx];
        let wide_adaptors = &withdrawal_adaptors[wire_idx];
        let poly_commits = &withdrawal_input_zeroth_coeffs[wire_idx];
        let position = wide_adaptors
            .iter()
            .zip(poly_commits)
            .position(|(adaptor, poly_commit)| {
                let val = adaptor.extract_share(&sig);
                let share = Share::new(Index::reserved(), val);
                *poly_commit == share.commit().point()
            });
        if let Some(position) = position {
            withdrawal_input[wire_idx] = position as WideLabelValue;
        } else {
            return Err(format!(
                "Adaptors can not extract share for withdrawal wire at index {wire_idx}"
            ));
        }
    }
    Ok(withdrawal_input)
}

fn extract_zeroth_coefficients(
    commits: &WideLabelWirePolynomialCommitments,
) -> WideLabelZerothPolynomialCoefficients {
    WideLabelZerothPolynomialCoefficients::from_vec(
        commits
            .iter()
            .map(|commit| commit.get_zeroth_coefficient())
            .collect(),
    )
}

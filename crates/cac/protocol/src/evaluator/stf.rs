use std::pin::pin;

use futures::StreamExt;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk, CommitMsgHeader,
    DepositAdaptors, DepositId, EvalGarblingTableCommitments, EvaluationIndices,
    GarblingTableCommitment, HeapArray, Index, InputPolynomialCommitments,
    OpenedGarblingTableCommitments, OpenedOutputShares, OutputPolynomialCommitment,
    ReservedSetupInputShares, Seed, SetupInputs, WithdrawalAdaptors,
    state_machine::evaluator::{
        Action, ActionContainer, ActionId, ActionResult, ChunkIndex, EvaluatorDepositInitData,
        EvaluatorDisputedWithdrawalData, Input,
    },
};
use mosaic_common::constants::{
    N_ADAPTOR_MSG_CHUNKS, N_CHALLENGE_RESPONSE_CHUNKS, N_EVAL_CIRCUITS, N_OPEN_CIRCUITS,
};

use super::{
    deposit::{DepositState, DepositStep},
    emit,
    root_state::{Config, EvaluatorState, EvaluatorState as State, Step},
    state::StateMut,
};
use crate::{SMError, SMResult, evaluator::state::StateRead};

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
        .ok_or_else(|| SMError::MissingRootState)?;

    match input {
        Input::Init(data) => match root_state.step {
            Step::Uninit => {
                root_state.config = Some(Config {
                    seed: data.seed,
                    setup_inputs: data.setup_inputs,
                });
                root_state.step = Step::WaitingForCommit {
                    header: false,
                    chunks: HeapArray::from_elem(false),
                };
            }
            _ => return Err(SMError::UnexpectedInput),
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
                    // deposit already exists
                    return Err(SMError::deposit_already_exists(deposit_id));
                }

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
        Input::DisputedWithdrawal(
            deposit_id,
            EvaluatorDisputedWithdrawalData {
                signatures,
                withdrawal_inputs,
            },
        ) => match root_state.step {
            Step::SetupComplete => {
                let deposit_state = require_deposit(state, &deposit_id).await?;

                match deposit_state.step {
                    DepositStep::DepositReady => {
                        state
                            .put_completed_signatures(&deposit_id, &signatures)
                            .await
                            .map_err(SMError::storage)?;

                        state
                            .put_withdrawal_inputs(&deposit_id, &withdrawal_inputs)
                            .await
                            .map_err(SMError::storage)?;

                        let challenge_indices = state
                            .get_challenge_indices()
                            .await
                            .map_err(SMError::storage)?;
                        let garbling_commitments = state
                            .get_garbling_table_commitments()
                            .await
                            .map_err(SMError::storage)?;

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
        },
        _ => return Err(SMError::UnexpectedInput),
    };

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
        .ok_or_else(|| SMError::MissingRootState)?;

    match result {
        ActionResult::ChallengeMsgAcked => {
            // The challenge message was sent. No further state change needed —
            // state was already advanced to WaitingForChallengeResponse when
            // we emitted the SendChallengeMsg action.
        }
        ActionResult::VerifyOpenedInputSharesResult(failure) => match root_state.step {
            Step::VerifyingOpenedInputShares => {
                if let Some(failure_reason) = failure {
                    root_state.step = Step::Aborted {
                        reason: format!("invalid opened input shares: {}", failure_reason),
                    };
                } else {
                    let opened_indices = state
                        .get_challenge_indices()
                        .await
                        .map_err(SMError::storage)?;
                    let opened_seeds = state
                        .get_opened_garbling_seeds()
                        .await
                        .map_err(SMError::storage)?;
                    let all_table_commitments = state
                        .get_garbling_table_commitments()
                        .await
                        .map_err(SMError::storage)?;
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
            handle_table_received(&mut root_state, state, index, table_commitment).await?;
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

                            if withdrawal_chunks.all() {
                                deposit_state.step = DepositStep::SendingAdaptors {
                                    acked: HeapArray::from_elem(false),
                                };

                                let withdrawal_adaptors = state
                                    .get_withdrawal_adaptors(&deposit_id)
                                    .await
                                    .map_err(SMError::storage)?;

                                for chunk in create_adaptor_message_chunks(
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

                        if *deposit && withdrawal_chunks.all() {
                            deposit_state.step = DepositStep::SendingAdaptors {
                                acked: HeapArray::from_elem(false),
                            };

                            let deposit_adaptors = state
                                .get_deposit_adaptors(&deposit_id)
                                .await
                                .map_err(SMError::storage)?;
                            let withdrawal_adaptors = state
                                .get_withdrawal_adaptors(&deposit_id)
                                .await
                                .map_err(SMError::storage)?;

                            for chunk in
                                create_adaptor_message_chunks(deposit_adaptors, withdrawal_adaptors)
                            {
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

                        if acked.all() {
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

                    if output_share.is_some() {
                        // Found the fault secret — evaluation complete.
                        // TODO: store output_share, interpolate to recover secret
                        root_state.step = Step::SetupConsumed {
                            deposit_id: *deposit_id,
                        };
                    } else if evaluated.all() {
                        // All tables evaluated, no fault found.
                        root_state.step = Step::SetupConsumed {
                            deposit_id: *deposit_id,
                        };
                    }
                    // else stay on same step and wait for more evaluations
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        _ => return Err(SMError::UnexpectedInput),
    };

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
        Step::WaitingForCommit { header, chunks } => {
            if !is_valid_commit_header(&commit_msg_header) {
                state.step = Step::Aborted {
                    reason: "invalid commit msg header".into(),
                };
                return Ok(());
            }
            let CommitMsgHeader {
                garbling_table_commitments,
                output_polynomial_commitment,
            } = commit_msg_header;

            artifact_store
                .put_garbling_table_commitments(&garbling_table_commitments)
                .await
                .map_err(SMError::storage)?;
            artifact_store
                .put_output_polynomial_commitment(&output_polynomial_commitment)
                .await
                .map_err(SMError::storage)?;

            *header = true;

            if !chunks.all() {
                return Ok(());
            }

            post_handle_commit_msg(state, artifact_store, actions).await
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
            if !is_valid_commit_chunk(&commit_msg_chunk) {
                root_state.step = Step::Aborted {
                    reason: "invalid commit msg chunk".into(),
                };
                return Ok(());
            }

            let chunk_idx = commit_msg_chunk.wire_index as usize;
            match chunks.get(chunk_idx) {
                Some(false) => {
                    // expected chunk
                }
                Some(true) => {
                    // already seen chunk
                    return Err(SMError::InvalidInputData);
                }
                None => {
                    // unexpected chunk idx
                    return Err(SMError::InvalidInputData);
                }
            };

            chunks[chunk_idx] = true;

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

    root_state.step = Step::WaitingForChallengeResponse {
        header: false,
        chunks: HeapArray::from_elem(false),
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
        Step::WaitingForChallengeResponse { header, chunks } => {
            if !is_valid_challenge_response_header(&response_msg_header) {
                root_state.step = Step::Aborted {
                    reason: "invalid challenge response message header".into(),
                };
                return Ok(());
            }

            let ChallengeResponseMsgHeader {
                reserved_setup_input_shares,
                opened_output_shares,
                opened_garbling_seeds,
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

            *header = true;
            if chunks.count_ones() != N_CHALLENGE_RESPONSE_CHUNKS {
                return Ok(());
            }

            post_handle_challenge_response(root_state, state, actions).await
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
        Step::WaitingForChallengeResponse { header, chunks } => {
            let challenge_idxs = state
                .get_challenge_indices()
                .await
                .map_err(SMError::storage)?;
            if !is_valid_challenge_response_chunk(&response_msg_chunk, &challenge_idxs) {
                root_state.step = Step::Aborted {
                    reason: "invalid challenge response message".into(),
                };
                return Ok(());
            }

            let chunk_idx = (response_msg_chunk.circuit_index as usize)
                .checked_sub(1)
                .unwrap();
            if chunks[chunk_idx] {
                return Err(SMError::InvalidInputData);
            }
            chunks[chunk_idx] = true;

            state
                .put_opened_input_shares_chunk(
                    response_msg_chunk.circuit_index,
                    &response_msg_chunk.shares,
                )
                .await
                .map_err(SMError::storage)?;

            if !*header || chunks.count_ones() != N_CHALLENGE_RESPONSE_CHUNKS {
                return Ok(());
            }

            post_handle_challenge_response(root_state, state, actions).await
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
    let opened_output_shares = state
        .get_opened_output_shares()
        .await
        .map_err(SMError::storage)?;

    let output_polynomial_commitment = state
        .get_output_polynomial_commitment()
        .await
        .map_err(SMError::storage)?;

    if let Some(failure_reason) =
        verify_opened_output_shares(&opened_output_shares, &output_polynomial_commitment)
    {
        root_state.step = Step::Aborted {
            reason: format!(
                "opened output share verification failed: {}",
                failure_reason
            ),
        };
        return Ok(());
    }

    let config = require_config(root_state)?;
    let reserved_setup_input_shares = state
        .get_reserved_setup_input_shares()
        .await
        .map_err(SMError::storage)?;
    let input_polynomial_commitments = state
        .get_input_polynomial_commitments()
        .await
        .map_err(SMError::storage)?;

    if let Some(failure_reason) = verify_reserved_setup_input_shares(
        &reserved_setup_input_shares,
        &config.setup_inputs,
        &input_polynomial_commitments,
    ) {
        root_state.step = Step::Aborted {
            reason: format!(
                "reserved input share verification failed: {}",
                failure_reason
            ),
        };
        return Ok(());
    }

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
                root_state.step = Step::Aborted {
                    reason: format!("invalid table seed for index {}", index),
                };
                return Ok(());
            }

            verified[idx] = true;

            if verified.all() {
                let eval_indices = get_eval_indices(opened_indices);
                debug_assert!(is_sorted(&eval_indices));

                let garbling_commitments = state
                    .get_garbling_table_commitments()
                    .await
                    .map_err(SMError::storage)?;
                let eval_commitments = get_eval_commitments(&eval_indices, &garbling_commitments);

                for commitment in &eval_commitments {
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
) -> SMResult<()> {
    match &mut root_state.step {
        Step::ReceivingGarblingTables {
            eval_indices: eval_idxs,
            eval_commitments,
            received,
        } => {
            let Some(idx) = eval_idxs.iter().position(|&x| x == index) else {
                return Err(SMError::InvalidInputData);
            };

            let expected_commitment = eval_commitments[idx];
            if table_commitment != expected_commitment {
                root_state.step = Step::Aborted {
                    reason: format!("invalid table for index {}", index),
                };
                return Ok(());
            }

            received[idx] = true;

            if received.all() {
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
        .ok_or_else(|| SMError::MissingRootState)?;

    match &root_state.step {
        Step::Uninit => {}
        Step::WaitingForCommit { .. } => {}
        Step::WaitingForChallengeResponse { .. } => {
            let challenge_indices = state
                .get_challenge_indices()
                .await
                .map_err(SMError::storage)?;
            let challenge_msg = ChallengeMsg { challenge_indices };

            emit(actions, Action::SendChallengeMsg(challenge_msg));
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
                    continue;
                }
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
                            .map_err(SMError::storage)?;
                        let withdrawal_adaptors = state
                            .get_withdrawal_adaptors(&deposit_id)
                            .await
                            .map_err(SMError::storage)?;

                        for chunk in
                            create_adaptor_message_chunks(deposit_adaptors, withdrawal_adaptors)
                        {
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
        _ => unimplemented!(),
    }

    Ok(())
}

// ============================================================================
// Pure helper functions
// ============================================================================

fn require_config(state: &State) -> SMResult<&Config> {
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

#[expect(unused_variables)]
fn is_valid_commit_header(commit_header: &CommitMsgHeader) -> bool {
    todo!()
}

#[expect(unused_variables)]
fn is_valid_commit_chunk(commit_msg: &CommitMsgChunk) -> bool {
    todo!()
}

#[expect(unused_variables)]
fn sample_challenge_indices(seed: Seed) -> ChallengeIndices {
    todo!()
}

#[expect(unused_variables)]
fn is_valid_challenge_response_header(response_msg_header: &ChallengeResponseMsgHeader) -> bool {
    todo!()
}

#[expect(unused_variables)]
fn is_valid_challenge_response_chunk(
    response_msg_chunk: &ChallengeResponseMsgChunk,
    challenge_idxs: &ChallengeIndices,
) -> bool {
    todo!()
}

/// Verify opened output shares against polynomial commitments and return failure reason or None.
#[expect(unused_variables)]
fn verify_opened_output_shares(
    opened_output_shares: &OpenedOutputShares,
    output_polynomial_commitment: &OutputPolynomialCommitment,
) -> Option<String> {
    todo!()
}

/// Verify reserved setup input shares and return failure reason or None.
#[expect(unused_variables)]
fn verify_reserved_setup_input_shares(
    reserved_setup_input_shares: &ReservedSetupInputShares,
    setup_inputs: &SetupInputs,
    input_polynomial_commitments: &InputPolynomialCommitments,
) -> Option<String> {
    todo!()
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

fn is_sorted<T: Ord>(slice: &[T]) -> bool {
    slice.windows(2).all(|w| w[0] <= w[1])
}

#[expect(unused_variables)]
fn get_eval_indices(challenge_indices: &ChallengeIndices) -> EvaluationIndices {
    todo!()
}

fn get_eval_commitments(
    eval_indices: &EvaluationIndices,
    garbling_commitments: &AllGarblingTableCommitments,
) -> EvalGarblingTableCommitments {
    HeapArray::new(|i| {
        let seed_idx = eval_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    })
}

#[expect(unused_variables)]
fn create_adaptor_message_chunks(
    deposit_adaptors: DepositAdaptors,
    withdrawal_adaptors: WithdrawalAdaptors,
) -> Vec<AdaptorMsgChunk> {
    todo!()
}

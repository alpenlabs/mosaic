use bitvec::array::BitArray;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk, CommitMsgHeader,
    DepositAdaptors, EvalGarblingTableCommitments, EvaluationIndices, GarblingTableCommitment,
    Index, InputPolynomialCommitments, OpenedGarblingTableCommitments, OpenedOutputShares,
    OutputPolynomialCommitment, ReservedSetupInputShares, Seed, SetupInputs, WithdrawalAdaptors,
    state_machine::evaluator::{
        Action, ActionContainer, ActionId, ActionResult, EvaluatorDepositInitData,
        EvaluatorDisputedWithdrawalData, Input,
    },
};
use mosaic_common::constants::{N_EVAL_CIRCUITS, N_OPEN_CIRCUITS};

use super::{
    SMResult,
    artifact::EvaluatorArtifactStore as ArtifactStore,
    emit,
    state::{EvaluatorState as State, EvaluatorStateContainer as StateContainer},
};
use crate::{
    SMError,
    evaluator::{
        deposit::{DepositState, DepositStep},
        state::{Config, EvaluatorState, Step},
    },
};

// ============================================================================
// External event handler
// ============================================================================

/// Handle an external event input (delivered via [`fasm::Input::Normal`]).
///
/// External events are messages from peers, bridge triggers, and initialization
/// — anything that originates outside the state machine.
pub(crate) async fn handle_event<S: ArtifactStore>(
    state_container: &mut StateContainer<S>,
    input: Input,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let (state, artifact_store) = state_container.state_and_artifact_store_mut();
    match input {
        Input::Init(data) => match state.step {
            Step::Uninit => {
                state.config = Some(Config {
                    seed: data.seed,
                    setup_inputs: data.setup_inputs,
                });
                state.step = Step::WaitingForCommit {
                    header: false,
                    chunks: BitArray::ZERO,
                };
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::RecvCommitMsgHeader(commit_msg_header) => {
            handle_commit_msg_header(state, artifact_store, *commit_msg_header, actions).await?;
        }
        Input::RecvCommitMsgChunk(commit_msg) => {
            handle_commit_msg_chunk(state, artifact_store, commit_msg, actions).await?;
        }
        Input::RecvChallengeResponseMsgHeader(response_msg_header) => {
            handle_recv_challenge_response_header(
                state,
                artifact_store,
                response_msg_header,
                actions,
            )
            .await?;
        }
        Input::RecvChallengeResponseMsgChunk(response_msg) => {
            handle_recv_challenge_response_msg(state, artifact_store, response_msg, actions)
                .await?;
        }
        Input::DepositInit(
            deposit_id,
            EvaluatorDepositInitData {
                sk,
                sighashes,
                deposit_inputs,
            },
        ) => match state.step {
            Step::SetupComplete => {
                if state.deposits.contains_key(&deposit_id) {
                    return Err(SMError::DepositAlreadyExists(deposit_id));
                }

                artifact_store
                    .save_sighashes_for_deposit(deposit_id, &sighashes)
                    .await?;
                artifact_store
                    .save_inputs_for_deposit(deposit_id, &deposit_inputs)
                    .await?;

                state.deposits.insert(
                    deposit_id,
                    DepositState {
                        step: DepositStep::GeneratingAdaptors,
                        sk,
                    },
                );

                emit(actions, Action::DepositGenerateAdaptors(deposit_id));
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DepositUndisputedWithdrawal(deposit_id) => match state.step {
            Step::SetupComplete => {
                let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                    return Err(SMError::UnknownDeposit(deposit_id));
                };

                match deposit_state.step {
                    DepositStep::DepositReady => {
                        deposit_state.step = DepositStep::WithdrawnUndisputed;
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DisputedWithdrawal(
            deposit_id,
            EvaluatorDisputedWithdrawalData {
                signatures,
                withdrawal_inputs,
            },
        ) => match state.step {
            Step::SetupComplete => {
                let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                    return Err(SMError::UnknownDeposit(deposit_id));
                };

                match deposit_state.step {
                    DepositStep::DepositReady => {
                        artifact_store
                            .save_completed_signatures(deposit_id, &signatures)
                            .await?;

                        artifact_store
                            .save_withdrawal_inputs(deposit_id, &withdrawal_inputs)
                            .await?;

                        let challenge_indices = artifact_store.load_challenge_indices().await?;
                        let garbling_commitments =
                            artifact_store.load_garbling_table_commitments().await?;

                        let eval_indices = get_eval_indices(&challenge_indices);
                        let eval_commitments =
                            get_eval_commitments(&eval_indices, &garbling_commitments);

                        state.step = Step::EvaluatingTables {
                            deposit_id,
                            eval_indices,
                            eval_commitments,
                            evaluated: BitArray::ZERO,
                        };

                        for idx in 0..N_EVAL_CIRCUITS {
                            let index = eval_indices[idx];
                            let commitment = eval_commitments[idx];
                            emit(actions, Action::EvaluateGarblingTable(index, commitment));
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }
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
pub(crate) async fn handle_action_result<S: ArtifactStore>(
    state_container: &mut StateContainer<S>,
    id: ActionId,
    result: ActionResult,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let (state, artifact_store) = state_container.state_and_artifact_store_mut();
    match result {
        ActionResult::ChallengeMsgAcked => {
            // The challenge message was sent. No further state change needed —
            // state was already advanced to WaitingForChallengeResponse when
            // we emitted the SendChallengeMsg action.
        }
        ActionResult::VerifyOpenedInputSharesResult(failure) => match state.step {
            Step::VerifyingOpenedInputShares => {
                if let Some(failure_reason) = failure {
                    state.step = Step::Aborted {
                        reason: format!("invalid opened input shares: {}", failure_reason),
                    };
                } else {
                    let opened_indices = artifact_store.load_challenge_indices().await?;
                    let opened_seeds = artifact_store.load_opened_garbling_seeds().await?;
                    let all_table_commitments =
                        artifact_store.load_garbling_table_commitments().await?;
                    let opened_commitments =
                        get_opened_commitments(&opened_indices, &all_table_commitments);

                    for ii in 0..N_OPEN_CIRCUITS {
                        let index = opened_indices[ii];
                        let seed = opened_seeds[ii];

                        emit(actions, Action::GenerateTableCommitment(index, seed));
                    }

                    state.step = Step::VerifyingTableCommitments {
                        opened_indices,
                        opened_seeds,
                        opened_commitments,
                        verified: BitArray::ZERO,
                    };
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::TableCommitmentGenerated(index, table_commitment) => {
            handle_table_commitment_generated(
                state,
                artifact_store,
                index,
                table_commitment,
                actions,
            )
            .await?;
        }
        ActionResult::GarblingTableReceived(index, table_commitment) => {
            handle_table_received(state, artifact_store, index, table_commitment).await?;
        }
        ActionResult::DepositAdaptorsGenerated(
            deposit_id,
            deposit_adaptors,
            withdrawal_adaptors,
        ) => match state.step {
            Step::SetupComplete => {
                let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                    return Err(SMError::UnknownDeposit(deposit_id));
                };

                match deposit_state.step {
                    DepositStep::GeneratingAdaptors => {
                        artifact_store
                            .save_adaptors_for_deposit(
                                deposit_id,
                                &deposit_adaptors,
                                &withdrawal_adaptors,
                            )
                            .await?;

                        deposit_state.step = DepositStep::SendingAdaptors {
                            acked: BitArray::ZERO,
                        };

                        for chunk in
                            create_adaptor_message_chunks(deposit_adaptors, withdrawal_adaptors)
                        {
                            emit(
                                actions,
                                Action::DepositSendAdaptorMsgChunk(deposit_id, chunk),
                            );
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::DepositAdaptorChunkSent(deposit_id) => match state.step {
            Step::SetupComplete => {
                let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                    return Err(SMError::UnknownDeposit(deposit_id));
                };

                match &mut deposit_state.step {
                    DepositStep::SendingAdaptors { acked } => {
                        let ActionId::DepositSendAdaptorMsgChunk(_, chunk_index) = id else {
                            return Err(SMError::InvalidInputData);
                        };
                        let idx = chunk_index as usize;
                        if acked[idx] {
                            return Err(SMError::InvalidInputData);
                        }

                        acked.set(idx, true);

                        if acked.all() {
                            deposit_state.step = DepositStep::DepositReady;
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        ActionResult::TableEvaluationResult(commitment, output_share) => {
            match &mut state.step {
                Step::EvaluatingTables {
                    deposit_id,
                    eval_indices: _,
                    eval_commitments,
                    evaluated,
                } => {
                    let Some(idx) = eval_commitments.iter().position(|c| *c == commitment) else {
                        return Err(SMError::InvalidInputData);
                    };

                    evaluated.set(idx, true);

                    if output_share.is_some() {
                        // Found the fault secret — evaluation complete.
                        // TODO: store output_share, interpolate to recover secret
                        state.step = Step::SetupConsumed {
                            deposit_id: *deposit_id,
                        };
                    } else if evaluated.all() {
                        // All tables evaluated, no fault found.
                        state.step = Step::SetupConsumed {
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

async fn handle_commit_msg_header<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    commit_msg_header: CommitMsgHeader,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForCommit { mut header, chunks } => {
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
                .save_garbling_table_commitments(&garbling_table_commitments)
                .await?;
            artifact_store
                .save_output_polynomial_commitment(&output_polynomial_commitment)
                .await?;

            header = true;

            if !chunks.all() {
                // Stay on same step with updated state
                state.step = Step::WaitingForCommit { header, chunks };
                return Ok(());
            }

            post_handle_commit_msg(state, artifact_store, actions).await
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_commit_msg_chunk<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    commit_msg_chunk: CommitMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForCommit { header, mut chunks } => {
            if !is_valid_commit_chunk(&commit_msg_chunk) {
                state.step = Step::Aborted {
                    reason: "invalid commit msg chunk".into(),
                };
                return Ok(());
            }

            let chunk_idx = commit_msg_chunk.wire_index as usize;
            match chunks.get(chunk_idx).as_deref() {
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

            chunks.set(chunk_idx, true);

            artifact_store
                .save_input_polynomial_commitments_chunk(
                    commit_msg_chunk.wire_index,
                    &commit_msg_chunk.commitments,
                )
                .await?;

            if !header || !chunks.all() {
                // Stay on same step with updated state
                state.step = Step::WaitingForCommit { header, chunks };
                return Ok(());
            }

            post_handle_commit_msg(state, artifact_store, actions).await
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn post_handle_commit_msg<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    // header and all chunks received
    let config = require_config(state)?;
    let challenge_indices = sample_challenge_indices(config.seed);
    debug_assert!(is_sorted(challenge_indices.as_slice()));

    artifact_store
        .save_challenge_indices(&challenge_indices)
        .await?;

    state.step = Step::WaitingForChallengeResponse {
        header: false,
        chunks: BitArray::ZERO,
    };

    let challenge_msg = ChallengeMsg { challenge_indices };
    emit(actions, Action::SendChallengeMsg(challenge_msg));
    Ok(())
}

async fn handle_recv_challenge_response_header<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    response_msg_header: ChallengeResponseMsgHeader,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForChallengeResponse { mut header, chunks } => {
            if !is_valid_challenge_response_header(&response_msg_header) {
                state.step = Step::Aborted {
                    reason: "invalid challenge response message header".into(),
                };
                return Ok(());
            }

            let ChallengeResponseMsgHeader {
                reserved_setup_input_shares,
                opened_output_shares,
                opened_garbling_seeds,
            } = response_msg_header;

            artifact_store
                .save_reserved_setup_input_shares(&reserved_setup_input_shares)
                .await?;
            artifact_store
                .save_opened_output_shares(&opened_output_shares)
                .await?;
            artifact_store
                .save_opened_garbling_seeds(&opened_garbling_seeds)
                .await?;

            header = true;
            if !chunks.all() {
                state.step = Step::WaitingForChallengeResponse { header, chunks };
                return Ok(());
            }

            let challenge_idxs = artifact_store.load_challenge_indices().await?;
            post_handle_challenge_response(challenge_idxs, state, artifact_store, actions).await
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_recv_challenge_response_msg<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    response_msg_chunk: ChallengeResponseMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForChallengeResponse { header, mut chunks } => {
            let challenge_idxs = artifact_store.load_challenge_indices().await?;
            if !is_valid_challenge_response_chunk(&response_msg_chunk, &challenge_idxs) {
                state.step = Step::Aborted {
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
            chunks.set(chunk_idx, true);

            artifact_store
                .save_openend_input_shares_chunk(
                    response_msg_chunk.circuit_index,
                    &response_msg_chunk.shares,
                )
                .await?;

            if !header || !chunks.all() {
                state.step = Step::WaitingForChallengeResponse { header, chunks };
                return Ok(());
            }

            post_handle_challenge_response(challenge_idxs, state, artifact_store, actions).await
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn post_handle_challenge_response<S: ArtifactStore>(
    challenge_idxs: Box<ChallengeIndices>,
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    // all chunks received
    let opened_output_shares = artifact_store.load_opened_output_shares().await?;

    let output_polynomial_commitment = artifact_store.load_output_polynomial_commitment().await?;

    if let Some(failure_reason) =
        verify_opened_output_shares(&opened_output_shares, &output_polynomial_commitment)
    {
        state.step = Step::Aborted {
            reason: format!(
                "opened output share verification failed: {}",
                failure_reason
            ),
        };
        return Ok(());
    }

    let config = require_config(state)?;
    let reserved_setup_input_shares = artifact_store.load_reserved_setup_input_shares().await?;
    let input_polynomial_commitments = artifact_store.load_input_polynomial_commitments().await?;

    if let Some(failure_reason) = verify_reserved_setup_input_shares(
        &reserved_setup_input_shares,
        &config.setup_inputs,
        &input_polynomial_commitments,
    ) {
        state.step = Step::Aborted {
            reason: format!(
                "reserved input share verification failed: {}",
                failure_reason
            ),
        };
        return Ok(());
    }

    state.step = Step::VerifyingOpenedInputShares;

    let opened_input_shares = artifact_store.load_openend_input_shares().await?;
    emit(
        actions,
        Action::VerifyOpenedInputShares(
            challenge_idxs,
            opened_input_shares,
            input_polynomial_commitments,
        ),
    );

    Ok(())
}

// ============================================================================
// Helpers for handle_action_result
// ============================================================================

async fn handle_table_commitment_generated<S: ArtifactStore>(
    state: &mut EvaluatorState,
    artifact_store: &mut S,
    index: Index,
    table_commitment: GarblingTableCommitment,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &mut state.step {
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
                state.step = Step::Aborted {
                    reason: format!("invalid table seed for index {}", index),
                };
                return Ok(());
            }

            verified.set(idx, true);

            if verified.all() {
                let eval_idxs = get_eval_indices(opened_indices);
                debug_assert!(is_sorted(&eval_idxs));

                let garbling_commitments = artifact_store.load_garbling_table_commitments().await?;
                let eval_commitments = get_eval_commitments(&eval_idxs, &garbling_commitments);
                state.step = Step::ReceivingGarblingTables {
                    eval_indices: eval_idxs,
                    eval_commitments,
                    received: BitArray::ZERO,
                };

                emit(actions, Action::ReceiveGarblingTables(eval_commitments));
            }

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_table_received<S: ArtifactStore>(
    state: &mut EvaluatorState,
    _artifact_store: &mut S,
    index: Index,
    table_commitment: GarblingTableCommitment,
) -> SMResult<()> {
    match &mut state.step {
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
                state.step = Step::Aborted {
                    reason: format!("invalid table for index {}", index),
                };
                return Ok(());
            }

            received.set(idx, true);

            if received.all() {
                state.step = Step::SetupComplete;
            }

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

// ============================================================================
// Restore
// ============================================================================

pub(crate) async fn restore<S: ArtifactStore>(
    state_container: &StateContainer<S>,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    let state = state_container.state();
    let artifact_store = state_container.artifact_store();
    match &state.step {
        Step::Uninit => {}
        Step::WaitingForCommit { .. } => {}
        Step::WaitingForChallengeResponse { .. } => {
            let challenge_indices = *artifact_store.load_challenge_indices().await?;
            let challenge_msg = ChallengeMsg { challenge_indices };

            emit(actions, Action::SendChallengeMsg(challenge_msg));
        }
        Step::VerifyingOpenedInputShares => {
            let challenge_idxs = artifact_store.load_challenge_indices().await?;
            let input_polynomial_commitments =
                artifact_store.load_input_polynomial_commitments().await?;

            let opened_input_shares = artifact_store.load_openend_input_shares().await?;

            emit(
                actions,
                Action::VerifyOpenedInputShares(
                    challenge_idxs,
                    opened_input_shares,
                    input_polynomial_commitments,
                ),
            );
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
            eval_commitments, ..
        } => {
            emit(actions, Action::ReceiveGarblingTables(*eval_commitments));
        }
        Step::SetupComplete => {
            for (deposit_id, deposit_state) in state.deposits.iter() {
                match &deposit_state.step {
                    DepositStep::GeneratingAdaptors => {
                        emit(actions, Action::DepositGenerateAdaptors(*deposit_id));
                    }
                    DepositStep::SendingAdaptors { acked } => {
                        let (deposit_adaptors, withdrawal_adaptors) = artifact_store
                            .load_adaptors_for_deposit(*deposit_id)
                            .await?;

                        for chunk in
                            create_adaptor_message_chunks(*deposit_adaptors, *withdrawal_adaptors)
                        {
                            if !acked[chunk.chunk_index as usize] {
                                emit(
                                    actions,
                                    Action::DepositSendAdaptorMsgChunk(*deposit_id, chunk),
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
        .ok_or_else(|| SMError::StateInconsistency("expected config to not be None"))
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
) -> Box<OpenedGarblingTableCommitments> {
    Box::new(std::array::from_fn(|i| {
        let seed_idx = challenge_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    }))
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
    std::array::from_fn(|i| {
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

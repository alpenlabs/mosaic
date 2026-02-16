use bitvec::array::BitArray;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, CommitMsgChunk, DepositAdaptors, EvalGarblingTableCommitments,
    EvaluationIndices, GarblingTableCommitment, Index, InputPolynomialCommitments,
    OpenedGarblingTableCommitments, OpenedOutputShares, PolynomialCommitment,
    ReservedSetupInputShares, Seed, SetupInputs, WithdrawalAdaptors,
    state_machine::evaluator::{
        Action, ActionContainer, ActionId, ActionResult, EvaluatorDepositInitData,
        EvaluatorDisputedWithdrawalData, Input,
    },
};
use mosaic_common::constants::{N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS, N_OPEN_CIRCUITS};

use super::{SMResult, artifact::EvaluatorArtifactStore, emit, state::State};
use crate::{
    SMError,
    evaluator::{
        deposit::{DepositState, DepositStep},
        state::{Config, Step},
    },
};

// ============================================================================
// External event handler
// ============================================================================

/// Handle an external event input (delivered via [`fasm::Input::Normal`]).
///
/// External events are messages from peers, bridge triggers, and initialization
/// — anything that originates outside the state machine.
pub(crate) async fn handle_event<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    input: Input,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match input {
        Input::Init(data) => match state.step {
            Step::Uninit => {
                state.config = Some(Config {
                    seed: data.seed,
                    setup_inputs: data.setup_inputs,
                });
                state.step = Step::WaitingForCommit {
                    chunks: BitArray::ZERO,
                };
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::RecvCommitMsgChunk(commit_msg) => {
            handle_commit_msg_chunk(state, commit_msg, actions).await?;
        }
        Input::RecvChallengeResponseMsgChunk(response_msg) => {
            handle_recv_challenge_response_msg(state, response_msg, actions).await?;
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

                state
                    .artifact_store
                    .save_sighashes_for_deposit(deposit_id, &sighashes)
                    .await?;
                state
                    .artifact_store
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
                        state
                            .artifact_store
                            .save_completed_signatures(deposit_id, &signatures)
                            .await?;

                        state
                            .artifact_store
                            .save_withdrawal_inputs(deposit_id, &withdrawal_inputs)
                            .await?;

                        let challenge_indices =
                            state.artifact_store.load_challenge_indices().await?;
                        let garbling_commitments = state
                            .artifact_store
                            .load_garbling_table_commitments()
                            .await?;

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
pub(crate) async fn handle_action_result<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    id: ActionId,
    result: ActionResult,
    actions: &mut ActionContainer,
) -> SMResult<()> {
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
                    let opened_indices = state.artifact_store.load_challenge_indices().await?;
                    let opened_seeds = state.artifact_store.load_opened_garbling_seeds().await?;
                    let all_table_commitments = state
                        .artifact_store
                        .load_garbling_table_commitments()
                        .await?;
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
            handle_table_commitment_generated(state, index, table_commitment, actions).await?;
        }
        ActionResult::GarblingTableReceived(index, table_commitment) => {
            handle_table_received(state, index, table_commitment).await?;
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
                        state
                            .artifact_store
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

async fn handle_commit_msg_chunk<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    commit_msg_chunk: CommitMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForCommit { chunks } => {
            if !is_valid_commit_chunk(&commit_msg_chunk) {
                state.step = Step::Aborted {
                    reason: "invalid commit msg chunk".into(),
                };
                return Ok(());
            }

            let chunk_idx = commit_msg_chunk.wire_index as usize;
            if chunks[chunk_idx] {
                return Err(SMError::InvalidInputData);
            }

            state
                .artifact_store
                .save_commit_msg_chunk(commit_msg_chunk)
                .await?;

            let received_chunks_count = chunks.count_ones();
            if received_chunks_count < N_COMMIT_MSG_CHUNKS {
                return Ok(());
            }
            if received_chunks_count > N_COMMIT_MSG_CHUNKS {
                return Err(SMError::StateInconsistency(
                    "saved more commit message chunks than expected",
                ));
            }

            // all chunks received
            let config = require_config(state)?;
            let challenge_indices = sample_challenge_indices(config.seed);
            debug_assert!(is_sorted(challenge_indices.as_slice()));

            state
                .artifact_store
                .save_challenge_indices(&challenge_indices)
                .await?;

            state.step = Step::WaitingForChallengeResponse {
                chunks: BitArray::ZERO,
            };

            let challenge_msg = ChallengeMsg { challenge_indices };
            emit(actions, Action::SendChallengeMsg(challenge_msg));
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_recv_challenge_response_msg<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    response_msg_chunk: ChallengeResponseMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForChallengeResponse { chunks } => {
            let challenge_idxs = state.artifact_store.load_challenge_indices().await?;
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

            state
                .artifact_store
                .save_challenge_response_msg_chunk(response_msg_chunk)
                .await?;

            if !chunks.all() {
                return Ok(());
            }

            // all chunks received
            let opened_output_shares = state.artifact_store.load_opened_output_shares().await?;

            let output_polynomial_commitment = state
                .artifact_store
                .load_output_polynomial_commitment()
                .await?;

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
            let reserved_setup_input_shares = state
                .artifact_store
                .load_reserved_setup_input_shares()
                .await?;
            let input_polynomial_commitments = state
                .artifact_store
                .load_input_polynomial_commitments()
                .await?;

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

            let opened_input_shares = state.artifact_store.load_openend_input_shares().await?;
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
        _ => Err(SMError::UnexpectedInput),
    }
}

// ============================================================================
// Helpers for handle_action_result
// ============================================================================

async fn handle_table_commitment_generated<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
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

                let garbling_commitments = state
                    .artifact_store
                    .load_garbling_table_commitments()
                    .await?;
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

async fn handle_table_received<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
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

pub(crate) async fn restore<S: EvaluatorArtifactStore>(
    state: &State<S>,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match &state.step {
        Step::Uninit => {}
        Step::WaitingForCommit { .. } => {}
        Step::WaitingForChallengeResponse { .. } => {
            let challenge_indices = *state.artifact_store.load_challenge_indices().await?;
            let challenge_msg = ChallengeMsg { challenge_indices };

            emit(actions, Action::SendChallengeMsg(challenge_msg));
        }
        Step::VerifyingOpenedInputShares => {
            let challenge_idxs = state.artifact_store.load_challenge_indices().await?;
            let input_polynomial_commitments = state
                .artifact_store
                .load_input_polynomial_commitments()
                .await?;

            let opened_input_shares = state.artifact_store.load_openend_input_shares().await?;

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
                        let (deposit_adaptors, withdrawal_adaptors) = state
                            .artifact_store
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

fn require_config<S>(state: &State<S>) -> SMResult<&Config> {
    state
        .config
        .as_ref()
        .ok_or_else(|| SMError::StateInconsistency("expected config to not be None"))
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
    output_polynomial_commitment: &PolynomialCommitment,
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

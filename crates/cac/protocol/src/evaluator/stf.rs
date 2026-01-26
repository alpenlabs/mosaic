use bitvec::array::BitArray;
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg, ChallengeResponseMsg, CommitMsg,
    EvalGarblingTableCommitments, EvaluationIndices, GarblingTableCommitment, HasMsgId, Index,
    InputPolynomialCommitments, OpenedGarblingTableCommitments, OpenedOutputShares,
    PolynomialCommitment, ReservedSetupInputShares, Seed, SetupInputs,
    state_machine::evaluator::{Action, Input},
};
use mosaic_common::constants::N_OPEN_CIRCUITS;

use super::{SMResult, artifact::EvaluatorArtifactStore, state::State};
use crate::{
    SMError,
    evaluator::state::{Config, Step},
};

pub(crate) async fn stf<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    input: Input,
) -> SMResult<Vec<Action>> {
    let mut actions = vec![];

    match input {
        Input::Init(data) => {
            match state.step {
                Step::Uninit => {
                    // state update
                    state.config = Some(Config {
                        seed: data.seed,
                        setup_inputs: data.setup_inputs,
                    });
                    state.step = Step::WaitingForCommit;
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::RecvCommitMsg(commit_msg) => {
            if let Some(ackd_commit_msg_id) = state.context.ackd_commit_msg_id {
                // a commit message has already been acked.
                // should ack again if its teh same message, ignore if different.
                let incoming_msg_id = commit_msg.id();

                if ackd_commit_msg_id != incoming_msg_id {
                    return Err(SMError::UnexpectedMsgId(incoming_msg_id));
                }

                actions.push(Action::AckCommitMsg(ackd_commit_msg_id));
            } else {
                handle_commit_msg(state, commit_msg, &mut actions).await?;
            }
        }
        // NOTE: This input might be unnecessary
        Input::ChallengeMsgAcked(msg_id) => match state.step {
            Step::WaitingForChallengeResponse => {
                let Some(sent_msg_id) = state.context.sent_challenge_msg_id else {
                    return Err(SMError::StateInconsistency("missing sent_challenge_msg_id"));
                };

                if sent_msg_id != msg_id {
                    return Err(SMError::UnexpectedMsgId(msg_id));
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::RecvChallengeResponseMsg(response_msg) => {
            if let Some(ackd_response_msg_id) = state.context.ackd_challenge_response_msg_id {
                // a challenge response message has already been acked.
                // should ack again if it is the same message, ignore if different.
                let incoming_msg_id = response_msg.id();

                if ackd_response_msg_id != incoming_msg_id {
                    return Err(SMError::UnexpectedMsgId(incoming_msg_id));
                }

                actions.push(Action::AckChallengeResponseMsg(ackd_response_msg_id));
            } else {
                handle_recv_challenge_response_msg(state, response_msg, &mut actions).await?;
            }
        }
        Input::VerifyOpenedInputSharesResult(failure) => match state.step {
            Step::VerifyingOpenedInputShares => {
                if let Some(failure_reason) = failure {
                    // failed exec_verify: 1) Verify opened input shares against polynomial
                    // commitments
                    state.step = Step::Aborted {
                        reason: format!("invalid opened input shares: {}", failure_reason),
                    };
                } else {
                    // success exec_verify: 1) Verify opened input shares against polynomial
                    // commitments

                    let opened_indices = state.artifact_store.load_challenge_indices().await?;
                    let opened_seeds = state.artifact_store.load_opened_garbling_seeds().await?;
                    let all_table_commitments = state
                        .artifact_store
                        .load_garbling_table_commitments()
                        .await?;
                    let opened_commitments =
                        get_opened_commitments(&opened_indices, &all_table_commitments);

                    // generate actions
                    for ii in 0..N_OPEN_CIRCUITS {
                        let index = opened_indices[ii];
                        let seed = opened_seeds[ii];

                        // NOTE: required input and output shares to be fetched by the job directly
                        // from db.
                        actions.push(Action::GenerateTableCommitment(index, seed));
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
        Input::TableCommitmentGenerated(index, table_commitment) => {
            handle_table_commitment_generated(state, index, table_commitment, &mut actions).await?;
        }
        Input::GarblingTableReceived(index, table_commitment) => {
            handle_table_received(state, index, table_commitment).await?;
        }

        _ => unimplemented!(),
    };

    Ok(actions)
}

pub(crate) async fn restore<S: EvaluatorArtifactStore>(state: &State<S>) -> SMResult<Vec<Action>> {
    let mut actions = vec![];
    match &state.step {
        Step::Uninit => {}
        Step::WaitingForCommit => {}
        Step::WaitingForChallengeResponse => {
            let Some(commit_msg_id) = state.context.ackd_commit_msg_id else {
                return Err(SMError::StateInconsistency(
                    "WaitingForChallengeResponse: missing expected ackd_commit_msg_id",
                ));
            };
            let challenge_indices = state.artifact_store.load_challenge_indices().await?;
            let challenge_msg = ChallengeMsg { challenge_indices };
            actions.push(Action::AckCommitMsg(commit_msg_id));
            actions.push(Action::SendChallengeMsg(challenge_msg));
        }
        Step::VerifyingOpenedInputShares => {
            let challenge_idxs = state.artifact_store.load_challenge_indices().await?;
            let input_polynomial_commitments = state
                .artifact_store
                .load_input_polynomial_commitments()
                .await?;

            let opened_input_shares = state.artifact_store.load_openend_input_shares().await?;

            actions.push(Action::VerifyOpenedInputShares(
                challenge_idxs,
                opened_input_shares,
                input_polynomial_commitments,
            ));
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

                // NOTE: required input and output shares to be fetched by the job directly
                // from db.
                actions.push(Action::GenerateTableCommitment(index, seed));
            }
        }
        _ => unimplemented!(),
    }

    Ok(actions)
}

async fn handle_commit_msg<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    commit_msg: CommitMsg,
    actions: &mut Vec<Action>,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForCommit => {
            if !is_valid_commit(&commit_msg) {
                // invalid commit message
                state.step = Step::Aborted {
                    reason: "invalid commit msg".into(),
                };
                return Ok(());
            }

            // state update
            let msg_id = commit_msg.id();
            let config = require_config(state)?;
            let challenge_indices = sample_challenge_indices(config.seed);
            debug_assert!(is_sorted(challenge_indices.as_ref()));

            state
                .artifact_store
                .save_polynomial_commitments(&commit_msg.polynomial_commitments)
                .await?;
            state
                .artifact_store
                .save_garbling_table_commitments(&commit_msg.garbling_table_commitments)
                .await?;
            state
                .artifact_store
                .save_challenge_indices(&challenge_indices)
                .await?;

            state.context.ackd_challenge_response_msg_id = Some(msg_id);
            state.step = Step::WaitingForChallengeResponse;

            // generate actions
            let challenge_msg = ChallengeMsg { challenge_indices };
            actions.push(Action::AckCommitMsg(msg_id));
            actions.push(Action::SendChallengeMsg(challenge_msg));
            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_recv_challenge_response_msg<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    response_msg: ChallengeResponseMsg,
    actions: &mut Vec<Action>,
) -> SMResult<()> {
    match state.step {
        Step::WaitingForChallengeResponse => {
            let challenge_idxs = state.artifact_store.load_challenge_indices().await?;
            if !is_valid_challenge_response(&response_msg, &challenge_idxs) {
                state.step = Step::Aborted {
                    reason: "invalid challenge response message".into(),
                };
                return Ok(());
            }
            let output_polynomial_commitment = state
                .artifact_store
                .load_output_polynomial_commitment()
                .await?;

            // exec_verify: 2) Verify opened output (false) shares
            if let Some(failure_reason) = verify_opened_output_shares(
                &response_msg.opened_output_shares,
                &output_polynomial_commitment,
            ) {
                state.step = Step::Aborted {
                    reason: format!(
                        "opened output share verification failed: {}",
                        failure_reason
                    ),
                };
                return Ok(());
            }

            let config = require_config(state)?;
            let input_polynomial_commitments = state
                .artifact_store
                .load_input_polynomial_commitments()
                .await?;

            // exec_verify: 4) Verify setup input shares against setup input and polynomial
            // commitments
            if let Some(failure_reason) = verify_reserved_setup_input_shares(
                &response_msg.reserved_setup_input_shares,
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

            state
                .artifact_store
                .save_openend_input_shares(&response_msg.opened_input_shares)
                .await?;
            state
                .artifact_store
                .save_reserved_setup_input_shares(&response_msg.reserved_setup_input_shares)
                .await?;
            state
                .artifact_store
                .save_opened_garbling_seeds(&response_msg.opened_garbling_seeds)
                .await?;
            state
                .artifact_store
                .save_opened_garbling_seeds(&response_msg.opened_garbling_seeds)
                .await?;

            state.step = Step::VerifyingOpenedInputShares;

            // generate actions
            // exec_verify: 1) Verify opened input shares against polynomial commitments
            actions.push(Action::VerifyOpenedInputShares(
                challenge_idxs,
                response_msg.opened_input_shares,
                input_polynomial_commitments,
            ));

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

async fn handle_table_commitment_generated<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    index: Index,
    table_commitment: GarblingTableCommitment,
    actions: &mut Vec<Action>,
) -> SMResult<()> {
    match &mut state.step {
        Step::VerifyingTableCommitments {
            opened_indices,
            opened_commitments,
            verified,
            ..
        } => {
            let Ok(idx) = opened_indices.binary_search(&index) else {
                // not an index that we are expecting
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
                // all opened tables are verified
                let eval_idxs = get_eval_indices(opened_indices);
                debug_assert!(is_sorted(&eval_idxs));

                let garbling_commitments = state
                    .artifact_store
                    .load_garbling_table_commitments()
                    .await?;
                let eval_commitments = get_eval_commitments(&eval_idxs, &garbling_commitments);
                state.step = Step::ReceivingGarblingTables {
                    eval_idxs,
                    eval_commitments: eval_commitments.clone(),
                    received: BitArray::ZERO,
                };

                // expect to receive garbling tables with these commitments
                actions.push(Action::ReceiveGarblingTables(eval_commitments));
            }
            // else stay on same step and wait for all tables to be verified

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
            eval_idxs,
            eval_commitments,
            received,
        } => {
            let Some(idx) = eval_idxs.iter().position(|&x| x == index) else {
                // not an index that we are expecting
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
                // all eval tables received and verified
                state.step = Step::SetupComplete;
            }
            // else stay on same step and wait for all tables to be received

            Ok(())
        }
        _ => Err(SMError::UnexpectedInput),
    }
}

fn require_config<S>(state: &State<S>) -> SMResult<&Config> {
    state
        .config
        .as_ref()
        .ok_or_else(|| SMError::StateInconsistency("expected config to not be None"))
}

#[expect(unused_variables)]
fn is_valid_commit(commit_msg: &CommitMsg) -> bool {
    todo!()
}

#[expect(unused_variables)]
fn sample_challenge_indices(seed: Seed) -> Box<ChallengeIndices> {
    todo!()
}

#[expect(unused_variables)]
fn is_valid_challenge_response(
    response_msg: &ChallengeResponseMsg,
    challenge_idxs: &ChallengeIndices,
) -> bool {
    // simple input validations
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

/// Verify opened output shares against polynomial commitments and return failure reason or None.
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
        // eval_indices are 1-indexed (1..=181), garbling_commitments are 0-indexed (0..=180)
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
) -> Box<EvalGarblingTableCommitments> {
    Box::new(std::array::from_fn(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_commitments are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    }))
}

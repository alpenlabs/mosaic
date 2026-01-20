use bitvec::array::BitArray;
use mosaic_cac_types::{
    AdaptorMsg, AllGarblingSeeds, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsg, CommitMsg, EvalGarblingSeeds, EvalGarblingTableCommitments,
    EvaluationIndices, HasMsgId, InputShares, OutputShares, ReservedDepositInputShares,
    ReservedInputShares, ReservedWithdrawalInputShares, Seed, SetupInputs,
    state_machine::garbler::{
        Action, AdaptorVerificationData, CompleteAdaptorSignaturesData, GarblerDepositInitData,
        Input,
    },
};

use super::{
    artifact::GarblerArtifactStore,
    deposit::{DepositState, DepositStep},
    state::{State, Step},
};
use crate::{SMError, SMResult, garbler::state::Config};

pub(crate) async fn stf<S: GarblerArtifactStore>(
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
                    state.step = Step::GeneratingPolynomials;

                    // generate actions
                    let seed = state.config.expect("just set").seed;
                    actions.push(Action::GeneratePolynomials(seed));
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::PolynomialsGenerated(polynomials, commitments) => {
            match state.step {
                Step::GeneratingPolynomials => {
                    // state update
                    state
                        .artifact_store
                        .save_polynomials(polynomials.as_ref())
                        .await?;
                    state
                        .artifact_store
                        .save_polynomial_commitments(commitments.as_ref())
                        .await?;
                    state.step = Step::GeneratingShares;

                    // generate actions
                    actions.push(Action::GenerateShares(polynomials));
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::SharesGenerated(input_shares, output_shares) => {
            match state.step {
                Step::GeneratingShares => {
                    // state update
                    state
                        .artifact_store
                        .save_shares(input_shares.as_ref(), output_shares.as_ref())
                        .await?;

                    state.step = Step::GeneratingTableCommitments;

                    // generate actions
                    let config = require_config(&state)?;
                    let seeds = generate_garbling_table_seeds(config.seed);
                    actions.push(Action::GenerateTableCommitments(
                        Box::new(seeds),
                        input_shares,
                        output_shares,
                    ));
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::TableCommitmentsGenerated(garbling_table_commitments) => {
            match state.step {
                Step::GeneratingTableCommitments => {
                    // state update
                    state
                        .artifact_store
                        .save_garbling_table_commitments(garbling_table_commitments.as_ref())
                        .await?;
                    state.step = Step::SendingCommit;

                    // generate actions
                    let polynomial_commitments =
                        state.artifact_store.load_polynomial_commitments().await?;
                    let commit_msg = CommitMsg {
                        polynomial_commitments,
                        garbling_table_commitments,
                    };
                    actions.push(Action::SendCommitMsg(commit_msg));
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::CommitMsgAcked(msg_id) => match state.step {
            Step::SendingCommit => {
                let Some(sent_msg_id) = state.context.sent_commit_msg_id else {
                    return Err(SMError::StateInconsistency("missing sent_commit_msg_id"));
                };

                if sent_msg_id != msg_id {
                    return Err(SMError::UnexpectedMsgId(msg_id));
                }

                state.step = Step::WaitingForChallenge;
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::RecvChallengeMsg(challenge_msg) => {
            if let Some(ackd_challenge_msg_id) = state.context.ackd_challenge_msg_id {
                // a challenge message has already been acked.
                // should ack again if it is the same message, ignore if different.
                let incoming_msg_id = challenge_msg.id();

                if ackd_challenge_msg_id != incoming_msg_id {
                    return Err(SMError::UnexpectedMsgId(incoming_msg_id));
                }

                actions.push(Action::AckChallengeMsg(ackd_challenge_msg_id));
            } else {
                match state.step {
                    Step::SendingCommit | Step::WaitingForChallenge => {
                        if is_valid_challenge(&challenge_msg) {
                            let msg_id = challenge_msg.id();
                            let (input_shares, output_shares) =
                                state.artifact_store.load_shares().await?;
                            let config = require_config(&state)?;
                            let seeds = generate_garbling_table_seeds(config.seed);
                            let challenge_response_msg = create_challenge_response_msg(
                                challenge_msg.challenge_indices.as_ref(),
                                input_shares,
                                output_shares,
                                seeds,
                                config.setup_inputs,
                            );
                            state
                                .artifact_store
                                .save_challenge_indices(challenge_msg.challenge_indices.as_ref())
                                .await?;
                            state.context.ackd_challenge_msg_id = Some(msg_id);

                            state.step = Step::SendingChallengeResponse;

                            actions.push(Action::AckChallengeMsg(msg_id));
                            actions.push(Action::SendChallengeResponseMsg(challenge_response_msg));
                        } else {
                            // TODO: should this abort, or just ignore and stay at same state ?
                            state.step = Step::Aborted {
                                reason: "invalid challenge msg".into(),
                            };
                        }
                    }
                    _ => return Err(SMError::UnexpectedInput),
                }
            }
        }
        Input::ChallengeResponseAcked(msg_id) => match state.step {
            Step::SendingChallengeResponse => {
                let Some(sent_msg_id) = state.context.sent_challenge_response_msg_id else {
                    return Err(SMError::StateInconsistency(
                        "missing sent_challenge_response_msg_id",
                    ));
                };

                if sent_msg_id != msg_id {
                    return Err(SMError::UnexpectedMsgId(msg_id));
                }

                let challenge_indices = state.artifact_store.load_challenge_indices().await?;
                let eval_indices = get_eval_indices(challenge_indices.as_ref());

                let garbling_table_commitments = state
                    .artifact_store
                    .load_garbling_table_commitments()
                    .await?;
                let eval_commitments =
                    get_eval_commitments(&eval_indices, garbling_table_commitments.as_ref());

                let config = require_config(&state)?;
                let garbling_seeds = generate_garbling_table_seeds(config.seed);
                let eval_seeds = get_eval_seeds(&eval_indices, &garbling_seeds);

                state.step = Step::TransferringGarblingTables {
                    eval_seeds: Box::new(eval_seeds),
                    eval_commitments: Box::new(eval_commitments),
                    transferred: BitArray::ZERO,
                };

                for seed in eval_seeds.as_ref() {
                    actions.push(Action::TransferGarblingTable(*seed));
                }
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::GarblingTableTransferred(garbling_seed, commitment) => match &mut state.step {
            Step::TransferringGarblingTables {
                eval_seeds,
                eval_commitments,
                transferred,
            } => {
                let Some(index) = eval_seeds.iter().enumerate().find_map(|(idx, seed)| {
                    if seed == &garbling_seed {
                        Some(idx)
                    } else {
                        None
                    }
                }) else {
                    return Err(SMError::InvalidInputData);
                };

                if eval_commitments[index] != commitment {
                    return Err(SMError::InvalidInputData);
                }

                transferred.set(index, true);

                if transferred.all() {
                    // all tables are transferred
                    state.step = Step::SetupComplete;
                }
                // else stay on same step and wait all tables to be transferred
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DepositInit(
            deposit_id,
            GarblerDepositInitData {
                pk,
                sighashes,
                deposit_inputs,
            },
        ) => match state.step {
            Step::SetupComplete => {
                if state.deposits.contains_key(&deposit_id) {
                    // deposit already exists
                    return Err(SMError::DepositAlreadyExists(deposit_id));
                }

                state
                    .artifact_store
                    .save_sighashes_for_deposit(deposit_id, sighashes.as_ref())
                    .await?;
                state
                    .artifact_store
                    .save_inputs_for_deposit(deposit_id, deposit_inputs.as_ref())
                    .await?;

                state.deposits.insert(deposit_id, DepositState::init(pk));
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DepositRecvAdaptorMsg(deposit_id, adaptor_msg) => {
            match state.step {
                Step::SetupComplete => {
                    let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                        // deposit does not exist
                        return Err(SMError::UnknownDeposit(deposit_id));
                    };

                    if let Some(ackd_adaptor_msg_id) = deposit_state.ackd_adaptor_msg_id {
                        // an adaptor message has already been acked for this deposit.
                        // should ack again if it is the same message, ignore if different.
                        let incoming_msg_id = adaptor_msg.id();

                        if ackd_adaptor_msg_id != incoming_msg_id {
                            return Err(SMError::UnexpectedMsgId(incoming_msg_id));
                        }

                        actions.push(Action::DepositAckAdaptorMsg(
                            deposit_id,
                            ackd_adaptor_msg_id,
                        ));
                    } else {
                        match deposit_state.step {
                            DepositStep::WaitingForAdaptors => {
                                let msg_id = adaptor_msg.id();
                                let AdaptorMsg {
                                    deposit_adaptors,
                                    withdrawal_adaptors,
                                } = adaptor_msg;
                                state
                                    .artifact_store
                                    .save_adaptors_for_deposit(
                                        deposit_id,
                                        deposit_adaptors.as_ref(),
                                        withdrawal_adaptors.as_ref(),
                                    )
                                    .await?;

                                let (input_shares, _) = state.artifact_store.load_shares().await?;
                                let sighashes = state
                                    .artifact_store
                                    .load_sighashes_for_deposit(deposit_id)
                                    .await?;

                                let adaptor_verif_data = AdaptorVerificationData {
                                    pk: deposit_state.pk,
                                    deposit_adaptors,
                                    withdrawal_adaptors,
                                    input_shares,
                                    sighashes,
                                };

                                deposit_state.ackd_adaptor_msg_id = Some(msg_id);
                                deposit_state.step = DepositStep::VerifyingAdaptors;

                                actions.push(Action::DepositAckAdaptorMsg(deposit_id, msg_id));
                                actions.push(Action::DepositVerifyAdaptors(
                                    deposit_id,
                                    adaptor_verif_data,
                                ));
                            }
                            _ => return Err(SMError::UnexpectedInput),
                        };
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::DepositAdaptorVerificationResult(deposit_id, verification_success) => {
            match state.step {
                Step::SetupComplete => {
                    let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                        // deposit does not exist
                        return Err(SMError::UnknownDeposit(deposit_id));
                    };
                    match deposit_state.step {
                        DepositStep::VerifyingAdaptors => {
                            if verification_success {
                                deposit_state.step = DepositStep::DepositReady;
                            } else {
                                deposit_state.step = DepositStep::Aborted {
                                    reason: "adaptor verification failed".into(),
                                };
                            }
                        }
                        _ => return Err(SMError::UnexpectedInput),
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::DepositUndisputedWithdrawal(deposit_id) => {
            match state.step {
                Step::SetupComplete => {
                    let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                        // deposit does not exist
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
            }
        }
        Input::DisputedWithdrawal(deposit_id, withdrawal_input) => {
            match state.step {
                Step::SetupComplete => {
                    let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                        // deposit does not exist
                        return Err(SMError::UnknownDeposit(deposit_id));
                    };

                    match deposit_state.step {
                        DepositStep::DepositReady => {
                            // next step
                            state.step = Step::CompletingAdaptors { deposit_id };

                            state
                                .artifact_store
                                .save_withdrawal_input(deposit_id, withdrawal_input.as_ref())
                                .await?;

                            let pk = deposit_state.pk;
                            let sighashes = state
                                .artifact_store
                                .load_sighashes_for_deposit(deposit_id)
                                .await?;
                            let (deposit_adaptors, withdrawal_adaptors) = state
                                .artifact_store
                                .load_adaptors_for_deposit(deposit_id)
                                .await?;

                            let reserved_input_shares =
                                state.artifact_store.load_reserved_input_shares().await?;
                            let (reserved_deposit_input_shares, reserved_withdrawal_input_shares) =
                                get_reserved_deposit_withdrawal_shares(reserved_input_shares);

                            actions.push(Action::CompleteAdaptorSignatures(
                                deposit_id,
                                CompleteAdaptorSignaturesData {
                                    pk,
                                    sighashes,
                                    deposit_adaptors,
                                    withdrawal_adaptors,
                                    reserved_deposit_input_shares,
                                    reserved_withdrawal_input_shares,
                                    withdrawal_input,
                                },
                            ));
                        }
                        _ => return Err(SMError::UnexpectedInput),
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::AdaptorSignaturesCompleted(signature_deposit_id, signatures) => {
            match state.step {
                Step::CompletingAdaptors { deposit_id } => {
                    // just in case
                    if signature_deposit_id != deposit_id {
                        return Err(SMError::UnexpectedInput);
                    }

                    state
                        .artifact_store
                        .save_completed_signatures(deposit_id, signatures.as_ref())
                        .await?;

                    // next step
                    state.step = Step::SetupConsumed { deposit_id };
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        _ => unreachable!(),
    };

    Ok(actions)
}

pub(crate) async fn restore<S: GarblerArtifactStore>(state: &State<S>) -> SMResult<Vec<Action>> {
    let mut actions = vec![];

    match &state.step {
        Step::Uninit => {}
        Step::GeneratingPolynomials => {
            let config = require_config(state)?;
            actions.push(Action::GeneratePolynomials(config.seed));
        }
        Step::GeneratingShares => {
            let polynomials = state.artifact_store.load_polynomials().await?;
            actions.push(Action::GenerateShares(polynomials));
        }
        Step::GeneratingTableCommitments => {
            let config = require_config(state)?;
            let seeds = generate_garbling_table_seeds(config.seed);
            let (input_shares, output_shares) = state.artifact_store.load_shares().await?;
            actions.push(Action::GenerateTableCommitments(
                Box::new(seeds),
                input_shares,
                output_shares,
            ));
        }
        Step::SendingCommit => {
            let polynomial_commitments = state.artifact_store.load_polynomial_commitments().await?;
            let garbling_table_commitments = state
                .artifact_store
                .load_garbling_table_commitments()
                .await?;
            let commit_msg = CommitMsg {
                polynomial_commitments,
                garbling_table_commitments,
            };
            actions.push(Action::SendCommitMsg(commit_msg));
        }
        Step::WaitingForChallenge => {}
        Step::SendingChallengeResponse => {
            let Some(challenge_msg_id) = state.context.ackd_challenge_msg_id else {
                return Err(SMError::StateInconsistency(
                    "SendingChallengeResponse: missing expected ackd_challenge_msg_id",
                ));
            };
            let challenge_indices = state.artifact_store.load_challenge_indices().await?;
            let (input_shares, output_shares) = state.artifact_store.load_shares().await?;
            let config = require_config(state)?;
            let seeds = generate_garbling_table_seeds(config.seed);
            let challenge_response_msg = create_challenge_response_msg(
                challenge_indices.as_ref(),
                input_shares,
                output_shares,
                seeds,
                config.setup_inputs,
            );

            // sanity check
            let Some(challenge_response_msg_id) = state.context.sent_challenge_response_msg_id
            else {
                return Err(SMError::StateInconsistency(
                    "SendingChallengeResponse: missing expected sent_challenge_response_msg_id",
                ));
            };
            if challenge_response_msg_id != challenge_response_msg.id() {
                return Err(SMError::StateInconsistency(
                    "SendingChallengeResponse: unexpected challenge_response_msg id",
                ));
            }

            actions.push(Action::AckChallengeMsg(challenge_msg_id));
            actions.push(Action::SendChallengeResponseMsg(challenge_response_msg));
        }
        Step::TransferringGarblingTables {
            eval_seeds,
            transferred,
            ..
        } => {
            for (index, seed) in eval_seeds.iter().enumerate() {
                if transferred[index] {
                    continue;
                }
                actions.push(Action::TransferGarblingTable(*seed));
            }
        }
        Step::SetupComplete => {
            for (deposit_id, deposit_state) in state.deposits.iter() {
                match &deposit_state.step {
                    DepositStep::WaitingForAdaptors => {}
                    DepositStep::VerifyingAdaptors => {
                        let Some(msg_id) = deposit_state.ackd_adaptor_msg_id else {
                            return Err(SMError::StateInconsistency(
                                "missing expected deposit ackd_adaptor_msg_id",
                            ));
                        };

                        let (input_shares, _) = state.artifact_store.load_shares().await?;
                        let sighashes = state
                            .artifact_store
                            .load_sighashes_for_deposit(*deposit_id)
                            .await?;
                        let (deposit_adaptors, withdrawal_adaptors) = state
                            .artifact_store
                            .load_adaptors_for_deposit(*deposit_id)
                            .await?;

                        let adaptor_verif_data = AdaptorVerificationData {
                            pk: deposit_state.pk,
                            deposit_adaptors,
                            withdrawal_adaptors,
                            input_shares,
                            sighashes,
                        };

                        actions.push(Action::DepositAckAdaptorMsg(*deposit_id, msg_id));
                        actions.push(Action::DepositVerifyAdaptors(
                            *deposit_id,
                            adaptor_verif_data,
                        ));
                    }
                    DepositStep::DepositReady => {}
                    DepositStep::WithdrawnUndisputed => {}
                    DepositStep::Aborted { .. } => {}
                }
            }
        }
        Step::CompletingAdaptors { deposit_id } => {
            let Some(deposit_state) = state.deposits.get(deposit_id) else {
                // deposit does not exist
                return Err(SMError::StateInconsistency(
                    "CompletingAdaptors: missing expected deposit",
                ));
            };

            let pk = deposit_state.pk;
            let sighashes = state
                .artifact_store
                .load_sighashes_for_deposit(*deposit_id)
                .await?;
            let (deposit_adaptors, withdrawal_adaptors) = state
                .artifact_store
                .load_adaptors_for_deposit(*deposit_id)
                .await?;

            let reserved_input_shares = state.artifact_store.load_reserved_input_shares().await?;
            let (deposit_input_shares, withdrawal_input_shares) =
                get_reserved_deposit_withdrawal_shares(reserved_input_shares);

            let withdrawal_input = state
                .artifact_store
                .load_withdrawal_input(*deposit_id)
                .await?;

            actions.push(Action::CompleteAdaptorSignatures(
                *deposit_id,
                CompleteAdaptorSignaturesData {
                    pk,
                    sighashes,
                    deposit_adaptors,
                    withdrawal_adaptors,
                    reserved_deposit_input_shares: deposit_input_shares,
                    reserved_withdrawal_input_shares: withdrawal_input_shares,
                    withdrawal_input,
                },
            ));
        }
        Step::SetupConsumed { .. } => {}
        Step::Aborted { .. } => {}
    };

    Ok(actions)
}

fn require_config<S>(state: &State<S>) -> SMResult<Config> {
    state
        .config
        .ok_or_else(|| SMError::StateInconsistency("expected config to not be None"))
}

#[expect(unused_variables)]
fn generate_garbling_table_seeds(base_seed: Seed) -> AllGarblingSeeds {
    todo!()
}

#[expect(unused_variables)]
fn is_valid_challenge(challenge: &ChallengeMsg) -> bool {
    // challenge indices must be in range, must not include 0, etc
    todo!()
}

#[expect(unused_variables)]
fn create_challenge_response_msg(
    challenge_idxs: &ChallengeIndices,
    input_shares: Box<InputShares>,
    output_shares: Box<OutputShares>,
    garbling_seeds: AllGarblingSeeds,
    setup_inputs: SetupInputs,
) -> ChallengeResponseMsg {
    todo!()
}

#[expect(unused_variables)]
fn get_eval_indices(challenge_indices: &ChallengeIndices) -> EvaluationIndices {
    todo!()
}

fn get_eval_seeds(
    eval_indices: &EvaluationIndices,
    garbling_seeds: &AllGarblingSeeds,
) -> EvalGarblingSeeds {
    std::array::from_fn(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_seeds are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_seeds[seed_idx]
    })
}

fn get_eval_commitments(
    eval_indices: &EvaluationIndices,
    garbling_commitments: &AllGarblingTableCommitments,
) -> EvalGarblingTableCommitments {
    std::array::from_fn(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_commitments are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    })
}

#[expect(unused_variables)]
fn get_reserved_deposit_withdrawal_shares(
    reserved_input_shares: Box<ReservedInputShares>,
) -> (
    Box<ReservedDepositInputShares>,
    Box<ReservedWithdrawalInputShares>,
) {
    todo!()
}

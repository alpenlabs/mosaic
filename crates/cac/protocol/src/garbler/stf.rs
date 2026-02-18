use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingSeeds, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk, CommitMsgHeader,
    DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments, EvaluationIndices, HeapArray,
    Index, InputPolynomialCommitments, InputShares, OutputShares, ReservedDepositInputShares,
    ReservedInputShares, ReservedWithdrawalInputShares, Seed, SetupInputs,
    state_machine::garbler::{
        Action, ActionContainer, ActionId, ActionResult, AdaptorVerificationData,
        CompleteAdaptorSignaturesData, GarblerDepositInitData, Input,
    },
};
use mosaic_common::constants::N_CIRCUITS;

use super::{
    artifact::GarblerArtifactStore as ArtifactStore,
    deposit::{DepositState, DepositStep},
    emit,
    state::{Config, GarblerState as State, GarblerStateContainer as StateContainer, Step},
};
use crate::{SMError, SMResult};

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
        Input::Init(data) => {
            match state.step {
                Step::Uninit => {
                    // state update
                    state.config = Some(Config {
                        seed: data.seed,
                        setup_inputs: data.setup_inputs,
                    });

                    state.step = Step::GeneratingPolynomialCommitments;

                    // Polynomial generation + commitment is handled entirely
                    // by the job handler. Polynomials are cached job-side for
                    // the subsequent GenerateShares calls.
                    emit(actions, Action::GeneratePolynomialCommitments(data.seed));
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        Input::RecvChallengeMsg(challenge_msg) => {
            match state.step {
                Step::SendingCommit { .. } | Step::WaitingForChallenge => {
                    if is_valid_challenge(&challenge_msg) {
                        let (input_shares, output_shares) = artifact_store.load_shares().await?;
                        let config = require_config(state)?;
                        let seeds = generate_garbling_table_seeds(config.seed);
                        let (header, chunks) = create_challenge_response_msgs(
                            &challenge_msg.challenge_indices,
                            *input_shares,
                            *output_shares,
                            seeds,
                            config.setup_inputs,
                        );
                        artifact_store
                            .save_challenge_indices(&challenge_msg.challenge_indices)
                            .await?;

                        state.step = Step::SendingChallengeResponse {
                            acked: HeapArray::from_elem(false),
                        };

                        emit(actions, Action::SendChallengeResponseMsgHeader(header));
                        for chunk in chunks {
                            emit(actions, Action::SendChallengeResponseMsgChunk(chunk));
                        }
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

                artifact_store
                    .save_sighashes_for_deposit(deposit_id, sighashes.as_ref())
                    .await?;
                artifact_store
                    .save_inputs_for_deposit(deposit_id, deposit_inputs.as_ref())
                    .await?;

                state.deposits.insert(
                    deposit_id,
                    DepositState {
                        step: DepositStep::WaitingForAdaptors {
                            chunks: HeapArray::from_elem(false),
                        },
                        pk,
                    },
                );
            }
            _ => return Err(SMError::UnexpectedInput),
        },
        Input::DepositRecvAdaptorMsgChunk(deposit_id, adaptor_msg_chunk) => {
            handle_recv_deposit_adaptor_msg_chunk(
                state,
                artifact_store,
                deposit_id,
                adaptor_msg_chunk,
                actions,
            )
            .await?;
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

                            artifact_store
                                .save_withdrawal_input(deposit_id, withdrawal_input.as_ref())
                                .await?;

                            let pk = deposit_state.pk;
                            let sighashes = artifact_store
                                .load_sighashes_for_deposit(deposit_id)
                                .await?;
                            let (deposit_adaptors, withdrawal_adaptors) =
                                artifact_store.load_adaptors_for_deposit(deposit_id).await?;

                            let reserved_input_shares =
                                artifact_store.load_reserved_input_shares().await?;
                            let (reserved_deposit_input_shares, reserved_withdrawal_input_shares) =
                                get_reserved_deposit_withdrawal_shares(&reserved_input_shares);

                            emit(
                                actions,
                                Action::CompleteAdaptorSignatures(
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
                                ),
                            );
                        }
                        _ => return Err(SMError::UnexpectedInput),
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
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
        ActionResult::PolynomialCommitmentsGenerated(commitments) => {
            match state.step {
                Step::GeneratingPolynomialCommitments => {
                    // state update
                    artifact_store
                        .save_polynomial_commitments(&commitments)
                        .await?;
                    state.step = Step::GeneratingShares {
                        generated: HeapArray::from_elem(false),
                    };

                    // generate actions
                    let config = require_config(state)?;
                    for idx in 0..N_CIRCUITS {
                        let index = Index::new(idx + 1).expect("valid index");
                        emit(actions, Action::GenerateShares(config.seed, index));
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        ActionResult::SharesGenerated(index, input_shares, output_shares) => {
            match &mut state.step {
                Step::GeneratingShares { generated } => {
                    let idx = index.get().checked_sub(1).ok_or_else(|| {
                        // not expecting reserved (0) index
                        SMError::InvalidInputData
                    })?;
                    if generated[idx] {
                        // already have this data
                        return Err(SMError::InvalidInputData);
                    }

                    // state update
                    generated[idx] = true;
                    artifact_store
                        .save_shares_for_index(index, input_shares.as_ref(), output_shares.as_ref())
                        .await?;

                    if generated.all() {
                        let config = require_config(state)?;
                        let seeds = Box::new(generate_garbling_table_seeds(config.seed));

                        // generate actions
                        for idx in 0..N_CIRCUITS {
                            let index = Index::new(idx + 1).expect("valid index");
                            let seed = seeds[idx];
                            emit(actions, Action::GenerateTableCommitment(index, seed));
                        }

                        state.step = Step::GeneratingTableCommitments {
                            seeds,
                            generated: HeapArray::from_elem(false),
                        };
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        ActionResult::TableCommitmentGenerated(index, commitment) => {
            match &mut state.step {
                Step::GeneratingTableCommitments { generated, .. } => {
                    let idx = index.get().checked_sub(1).ok_or_else(|| {
                        // not expecting reserved (0) index
                        SMError::InvalidInputData
                    })?;
                    if generated[idx] {
                        // already have this data
                        return Err(SMError::InvalidInputData);
                    }

                    // state update
                    generated[idx] = true;
                    artifact_store
                        .save_garbling_table_commitment(index, &commitment)
                        .await?;

                    if generated.all() {
                        state.step = Step::SendingCommit {
                            acked: HeapArray::from_elem(false),
                        };

                        // generate actions
                        let (input_polynomial_commitments, output_polynomial_commitment) =
                            artifact_store.load_polynomial_commitments().await?;
                        let garbling_table_commitments =
                            artifact_store.load_all_garbling_table_commitments().await?;

                        let commit_msg_header = CommitMsgHeader {
                            garbling_table_commitments,
                            output_polynomial_commitment,
                        };
                        emit(actions, Action::SendCommitMsgHeader(commit_msg_header));
                        for chunk in create_commit_msg_chunks(input_polynomial_commitments) {
                            emit(actions, Action::SendCommitMsgChunk(chunk));
                        }
                    }
                    // else stay on same step and wait for all table commitments to be generated
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        ActionResult::CommitMsgChunkAcked => {
            match &mut state.step {
                Step::SendingCommit { acked } => {
                    let ActionId::SendCommitMsgChunk(wire_index) = id else {
                        return Err(SMError::InvalidInputData);
                    };
                    let idx = wire_index as usize;
                    if acked[idx] {
                        // already acked this chunk
                        return Err(SMError::InvalidInputData);
                    }

                    acked[idx] = true;

                    if acked.all() {
                        state.step = Step::WaitingForChallenge;
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }

        ActionResult::ChallengeResponseChunkAcked => {
            match &mut state.step {
                Step::SendingChallengeResponse { acked } => {
                    let ActionId::SendChallengeResponseMsgChunk(circuit_index) = id else {
                        return Err(SMError::InvalidInputData);
                    };
                    let idx = circuit_index as usize;
                    if acked[idx] {
                        // already acked this chunk
                        return Err(SMError::InvalidInputData);
                    }

                    acked[idx] = true;

                    if acked.all() {
                        let challenge_indices = artifact_store.load_challenge_indices().await?;
                        let eval_indices = get_eval_indices(challenge_indices.as_ref());

                        let garbling_table_commitments =
                            artifact_store.load_all_garbling_table_commitments().await?;
                        let eval_commitments = Box::new(get_eval_commitments(
                            &eval_indices,
                            &garbling_table_commitments,
                        ));

                        let config = require_config(state)?;
                        let garbling_seeds = generate_garbling_table_seeds(config.seed);
                        let eval_seeds = Box::new(get_eval_seeds(&eval_indices, &garbling_seeds));

                        for seed in eval_seeds.as_ref() {
                            emit(actions, Action::TransferGarblingTable(*seed));
                        }

                        state.step = Step::TransferringGarblingTables {
                            eval_seeds,
                            eval_commitments,
                            transferred: HeapArray::from_elem(false),
                        };
                    }
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        ActionResult::GarblingTableTransferred(garbling_seed, commitment) => {
            match &mut state.step {
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

                    transferred[index] = true;

                    if transferred.all() {
                        // all tables are transferred
                        state.step = Step::SetupComplete;
                    }
                    // else stay on same step and wait all tables to be transferred
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }

        ActionResult::DepositAdaptorVerificationResult(deposit_id, verification_success) => {
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
        ActionResult::AdaptorSignaturesCompleted(signature_deposit_id, signatures) => {
            match state.step {
                Step::CompletingAdaptors { deposit_id } => {
                    // just in case
                    if signature_deposit_id != deposit_id {
                        return Err(SMError::UnexpectedInput);
                    }

                    artifact_store
                        .save_completed_signatures(deposit_id, signatures.as_ref())
                        .await?;

                    // next step
                    state.step = Step::SetupConsumed { deposit_id };
                }
                _ => return Err(SMError::UnexpectedInput),
            }
        }
        _ => return Err(SMError::UnexpectedInput),
    };

    Ok(())
}

// ============================================================================
// Deposit adaptor chunk handler (helper for handle_event)
// ============================================================================

async fn handle_recv_deposit_adaptor_msg_chunk<S: ArtifactStore>(
    state: &mut State,
    artifact_store: &mut S,
    deposit_id: DepositId,
    adaptor_msg_chunk: AdaptorMsgChunk,
    actions: &mut ActionContainer,
) -> SMResult<()> {
    match state.step {
        Step::SetupComplete => {
            let Some(deposit_state) = state.deposits.get_mut(&deposit_id) else {
                // deposit does not exist
                return Err(SMError::UnknownDeposit(deposit_id));
            };

            if let DepositStep::WaitingForAdaptors { chunks } = &mut deposit_state.step {
                let chunk_idx = adaptor_msg_chunk.chunk_index as usize;

                if chunks[chunk_idx] {
                    // message for this chunk already seen
                    return Err(SMError::InvalidInputData);
                }

                artifact_store
                    .save_adaptor_msg_chunk_for_deposit(deposit_id, &adaptor_msg_chunk)
                    .await?;

                chunks[chunk_idx] = true;

                if !chunks.all() {
                    // Not all chunks received, wait for more
                    return Ok(());
                }

                // all chunks received

                let (input_shares, _) = artifact_store.load_shares().await?;
                let sighashes = artifact_store
                    .load_sighashes_for_deposit(deposit_id)
                    .await?;
                let (deposit_adaptors, withdrawal_adaptors) =
                    artifact_store.load_adaptors_for_deposit(deposit_id).await?;

                let adaptor_verif_data = AdaptorVerificationData {
                    pk: deposit_state.pk,
                    deposit_adaptors,
                    withdrawal_adaptors,
                    input_shares,
                    sighashes,
                };

                deposit_state.step = DepositStep::VerifyingAdaptors;

                emit(
                    actions,
                    Action::DepositVerifyAdaptors(deposit_id, adaptor_verif_data),
                );
            }
        }
        _ => return Err(SMError::UnexpectedInput),
    };

    Ok(())
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
        Step::GeneratingPolynomialCommitments => {
            let config = require_config(state)?;
            emit(actions, Action::GeneratePolynomialCommitments(config.seed));
        }
        Step::GeneratingShares { generated } => {
            let config = require_config(state)?;
            for idx in 0..N_CIRCUITS {
                if generated[idx] {
                    continue;
                }
                let index = Index::new(idx + 1).expect("valid index");
                emit(actions, Action::GenerateShares(config.seed, index));
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
        Step::SendingCommit { acked } => {
            let (input_polynomial_commitments, output_polynomial_commitment) =
                artifact_store.load_polynomial_commitments().await?;
            let garbling_table_commitments =
                artifact_store.load_all_garbling_table_commitments().await?;

            let commit_msg_header = CommitMsgHeader {
                garbling_table_commitments,
                output_polynomial_commitment,
            };
            emit(actions, Action::SendCommitMsgHeader(commit_msg_header));

            for chunk in create_commit_msg_chunks(input_polynomial_commitments) {
                if !acked[chunk.wire_index as usize] {
                    emit(actions, Action::SendCommitMsgChunk(chunk));
                }
            }
        }
        Step::WaitingForChallenge => {}
        Step::SendingChallengeResponse { acked } => {
            let challenge_indices = artifact_store.load_challenge_indices().await?;
            let (input_shares, output_shares) = artifact_store.load_shares().await?;
            let config = require_config(state)?;
            let seeds = generate_garbling_table_seeds(config.seed);
            let (header, chunks) = create_challenge_response_msgs(
                challenge_indices.as_ref(),
                *input_shares,
                *output_shares,
                seeds,
                config.setup_inputs,
            );
            emit(actions, Action::SendChallengeResponseMsgHeader(header));
            for chunk in chunks {
                if !acked[chunk.circuit_index as usize] {
                    emit(actions, Action::SendChallengeResponseMsgChunk(chunk));
                }
            }
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
                emit(actions, Action::TransferGarblingTable(*seed));
            }
        }
        Step::SetupComplete => {
            for (deposit_id, deposit_state) in state.deposits.iter() {
                match &deposit_state.step {
                    DepositStep::WaitingForAdaptors { .. } => {}
                    DepositStep::VerifyingAdaptors => {
                        let (input_shares, _) = artifact_store.load_shares().await?;
                        let sighashes = artifact_store
                            .load_sighashes_for_deposit(*deposit_id)
                            .await?;
                        let (deposit_adaptors, withdrawal_adaptors) = artifact_store
                            .load_adaptors_for_deposit(*deposit_id)
                            .await?;

                        let adaptor_verif_data = AdaptorVerificationData {
                            pk: deposit_state.pk,
                            deposit_adaptors,
                            withdrawal_adaptors,
                            input_shares,
                            sighashes,
                        };

                        emit(
                            actions,
                            Action::DepositVerifyAdaptors(*deposit_id, adaptor_verif_data),
                        );
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
            let sighashes = artifact_store
                .load_sighashes_for_deposit(*deposit_id)
                .await?;
            let (deposit_adaptors, withdrawal_adaptors) = artifact_store
                .load_adaptors_for_deposit(*deposit_id)
                .await?;

            let reserved_input_shares = artifact_store.load_reserved_input_shares().await?;
            let (deposit_input_shares, withdrawal_input_shares) =
                get_reserved_deposit_withdrawal_shares(&reserved_input_shares);

            let withdrawal_input = artifact_store.load_withdrawal_input(*deposit_id).await?;

            emit(
                actions,
                Action::CompleteAdaptorSignatures(
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
                ),
            );
        }
        Step::SetupConsumed { .. } => {}
        Step::Aborted { .. } => {}
    };

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

fn require_config(state: &State) -> SMResult<&Config> {
    state
        .config
        .as_ref()
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
fn create_commit_msg_chunks(
    polynomial_commitments: InputPolynomialCommitments,
) -> Vec<CommitMsgChunk> {
    todo!()
}

#[expect(unused_variables)]
fn create_challenge_response_msgs(
    challenge_idxs: &ChallengeIndices,
    input_shares: InputShares,
    output_shares: OutputShares,
    garbling_seeds: AllGarblingSeeds,
    setup_inputs: SetupInputs,
) -> (ChallengeResponseMsgHeader, Vec<ChallengeResponseMsgChunk>) {
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
    reserved_input_shares: &ReservedInputShares,
) -> (
    Box<ReservedDepositInputShares>,
    Box<ReservedWithdrawalInputShares>,
) {
    todo!()
}

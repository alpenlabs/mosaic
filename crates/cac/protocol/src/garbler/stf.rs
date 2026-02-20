use std::pin::pin;

use futures::StreamExt;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingSeeds, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CircuitInputShares, CircuitOutputShare,
    CommitMsgChunk, CommitMsgHeader, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments,
    EvaluationIndices, GarblingTableCommitment, HeapArray, Index, InputPolynomialCommitments,
    InputShares, OutputShares, Seed, SetupInputs, state_machine::garbler::*,
};
use mosaic_common::constants::N_CIRCUITS;

use super::emit;
use crate::{ResultOptionExt, SMError, SMResult};

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
        Input::Init(data) => {
            match root_state.step {
                Step::Uninit => {
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

                    emit(actions, Action::GeneratePolynomialCommitments(data.seed));
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        Input::RecvChallengeMsg(challenge_msg) => {
            match root_state.step {
                Step::SendingCommit { .. } | Step::WaitingForChallenge => {
                    if is_valid_challenge(&challenge_msg) {
                        let input_shares = state
                            .get_input_shares()
                            .await
                            .require("expected input shares")?;
                        let output_shares = state
                            .get_output_shares()
                            .await
                            .require("expected output shares")?;
                        let config = require_config(&root_state)?;
                        let seeds = generate_garbling_table_seeds(config.seed);
                        let (header, chunks) = create_challenge_response_msgs(
                            &challenge_msg.challenge_indices,
                            input_shares,
                            output_shares,
                            seeds,
                            config.setup_inputs,
                        );
                        state
                            .put_challenge_indices(&challenge_msg.challenge_indices)
                            .await
                            .map_err(SMError::storage)?;

                        root_state.step = Step::SendingChallengeResponse {
                            acked: HeapArray::from_elem(false),
                        };

                        emit(actions, Action::SendChallengeResponseMsgHeader(header));
                        for chunk in chunks {
                            emit(actions, Action::SendChallengeResponseMsgChunk(chunk));
                        }
                    } else {
                        // TODO: should this abort, or just ignore and stay at same state ?
                        root_state.step = Step::Aborted {
                            reason: "invalid challenge msg".into(),
                        };
                    }
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
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
                    // deposit already exists
                    return Err(SMError::deposit_already_exists(deposit_id));
                }

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
        _ => return Err(SMError::unexpected_input()),
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
        .ok_or_else(|| SMError::MissingRootState)?;

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
        ActionResult::TableCommitmentGenerated(index, commitment) => {
            handle_table_commitment_generated(&mut root_state, state, index, commitment, actions)
                .await?;
        }
        ActionResult::CommitMsgChunkAcked => {
            match &mut root_state.step {
                Step::SendingCommit { acked } => {
                    let ActionId::SendCommitMsgChunk(wire_index) = id else {
                        return Err(SMError::invalid_input_data());
                    };
                    let idx = wire_index as usize;
                    if acked[idx] {
                        // already acked this chunk
                        return Err(SMError::duplicate_action());
                    }

                    acked[idx] = true;

                    if acked.all() {
                        root_state.step = Step::WaitingForChallenge;
                    }
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }

        ActionResult::ChallengeResponseChunkAcked => {
            match &mut root_state.step {
                Step::SendingChallengeResponse { acked } => {
                    let ActionId::SendChallengeResponseMsgChunk(circuit_index) = id else {
                        return Err(SMError::invalid_input_data());
                    };
                    let idx = circuit_index as usize;
                    if acked[idx] {
                        // already acked this chunk
                        return Err(SMError::invalid_input_data());
                    }

                    acked[idx] = true;

                    if acked.all() {
                        let challenge_indices = state
                            .get_challenge_indices()
                            .await
                            .require("expected challenge indices")?;
                        let eval_indices = get_eval_indices(&challenge_indices);

                        let garbling_table_commitments = state
                            .get_all_garbling_table_commitments()
                            .await
                            .require("expected garbling table commitments")?;

                        let eval_commitments =
                            get_eval_commitments(&eval_indices, &garbling_table_commitments);

                        let config = require_config(&root_state)?;
                        let garbling_seeds = generate_garbling_table_seeds(config.seed);
                        let eval_seeds = get_eval_seeds(&eval_indices, &garbling_seeds);

                        for seed in &eval_seeds {
                            emit(actions, Action::TransferGarblingTable(*seed));
                        }

                        root_state.step = Step::TransferringGarblingTables {
                            eval_seeds,
                            eval_commitments,
                            transferred: HeapArray::from_elem(false),
                        };
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
                    transferred,
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

                    transferred[index] = true;

                    if transferred.all() {
                        // all tables are transferred
                        root_state.step = Step::SetupComplete;
                    }
                    // else stay on same step and wait all tables to be transferred
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }

        ActionResult::DepositAdaptorVerificationResult(deposit_id, verification_success) => {
            match root_state.step {
                Step::SetupComplete => {
                    let mut deposit_state = require_deposit(state, &deposit_id).await?;
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

                    // next step
                    root_state.step = Step::SetupConsumed { deposit_id };
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        _ => return Err(SMError::unexpected_input()),
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

            // NOTE: 0 is reserved index
            emit(actions, Action::GenerateShares(Index::reserved()));
            for idx in 1..N_CIRCUITS + 1 {
                let index = Index::new(idx).expect("valid ckt index");
                emit(actions, Action::GenerateShares(config.seed, index));
            }
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
            state
                .put_garbling_table_commitment(index, &commitment)
                .await
                .map_err(SMError::storage)?;

            if !generated.all() {
                // wait for all commitments to be generated.
                return Ok(());
            }
            root_state.step = Step::SendingCommit {
                acked: HeapArray::from_elem(false),
            };

            // generate actions
            let input_polynomial_commitments = state
                .get_input_polynomial_commitments()
                .await
                .require("expected input polynomial commitments")?;
            let output_polynomial_commitment = state
                .get_output_polynomial_commitment()
                .await
                .require("expected output polynomial commitment")?;
            let garbling_table_commitments = state
                .get_all_garbling_table_commitments()
                .await
                .require("expected garbling table commitments")?;

            let commit_msg_header = CommitMsgHeader {
                garbling_table_commitments,
                output_polynomial_commitment,
            };
            emit(actions, Action::SendCommitMsgHeader(commit_msg_header));
            for chunk in create_commit_msg_chunks(input_polynomial_commitments) {
                emit(actions, Action::SendCommitMsgChunk(chunk));
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
    match root_state.step {
        Step::SetupComplete => {
            let mut deposit_state = require_deposit(state, &deposit_id).await?;

            if let DepositStep::WaitingForAdaptors { chunks } = &mut deposit_state.step {
                let chunk_idx = adaptor_msg_chunk.chunk_index as usize;

                if chunks[chunk_idx] {
                    // message for this chunk already seen
                    return Err(SMError::invalid_input_data());
                }

                state
                    .put_adaptor_msg_chunk_for_deposit(&deposit_id, &adaptor_msg_chunk)
                    .await
                    .map_err(SMError::storage)?;

                chunks[chunk_idx] = true;

                if !chunks.all() {
                    // Not all chunks received, wait for more
                    return Ok(());
                }

                // all chunks received
                deposit_state.step = DepositStep::VerifyingAdaptors;

                emit(actions, Action::DepositVerifyAdaptors(deposit_id));
            }

            state
                .put_deposit(deposit_id, &deposit_state)
                .await
                .map_err(SMError::storage)?;
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
        .ok_or_else(|| SMError::MissingRootState)?;

    match &root_state.step {
        Step::Uninit => {}
        Step::GeneratingPolynomialCommitments { .. } => {
            let config = require_config(&root_state)?;

            emit(actions, Action::GeneratePolynomialCommitments(config.seed));
        }
        Step::GeneratingShares { generated } => {
            let config = require_config(&root_state)?;
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
            let input_polynomial_commitments = state
                .get_input_polynomial_commitments()
                .await
                .require("expected input polynomial commitments")?;
            let output_polynomial_commitment = state
                .get_output_polynomial_commitment()
                .await
                .require("expected output polynomial commitment")?;
            let garbling_table_commitments = state
                .get_all_garbling_table_commitments()
                .await
                .require("expected garbling table commitments")?;

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
            let challenge_indices = state
                .get_challenge_indices()
                .await
                .require("expected challenge indices")?;
            let input_shares = state
                .get_input_shares()
                .await
                .require("expected input shares")?;
            let output_shares = state
                .get_output_shares()
                .await
                .require("expected output shares")?;
            let config = require_config(&root_state)?;
            let seeds = generate_garbling_table_seeds(config.seed);
            let (header, chunks) = create_challenge_response_msgs(
                &challenge_indices,
                input_shares,
                output_shares,
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
        _ => unimplemented!(),
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
    state: &mut S,
    deposit_id: &DepositId,
) -> SMResult<DepositState> {
    state
        .get_deposit(deposit_id)
        .await
        .map_err(SMError::storage)?
        .ok_or_else(|| SMError::unknown_deposit(*deposit_id))
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
    HeapArray::new(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_seeds are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_seeds[seed_idx]
    })
}

fn get_eval_commitments(
    eval_indices: &EvaluationIndices,
    garbling_commitments: &AllGarblingTableCommitments,
) -> EvalGarblingTableCommitments {
    HeapArray::new(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_commitments are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    })
}

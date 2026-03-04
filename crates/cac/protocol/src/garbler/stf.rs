use std::pin::pin;

use futures::StreamExt;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingSeeds, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CircuitInputShares, CircuitOutputShare,
    CommitMsgChunk, CommitMsgHeader, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments,
    EvaluationIndices, GarblingTableCommitment, HeapArray, Index, InputPolynomialCommitments,
    InputShares, OpenedGarblingSeeds, OpenedOutputShares, OutputShares, ReservedInputShares,
    ReservedSetupInputShares, Seed, SetupInputs, Share, WideLabelWireShares,
    state_machine::garbler::*,
};
use mosaic_common::{
    Byte32,
    constants::{
        N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
        WIDE_LABEL_VALUE_COUNT,
    },
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

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

                    emit(
                        actions,
                        Action::GeneratePolynomialCommitments(data.seed, Wire::Output),
                    );
                    for wire_idx in 0..N_INPUT_WIRES {
                        emit(
                            actions,
                            Action::GeneratePolynomialCommitments(
                                data.seed,
                                Wire::Input(wire_idx as u16),
                            ),
                        );
                    }
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
                        let garbling_table_meta: Vec<Byte32> = state
                            .get_all_garbling_table_metadata()
                            .await
                            .require("expected garbling table metadata")?
                            .iter()
                            .map(|x| x.output_label_ct)
                            .collect();
                        let eval_indices = get_eval_indices(&challenge_msg.challenge_indices);
                        let garbling_table_meta_unchallenged: Vec<Byte32> = eval_indices
                            .iter()
                            .map(|i| garbling_table_meta[i.get()])
                            .collect();
                        let (header, chunks) = create_challenge_response_msgs(
                            &challenge_msg.challenge_indices,
                            input_shares,
                            output_shares,
                            seeds,
                            config.setup_inputs,
                            garbling_table_meta_unchallenged,
                        );
                        state
                            .put_challenge_indices(&challenge_msg.challenge_indices)
                            .await
                            .map_err(SMError::storage)?;

                        root_state.step = Step::SendingChallengeResponse {
                            header_acked: false,
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
        ActionResult::CommitMsgHeaderAcked => match &mut root_state.step {
            Step::SendingCommit {
                header_acked,
                acked,
            } => {
                let ActionId::SendCommitMsgHeader = id else {
                    return Err(SMError::invalid_input_data());
                };
                *header_acked = true;
                if acked.all() && *header_acked {
                    root_state.step = Step::WaitingForChallenge;
                }
            }
            _ => return Err(SMError::unexpected_input()),
        },
        ActionResult::CommitMsgChunkAcked => {
            match &mut root_state.step {
                Step::SendingCommit {
                    header_acked,
                    acked,
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

                    if acked.all() && *header_acked {
                        root_state.step = Step::WaitingForChallenge;
                    }
                }
                _ => return Err(SMError::unexpected_input()),
            }
        }
        ActionResult::ChallengeResponseHeaderAcked => match &mut root_state.step {
            Step::SendingChallengeResponse {
                header_acked,
                acked: _,
            } => {
                let ActionId::SendChallengeResponseMsgHeader = id else {
                    return Err(SMError::invalid_input_data());
                };
                *header_acked = true;
            }
            _ => return Err(SMError::unexpected_input()),
        },
        ActionResult::ChallengeResponseChunkAcked => {
            match &mut root_state.step {
                Step::SendingChallengeResponse {
                    header_acked,
                    acked,
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
                        .unwrap();
                    if acked[challenge_index_pos] {
                        // already acked this chunk
                        return Err(SMError::invalid_input_data());
                    }

                    acked[challenge_index_pos] = true;

                    if *header_acked && acked.all() {
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

                        for i in 0..eval_seeds.len() {
                            emit(actions, Action::TransferGarblingTable(eval_seeds[i], eval_commitments[i]));
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
                    *output = true;
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
            emit(
                actions,
                Action::GenerateShares(config.seed, Index::reserved()),
            );
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
            state
                .put_garbling_table_commitment(index, &commitment)
                .await
                .map_err(SMError::storage)?;

            state
                .pub_garbling_metadata(index, &metadata)
                .await
                .map_err(SMError::storage)?;

            if !generated.all() {
                // wait for all commitments to be generated.
                return Ok(());
            }
            root_state.step = Step::SendingCommit {
                header_acked: false,
                acked: HeapArray::from_elem(false),
            };

            let garbling_table_commitments = state
                .get_all_garbling_table_commitments()
                .await
                .unwrap()
                .unwrap();
            let output_polynomial_commitment = state
                .get_output_polynomial_commitment()
                .await
                .unwrap()
                .unwrap();
            let metadata = state
                .get_all_garbling_table_metadata()
                .await
                .unwrap()
                .unwrap();
            let all_aes128_keys = HeapArray::from_vec(
                metadata
                    .iter()
                    .map(|x| x.aes128_key)
                    .collect::<Vec<[u8; 16]>>(),
            );
            let all_public_s = HeapArray::from_vec(
                metadata
                    .iter()
                    .map(|x| x.public_s)
                    .collect::<Vec<[u8; 16]>>(),
            );
            let all_constant_zero_labels = HeapArray::from_vec(
                metadata
                    .iter()
                    .map(|x| x.constant_zero_label)
                    .collect::<Vec<[u8; 16]>>(),
            );
            let all_constant_one_labels = HeapArray::from_vec(
                metadata
                    .iter()
                    .map(|x| x.constant_one_label)
                    .collect::<Vec<[u8; 16]>>(),
            );

            let commit_msg_header: CommitMsgHeader = CommitMsgHeader {
                garbling_table_commitments,
                output_polynomial_commitment,
                all_aes128_keys,
                all_public_s,
                all_constant_zero_labels,
                all_constant_one_labels,
            };
            emit(actions, Action::SendCommitMsgHeader(commit_msg_header));

            // Create commit msg chunks
            let input_poly_commits = state
                .get_input_polynomial_commitments()
                .await
                .unwrap()
                .unwrap();
            input_poly_commits
                .into_iter()
                .enumerate()
                .for_each(|(wire_index, commitments)| {
                    let chunk = CommitMsgChunk {
                        wire_index: wire_index as u16,
                        commitments,
                    };
                    emit(actions, Action::SendCommitMsgChunk(chunk));
                });
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
        Step::GeneratingPolynomialCommitments { inputs, output } => {
            let config = require_config(&root_state)?;

            if !output {
                emit(
                    actions,
                    Action::GeneratePolynomialCommitments(config.seed, Wire::Output),
                );
            }
            for (wire_idx, generated) in inputs.iter().enumerate() {
                if *generated {
                    continue;
                }
                emit(
                    actions,
                    Action::GeneratePolynomialCommitments(
                        config.seed,
                        Wire::Input(wire_idx as u16),
                    ),
                );
            }
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
        Step::SendingCommit {
            header_acked,
            acked: _,
        } => {
            todo!()
            // TODO(sapinb): restore SendCommitMsgHeader + SendCommitMsgChunk
            // emission once CommitMsgHeader fields are populated. See #72.
        }
        Step::WaitingForChallenge => {}
        Step::SendingChallengeResponse {
            header_acked,
            acked,
        } => {
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
                todo!(),
            );
            if !*header_acked {
                emit(actions, Action::SendChallengeResponseMsgHeader(header));
            }
            for chunk in chunks {
                if !acked[chunk.circuit_index as usize] {
                    emit(actions, Action::SendChallengeResponseMsgChunk(chunk));
                }
            }
        }
        Step::TransferringGarblingTables {
            eval_seeds,
            eval_commitments,
            transferred,
            ..
        } => {
            for (index, seed) in eval_seeds.iter().enumerate() {
                if transferred[index] {
                    continue;
                }
                emit(actions, Action::TransferGarblingTable(*seed, eval_commitments[index]));
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

fn generate_garbling_table_seeds(base_seed: Seed) -> AllGarblingSeeds {
    let mut rng = ChaCha20Rng::from_seed(base_seed.into()); // modify base seed ?
    let garbling_seeds = (0..N_CIRCUITS)
        .into_iter()
        .map(|_| {
            let mut bytes: [u8; 32] = [0; 32];
            rng.fill_bytes(&mut bytes);
            Byte32::from(bytes)
        })
        .collect::<Vec<Byte32>>();
    HeapArray::from_vec(garbling_seeds)
}

#[expect(unused_variables)]
fn is_valid_challenge(challenge: &ChallengeMsg) -> bool {
    // challenge indices must be in range, must not include 0, etc
    true
}

fn create_challenge_response_msgs(
    challenge_idxs: &ChallengeIndices,
    input_shares: InputShares,
    output_shares: OutputShares,
    garbling_seeds: AllGarblingSeeds,
    setup_inputs: SetupInputs,
    output_cts: Vec<Byte32>,
) -> (ChallengeResponseMsgHeader, Vec<ChallengeResponseMsgChunk>) {
    let (header, _) = create_challenge_response_msg_header(
        challenge_idxs,
        &input_shares,
        &output_shares,
        garbling_seeds,
        setup_inputs,
        HeapArray::from_vec(output_cts),
    );
    let chunks = create_challenge_response_msg_chunks(challenge_idxs, &input_shares);
    (header, chunks)
}

fn create_challenge_response_msg_chunks(
    challenge_indices: &ChallengeIndices,
    input_shares: &InputShares,
) -> Vec<ChallengeResponseMsgChunk> {
    let mut open_input_shares: Vec<ChallengeResponseMsgChunk> = Vec::with_capacity(N_OPEN_CIRCUITS);
    for i in 0..N_OPEN_CIRCUITS {
        let idx = challenge_indices[i].get();
        let mut selected_input_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
        for j in 0..N_INPUT_WIRES {
            let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
            for k in 0..WIDE_LABEL_VALUE_COUNT {
                wide_shares.push(input_shares[idx][j][k].clone());
            }
            selected_input_shares.push(HeapArray::from_vec(wide_shares));
        }
        open_input_shares.push(ChallengeResponseMsgChunk {
            circuit_index: idx as u16,
            shares: HeapArray::from_vec(selected_input_shares),
        });
    }
    open_input_shares
}

fn create_challenge_response_msg_header(
    challenge_idxs: &ChallengeIndices,
    all_input_shares: &InputShares,
    all_output_shares: &OutputShares,
    garbling_seeds: AllGarblingSeeds,
    setup_input: SetupInputs,
    unchallenged_output_label_cts: HeapArray<Byte32, N_EVAL_CIRCUITS>,
) -> (ChallengeResponseMsgHeader, ReservedInputShares) {
    fn get_reserved_input_shares(input_shares: &InputShares) -> Box<ReservedInputShares> {
        let mut selected_input_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
        for i in 0..N_INPUT_WIRES {
            let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
            for j in 0..WIDE_LABEL_VALUE_COUNT {
                wide_shares.push(input_shares[0][i][j].clone());
            }
            selected_input_shares.push(HeapArray::from_vec(wide_shares));
        }
        let input_shares: CircuitInputShares = HeapArray::from_vec(selected_input_shares);
        Box::new(input_shares)
    }

    // evaluate the output false polynomial at the challenge indices
    let opened_output_shares: OpenedOutputShares = HeapArray::from_vec(
        challenge_idxs
            .map(|idx| all_output_shares[idx.get()].clone())
            .to_vec(),
    );

    // evaluate each input polynomial at the reserved i=0 index
    let reserved_input_shares: Box<ReservedInputShares> =
        get_reserved_input_shares(&all_input_shares);

    // take 0..N_SETUP_INPUT_WIRES indices and
    let reserved_setup_input_shares: ReservedSetupInputShares = HeapArray::from_vec(
        (0..N_SETUP_INPUT_WIRES)
            .into_iter()
            .map(|i| reserved_input_shares[i][setup_input[i] as usize].clone())
            .collect(),
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

    (
        ChallengeResponseMsgHeader {
            reserved_setup_input_shares,
            opened_output_shares,
            opened_garbling_seeds,
            unchallenged_output_label_cts,
        },
        *reserved_input_shares,
    )
}

fn get_eval_indices(challenge_indices: &ChallengeIndices) -> EvaluationIndices {
    let challenged_indices: Vec<usize> = challenge_indices
        .iter()
        .map(|x| x.get())
        .collect::<Vec<usize>>();
    let unchallenged_indices: [Index; N_EVAL_CIRCUITS] = (1..=N_CIRCUITS)
        .into_iter()
        .filter(|id| !challenged_indices.contains(id))
        .map(|id| Index::new(id).unwrap())
        .collect::<Vec<Index>>()
        .try_into()
        .expect("unchallenge length");
    unchallenged_indices
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

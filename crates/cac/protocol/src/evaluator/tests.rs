use std::collections::BTreeSet;

use fasm::actions::Action as FasmAction;
use mosaic_cac_types::{
    ChallengeIndices, ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk,
    CommitMsgHeader, DepositId, EvaluationIndices, HeapArray, Index, Polynomial,
    state_machine::evaluator::{Action, EvaluatorState, Input, StateMut, Step},
};
use mosaic_common::constants::N_EVAL_CIRCUITS;
use mosaic_storage_inmemory::evaluator::StoredEvaluatorState;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::stf::{handle_event, restore};
use crate::evaluator::stf::get_remaining_challenge_response_chunks;

#[tokio::test]
async fn restore_evaluating_tables_replays_only_pending_tables() {
    let mut state = StoredEvaluatorState::default();
    let deposit_id = DepositId::from([42; 32]);
    let eval_indices: EvaluationIndices =
        std::array::from_fn(|i| Index::new(i + 1).expect("valid index"));
    let eval_indices_for_state: EvaluationIndices =
        std::array::from_fn(|i| Index::new(i + 1).expect("valid index"));
    let eval_commitments = HeapArray::new(|i| [i as u8; 32].into());
    let mut evaluated = HeapArray::from_elem(false);
    evaluated[1] = true;

    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::EvaluatingTables {
                deposit_id,
                eval_indices: eval_indices_for_state,
                eval_commitments: eval_commitments.clone(),
                evaluated: evaluated.clone(),
            },
        })
        .await
        .expect("write root state");

    let mut actions = Vec::new();
    restore(&state, &mut actions)
        .await
        .expect("restore succeeds");

    let expected_actions = (0..N_EVAL_CIRCUITS).filter(|idx| !evaluated[*idx]).count();
    assert_eq!(actions.len(), expected_actions);

    let mut emitted_positions = BTreeSet::new();
    for action in actions {
        let FasmAction::Tracked(tracked) = action;
        let (_id, action) = tracked.into_parts();
        let Action::EvaluateGarblingTable(index, commitment) = action else {
            panic!("unexpected action emitted during EvaluatingTables restore");
        };
        let pos = eval_indices
            .iter()
            .position(|candidate| *candidate == index)
            .expect("restore emitted unknown evaluation index");
        assert_eq!(commitment, eval_commitments[pos]);
        assert!(
            !evaluated[pos],
            "restore must not re-emit already completed evaluations"
        );
        emitted_positions.insert(pos);
    }

    for pos in 0..N_EVAL_CIRCUITS {
        if !evaluated[pos] {
            assert!(
                emitted_positions.contains(&pos),
                "missing pending evaluation replay at index {pos}"
            );
        }
    }
}

#[tokio::test]
async fn restore_setup_consumed_and_aborted_emit_nothing() {
    let mut state = StoredEvaluatorState::default();
    let mut actions = Vec::new();

    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::SetupConsumed {
                deposit_id: DepositId::from([7; 32]),
                success: false,
            },
        })
        .await
        .expect("write setup consumed state");
    restore(&state, &mut actions)
        .await
        .expect("restore setup consumed succeeds");
    assert!(actions.is_empty());

    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::Aborted {
                reason: "test".into(),
            },
        })
        .await
        .expect("write aborted state");
    restore(&state, &mut actions)
        .await
        .expect("restore aborted succeeds");
    assert!(actions.is_empty());
}

#[tokio::test]
async fn restore_waiting_for_challenge_response_replays_only_before_receipt() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).expect("valid index"));
    state
        .put_challenge_indices(&challenge_indices)
        .await
        .expect("store challenge indices");

    let mut actions = Vec::new();
    let all_chunks_remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: false,
                remaining_chunks: all_chunks_remaining,
            },
        })
        .await
        .expect("write waiting state");
    restore(&state, &mut actions)
        .await
        .expect("restore waiting state succeeds");
    assert_eq!(
        actions.len(),
        1,
        "challenge should replay before any response"
    );
    let first = actions.pop().expect("one action emitted");
    let FasmAction::Tracked(tracked) = first;
    let (_id, action) = tracked.into_parts();
    match action {
        Action::SendChallengeMsg(msg) => assert_eq!(msg.challenge_indices, challenge_indices),
        _ => panic!("unexpected replay action in WaitingForChallengeResponse"),
    }

    actions.clear();
    let mut remaining_chunks = get_remaining_challenge_response_chunks(&challenge_indices);
    let remaining_idx = remaining_chunks
        .iter()
        .position(|&v| v)
        .expect("must exist");
    remaining_chunks[remaining_idx] = false;
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: true,
                remaining_chunks,
            },
        })
        .await
        .expect("write partially received state");
    restore(&state, &mut actions)
        .await
        .expect("restore partial response state succeeds");
    assert!(
        actions.is_empty(),
        "challenge must not replay after response receipt begins"
    );
}

// ============================================================================
// "Ack and ignore" tests
//
// Each test puts the STF in a step where the incoming message is no longer
// relevant (the machine already advanced past it), and asserts that
// handle_event returns Ok(()) with an empty action queue.
// ============================================================================

/// Helper: build a dummy `CommitMsgHeader` with arbitrary but valid-shaped data.
fn dummy_commit_msg_header() -> CommitMsgHeader {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let poly_commitment = Polynomial::rand(&mut rng).commit();
    CommitMsgHeader {
        garbling_table_commitments: HeapArray::new(|i| [i as u8; 32].into()),
        output_polynomial_commitment: HeapArray::from_elem(poly_commitment.clone()),
        all_aes128_keys: HeapArray::from_elem([0u8; 16]),
        all_public_s: HeapArray::from_elem([0u8; 16]),
        all_constant_zero_labels: HeapArray::from_elem([0u8; 16]),
        all_constant_one_labels: HeapArray::from_elem([0u8; 16]),
    }
}

/// Helper: build a dummy `CommitMsgChunk` for the given wire index.
fn dummy_commit_msg_chunk(wire_index: u16) -> CommitMsgChunk {
    let mut rng = ChaCha20Rng::seed_from_u64(100);
    let poly_commitment = Polynomial::rand(&mut rng).commit();
    CommitMsgChunk {
        wire_index,
        commitments: HeapArray::from_elem(poly_commitment),
    }
}

/// Helper: build a dummy `ChallengeResponseMsgHeader`.
fn dummy_challenge_response_header() -> ChallengeResponseMsgHeader {
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    let dummy_share = Polynomial::rand(&mut rng).eval(Index::new(1).unwrap());
    ChallengeResponseMsgHeader {
        reserved_setup_input_shares: HeapArray::from_elem(dummy_share),
        opened_output_shares: HeapArray::from_elem(dummy_share),
        opened_garbling_seeds: HeapArray::from_elem([0u8; 32].into()),
        unchallenged_output_label_cts: HeapArray::from_elem([0u8; 32].into()),
    }
}

/// Helper: build a dummy `ChallengeResponseMsgChunk` for the given circuit index.
fn dummy_challenge_response_chunk(circuit_index: u16) -> ChallengeResponseMsgChunk {
    let mut rng = ChaCha20Rng::seed_from_u64(102);
    let dummy_share = Polynomial::rand(&mut rng).eval(Index::new(1).unwrap());
    ChallengeResponseMsgChunk {
        circuit_index,
        shares: HeapArray::from_elem(HeapArray::from_elem(dummy_share)),
    }
}

#[tokio::test]
async fn duplicate_commit_header_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForCommit {
                header: true,
                chunks: HeapArray::from_elem(false),
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvCommitMsgHeader(dummy_commit_msg_header()),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn commit_header_after_waiting_for_challenge_response_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: false,
                remaining_chunks: remaining,
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvCommitMsgHeader(dummy_commit_msg_header()),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn duplicate_commit_chunk_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    let mut chunks = HeapArray::from_elem(false);
    chunks[0] = true; // chunk 0 already received
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForCommit {
                header: false,
                chunks,
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvCommitMsgChunk(dummy_commit_msg_chunk(0)), // duplicate wire 0
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn commit_chunk_after_waiting_for_challenge_response_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: false,
                remaining_chunks: remaining,
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvCommitMsgChunk(dummy_commit_msg_chunk(0)),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn duplicate_challenge_response_header_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: true, // already received
                remaining_chunks: remaining,
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgHeader(dummy_challenge_response_header()),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn challenge_response_header_after_verifying_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::VerifyingOpenedInputShares,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgHeader(dummy_challenge_response_header()),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn duplicate_challenge_response_chunk_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let mut remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    // Mark first challenge index's chunk as already received.
    let first_challenge_idx = challenge_indices[0].get() - 1;
    remaining[first_challenge_idx] = false;
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::WaitingForChallengeResponse {
                header: false,
                remaining_chunks: remaining,
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    // Send same chunk again (circuit_index is 1-based).
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgChunk(dummy_challenge_response_chunk(
            challenge_indices[0].get() as u16,
        )),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn challenge_response_chunk_after_verifying_is_ack_and_ignore() {
    let mut state = StoredEvaluatorState::default();
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::VerifyingOpenedInputShares,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgChunk(dummy_challenge_response_chunk(1)),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

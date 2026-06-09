use std::collections::BTreeSet;

use fasm::actions::Action as FasmAction;
use mosaic_cac_types::{
    ChallengeIndices, ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk,
    CommitMsgHeader, DepositId, EvalGarblingTableCommitments, EvaluationIndices,
    GarblingTableCommitment, HeapArray, Index, OpenedOutputShares, Polynomial,
    state_machine::evaluator::{
        Action, ActionId, ActionResult, EvaluatorState, Input, StateMut, StateRead, Step,
    },
};
use mosaic_common::constants::{N_EVAL_CIRCUITS, N_OPEN_CIRCUITS};
use mosaic_storage_inmemory::evaluator::StoredEvaluatorState;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::stf::{handle_action_result, handle_event, restore};
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
        .put_challenge_indices(&challenge_indices)
        .await
        .unwrap();
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
async fn unchallenged_in_range_challenge_response_chunk_is_invalid() {
    let mut state = StoredEvaluatorState::default();
    let challenge_indices = ChallengeIndices::new(|i| Index::new((i * 2) + 1).unwrap());
    let remaining = get_remaining_challenge_response_chunks(&challenge_indices);
    state
        .put_challenge_indices(&challenge_indices)
        .await
        .unwrap();
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
        Input::RecvChallengeResponseMsgChunk(dummy_challenge_response_chunk(2)),
        &mut actions,
    )
    .await;

    assert!(
        matches!(result, Err(crate::error::SMError::InvalidInputData)),
        "unchallenged in-range chunk must be rejected, got: {result:?}"
    );
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

// ============================================================================
// ReceivingGarblingTables -> SetupComplete transition + restore correctness
//
// The step transitions to `SetupComplete` only after every `received[i]` AND
// `receipt_acked[i]` is true. Until then, `restore()` must be able to re-emit
// any in-flight `SendTableTransferReceipt` tracked action, so the state stays
// in `ReceivingGarblingTables` until the framework delivers every receipt's
// ack via `ActionResult::TableTransferReceiptAcked`.
// ============================================================================

fn receiving_garbling_tables_state(
    received: HeapArray<bool, N_EVAL_CIRCUITS>,
    receipt_acked: HeapArray<bool, N_EVAL_CIRCUITS>,
) -> (
    EvaluatorState,
    EvalGarblingTableCommitments,
    EvaluationIndices,
) {
    let eval_indices: EvaluationIndices =
        std::array::from_fn(|i| Index::new(i + 1).expect("valid index"));
    let eval_commitments: EvalGarblingTableCommitments =
        HeapArray::new(|i| GarblingTableCommitment::from([i as u8 + 1; 32]));
    let state = EvaluatorState {
        config: None,
        step: Step::ReceivingGarblingTables {
            eval_indices,
            eval_commitments: eval_commitments.clone(),
            received,
            receipt_acked,
        },
    };
    (state, eval_commitments, eval_indices)
}

#[tokio::test]
async fn handle_table_received_does_not_advance_to_setup_complete() {
    // Even when `received.all()` becomes true, the step must remain
    // `ReceivingGarblingTables` so restore can re-emit any in-flight
    // `SendTableTransferReceipt` actions.
    let mut state = StoredEvaluatorState::default();

    // Pre-fill so the (N-1) `received[i]` are already true; the last
    // GarblingTableReceived will be the one that would have triggered the
    // (old, buggy) eager transition.
    let mut received = HeapArray::from_elem(true);
    received[N_EVAL_CIRCUITS - 1] = false;
    let (root, eval_commitments, eval_indices) =
        receiving_garbling_tables_state(received, HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let last_pos = N_EVAL_CIRCUITS - 1;
    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::ReceiveGarblingTable(eval_commitments[last_pos]),
        ActionResult::GarblingTableReceived(eval_indices[last_pos], eval_commitments[last_pos]),
        &mut actions,
    )
    .await
    .expect("final GarblingTableReceived must succeed");

    let stored = state.get_root_state().await.unwrap().unwrap();
    let Step::ReceivingGarblingTables {
        received,
        receipt_acked,
        ..
    } = stored.step
    else {
        panic!(
            "expected step to remain ReceivingGarblingTables before any receipt ack, got something else"
        );
    };
    assert!(received.all(), "all tables should be received now");
    assert_eq!(
        receipt_acked.count_ones(),
        0,
        "no receipt has been acked yet"
    );
    assert_eq!(
        actions.len(),
        1,
        "exactly one SendTableTransferReceipt should be emitted for the final table"
    );
}

#[tokio::test]
async fn table_transfer_receipt_acked_advances_only_when_all_received_and_acked() {
    // Drive the full ack sequence and verify SetupComplete fires on the last
    // ack, not the last GarblingTableReceived.
    let mut state = StoredEvaluatorState::default();
    let (root, eval_commitments, _eval_indices) =
        receiving_garbling_tables_state(HeapArray::from_elem(true), HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    for i in 0..N_EVAL_CIRCUITS - 1 {
        handle_action_result(
            &mut state,
            ActionId::SendTableTransferReceipt(eval_commitments[i]),
            ActionResult::TableTransferReceiptAcked,
            &mut actions,
        )
        .await
        .expect("intermediate ack must succeed");

        let stored = state.get_root_state().await.unwrap().unwrap();
        assert!(
            matches!(stored.step, Step::ReceivingGarblingTables { .. }),
            "step must not advance until every receipt is acked"
        );
    }

    handle_action_result(
        &mut state,
        ActionId::SendTableTransferReceipt(eval_commitments[N_EVAL_CIRCUITS - 1]),
        ActionResult::TableTransferReceiptAcked,
        &mut actions,
    )
    .await
    .expect("final ack must succeed");

    let stored = state.get_root_state().await.unwrap().unwrap();
    assert!(
        matches!(stored.step, Step::SetupComplete),
        "step must advance to SetupComplete after the final receipt ack"
    );
    assert!(
        actions.is_empty(),
        "no actions should be emitted on the transition"
    );
}

#[tokio::test]
async fn duplicate_receipt_ack_is_idempotent() {
    // A duplicate `TableTransferReceiptAcked` (e.g. for a receipt re-emitted by
    // restore on a previous boot whose ack also arrives) must be a no-op, not
    // an error.
    let mut state = StoredEvaluatorState::default();
    let mut receipt_acked = HeapArray::from_elem(false);
    receipt_acked[0] = true;
    let (root, eval_commitments, _) =
        receiving_garbling_tables_state(HeapArray::from_elem(true), receipt_acked);
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::SendTableTransferReceipt(eval_commitments[0]),
        ActionResult::TableTransferReceiptAcked,
        &mut actions,
    )
    .await
    .expect("duplicate ack must be idempotent");

    let stored = state.get_root_state().await.unwrap().unwrap();
    let Step::ReceivingGarblingTables { receipt_acked, .. } = stored.step else {
        panic!("expected ReceivingGarblingTables");
    };
    assert_eq!(
        receipt_acked.count_ones(),
        1,
        "duplicate ack must not double-count"
    );
    assert!(actions.is_empty());
}

#[tokio::test]
async fn late_receipt_ack_after_setup_complete_is_ignored() {
    // Once the step has advanced past `ReceivingGarblingTables`, a stale
    // ack (e.g. for a duplicate receipt re-emitted earlier) must be
    // silently ignored rather than rejected as `UnexpectedInput`.
    let mut state = StoredEvaluatorState::default();
    state
        .put_root_state(&EvaluatorState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::SendTableTransferReceipt(GarblingTableCommitment::from([7u8; 32])),
        ActionResult::TableTransferReceiptAcked,
        &mut actions,
    )
    .await
    .expect("late ack past SetupComplete must succeed (ack and ignore)");
    assert!(actions.is_empty());
}

#[tokio::test]
async fn restore_receiving_tables_re_emits_unacked_receipts_and_pending_receives() {
    // Mixed state covering all three slot kinds:
    //   - slot 0: !received                  → re-emit ReceiveGarblingTable
    //   - slot 1: received but !receipt_acked → re-emit SendTableTransferReceipt
    //   - slot 2+: received && receipt_acked  → no action
    // Confirms the audit's required restore behaviour.
    let mut state = StoredEvaluatorState::default();
    let mut received = HeapArray::from_elem(true);
    received[0] = false;
    let mut receipt_acked = HeapArray::from_elem(true);
    receipt_acked[0] = false;
    receipt_acked[1] = false;
    let (root, eval_commitments, _) = receiving_garbling_tables_state(received, receipt_acked);
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    restore(&state, &mut actions)
        .await
        .expect("restore succeeds");

    let mut receive_targets: BTreeSet<GarblingTableCommitment> = BTreeSet::new();
    let mut receipt_targets: BTreeSet<GarblingTableCommitment> = BTreeSet::new();
    for action in actions {
        let FasmAction::Tracked(tracked) = action;
        let (_id, action) = tracked.into_parts();
        match action {
            Action::ReceiveGarblingTable(c) => {
                receive_targets.insert(c);
            }
            Action::SendTableTransferReceipt(msg) => {
                receipt_targets.insert(msg.garbling_table_commitment);
            }
            other => panic!("unexpected action in ReceivingGarblingTables restore: {other:?}"),
        }
    }

    assert_eq!(
        receive_targets,
        BTreeSet::from([eval_commitments[0]]),
        "ReceiveGarblingTable must re-emit only for the unreceived slot"
    );
    assert_eq!(
        receipt_targets,
        BTreeSet::from([eval_commitments[1]]),
        "SendTableTransferReceipt must re-emit only for received-but-unacked slots"
    );
}

#[tokio::test]
async fn restore_receiving_tables_emits_nothing_when_all_received_and_acked() {
    // Steady state inside `ReceivingGarblingTables` just before the final ack
    // would land: every receipt is acked but the transition has not yet
    // happened. Restore must not re-emit anything (no in-flight tracked
    // actions remain).
    let mut state = StoredEvaluatorState::default();
    let (root, _, _) =
        receiving_garbling_tables_state(HeapArray::from_elem(true), HeapArray::from_elem(true));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    restore(&state, &mut actions)
        .await
        .expect("restore succeeds");
    assert!(
        actions.is_empty(),
        "no actions expected when every slot is received and acked"
    );
}

#[tokio::test]
async fn ack_with_unknown_commitment_is_invalid_input() {
    // If the ActionId doesn't match any commitment in the current step (only
    // possible from a corrupted id), the handler must error rather than
    // silently mutate.
    let mut state = StoredEvaluatorState::default();
    let (root, _, _) =
        receiving_garbling_tables_state(HeapArray::from_elem(true), HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    let result = handle_action_result(
        &mut state,
        ActionId::SendTableTransferReceipt(GarblingTableCommitment::from([0xFFu8; 32])),
        ActionResult::TableTransferReceiptAcked,
        &mut actions,
    )
    .await;
    assert!(
        result.is_err(),
        "unknown commitment must be InvalidInputData"
    );
}

#[tokio::test]
async fn duplicate_garbling_table_received_is_idempotent() {
    // If `GarblingTableReceived` is delivered twice for the same slot, the
    // second delivery must not emit a stray `SendTableTransferReceipt` or
    // perturb state. Symmetric to the duplicate-ack guard.
    let mut state = StoredEvaluatorState::default();
    let mut received = HeapArray::from_elem(false);
    received[0] = true;
    let (root, eval_commitments, eval_indices) =
        receiving_garbling_tables_state(received, HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::ReceiveGarblingTable(eval_commitments[0]),
        ActionResult::GarblingTableReceived(eval_indices[0], eval_commitments[0]),
        &mut actions,
    )
    .await
    .expect("duplicate GarblingTableReceived must succeed");

    assert!(
        actions.is_empty(),
        "duplicate GarblingTableReceived must not emit anything"
    );
    let stored = state.get_root_state().await.unwrap().unwrap();
    let Step::ReceivingGarblingTables {
        received,
        receipt_acked,
        ..
    } = stored.step
    else {
        panic!("expected ReceivingGarblingTables");
    };
    assert_eq!(received.count_ones(), 1);
    assert_eq!(receipt_acked.count_ones(), 0);
}

#[tokio::test]
async fn ack_with_wrong_action_id_variant_is_invalid_input() {
    // `ActionResult::TableTransferReceiptAcked` must be paired with
    // `ActionId::SendTableTransferReceipt`. A mismatched pairing (only
    // reachable from a framework bug or a corrupted id) must fail closed.
    let mut state = StoredEvaluatorState::default();
    let (root, _, _) =
        receiving_garbling_tables_state(HeapArray::from_elem(true), HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    let result = handle_action_result(
        &mut state,
        ActionId::SendChallengeMsg, // wrong variant
        ActionResult::TableTransferReceiptAcked,
        &mut actions,
    )
    .await;
    assert!(
        result.is_err(),
        "mismatched ActionId variant must be InvalidInputData"
    );
}

#[tokio::test]
async fn duplicate_garbling_table_received_with_mismatched_commitment_aborts() {
    // A duplicate `GarblingTableReceived` with a *wrong* commitment for an
    // already-received slot must still abort, not be swallowed by the
    // idempotency guard. Defends the original abort-on-mismatch contract.
    let mut state = StoredEvaluatorState::default();
    let mut received = HeapArray::from_elem(false);
    received[0] = true;
    let (root, _eval_commitments, eval_indices) =
        receiving_garbling_tables_state(received, HeapArray::from_elem(false));
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::ReceiveGarblingTable(GarblingTableCommitment::from([0xAAu8; 32])),
        ActionResult::GarblingTableReceived(
            eval_indices[0],
            GarblingTableCommitment::from([0xAAu8; 32]), // wrong commitment
        ),
        &mut actions,
    )
    .await
    .expect("mismatch must produce Aborted, not Err");

    let stored = state.get_root_state().await.unwrap().unwrap();
    assert!(
        matches!(stored.step, Step::Aborted { .. }),
        "expected abort on commitment mismatch, got {:?}",
        stored.step
    );
}

// ============================================================================
// Output share verification
// ============================================================================

/// Build a valid `ChallengeResponseMsgHeader` whose `opened_output_shares` are
/// real evaluations of `output_polynomial` at each `challenge_indices` position.
fn build_valid_response_header(
    output_polynomial: &Polynomial,
    challenge_indices: &ChallengeIndices,
) -> (ChallengeResponseMsgHeader, OpenedOutputShares) {
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let dummy_share = Polynomial::rand(&mut rng).eval(Index::new(1).unwrap());

    let opened_output_shares: OpenedOutputShares =
        HeapArray::new(|i| output_polynomial.eval(challenge_indices[i]));

    let header = ChallengeResponseMsgHeader {
        reserved_setup_input_shares: HeapArray::from_elem(dummy_share),
        opened_output_shares: opened_output_shares.clone(),
        opened_garbling_seeds: HeapArray::from_elem([0u8; 32].into()),
        unchallenged_output_label_cts: HeapArray::from_elem([0u8; 32].into()),
    };

    (header, opened_output_shares)
}

/// Seed evaluator storage with the prerequisites needed to enter
/// `handle_recv_challenge_response_header` and reach the share-verification step.
async fn seed_evaluator_for_challenge_response(
    state: &mut StoredEvaluatorState,
    output_polynomial: &Polynomial,
    challenge_indices: &ChallengeIndices,
) {
    state
        .put_output_polynomial_commitment(&HeapArray::from_elem(output_polynomial.commit()))
        .await
        .unwrap();
    state
        .put_challenge_indices(challenge_indices)
        .await
        .unwrap();

    let remaining = get_remaining_challenge_response_chunks(challenge_indices);
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
}

#[tokio::test]
async fn valid_opened_output_shares_are_persisted() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let output_polynomial = Polynomial::rand(&mut rng);
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());

    let mut state = StoredEvaluatorState::default();
    seed_evaluator_for_challenge_response(&mut state, &output_polynomial, &challenge_indices).await;

    let (header, expected_opened) =
        build_valid_response_header(&output_polynomial, &challenge_indices);

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgHeader(header),
        &mut actions,
    )
    .await;
    assert!(
        result.is_ok(),
        "valid header must be accepted, got: {result:?}"
    );

    // Step still WaitingForChallengeResponse (chunks not yet received) but header flag flipped.
    let root = state.get_root_state().await.unwrap().unwrap();
    match root.step {
        Step::WaitingForChallengeResponse { header, .. } => {
            assert!(header, "header flag should be set after valid header");
        }
        other => panic!("unexpected step after valid header: {other:?}"),
    }

    // Shares were persisted.
    let stored = state.get_opened_output_shares().await.unwrap();
    assert_eq!(stored, Some(expected_opened));
}

#[tokio::test]
async fn opened_output_share_with_wrong_challenge_index_aborts_without_persisting() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let output_polynomial = Polynomial::rand(&mut rng);
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());

    let mut state = StoredEvaluatorState::default();
    seed_evaluator_for_challenge_response(&mut state, &output_polynomial, &challenge_indices).await;

    let (mut header, _) = build_valid_response_header(&output_polynomial, &challenge_indices);

    // Duplicate a committed, otherwise valid share into another opened position.
    // verify_share accepts the embedded index, so the evaluator must also
    // require each opened share index to match the corresponding challenge.
    header.opened_output_shares[1] = header.opened_output_shares[0];

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgHeader(header),
        &mut actions,
    )
    .await;
    assert!(
        result.is_ok(),
        "wrong-index header should abort, not error: {result:?}"
    );
    assert!(actions.is_empty(), "abort path must not emit actions");

    let root = state.get_root_state().await.unwrap().unwrap();
    match root.step {
        Step::Aborted { reason } => {
            assert!(
                reason.contains("has index"),
                "unexpected abort reason: {reason}"
            );
        }
        other => panic!("expected Aborted, got: {other:?}"),
    }

    assert_eq!(state.get_opened_output_shares().await.unwrap(), None);
    assert_eq!(state.get_reserved_setup_input_shares().await.unwrap(), None);
    assert_eq!(state.get_opened_garbling_seeds().await.unwrap(), None);
}

#[tokio::test]
async fn corrupted_opened_output_share_aborts_without_persisting() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let output_polynomial = Polynomial::rand(&mut rng);
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());

    let mut state = StoredEvaluatorState::default();
    seed_evaluator_for_challenge_response(&mut state, &output_polynomial, &challenge_indices).await;

    let (mut header, _) = build_valid_response_header(&output_polynomial, &challenge_indices);

    // Replace one opened share with a share from an unrelated polynomial at the same index —
    // it will fail verify_share against the committed output polynomial.
    let corrupt_idx = N_OPEN_CIRCUITS / 2;
    let other_polynomial = Polynomial::rand(&mut rng);
    header.opened_output_shares[corrupt_idx] =
        other_polynomial.eval(challenge_indices[corrupt_idx]);

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeResponseMsgHeader(header),
        &mut actions,
    )
    .await;
    assert!(
        result.is_ok(),
        "corrupted header should abort, not error: {result:?}"
    );
    assert!(actions.is_empty(), "abort path must not emit actions");

    // Step transitioned to Aborted with the expected reason prefix.
    let root = state.get_root_state().await.unwrap().unwrap();
    match root.step {
        Step::Aborted { reason } => {
            assert!(
                reason.starts_with("invalid opened output shares"),
                "unexpected abort reason: {reason}"
            );
        }
        other => panic!("expected Aborted, got: {other:?}"),
    }

    // Crucially: nothing was persisted.
    assert_eq!(state.get_opened_output_shares().await.unwrap(), None);
    assert_eq!(state.get_reserved_setup_input_shares().await.unwrap(), None);
    assert_eq!(state.get_opened_garbling_seeds().await.unwrap(), None);
}

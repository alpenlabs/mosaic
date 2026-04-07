use std::collections::BTreeSet;

use fasm::actions::Action as FasmAction;
use mosaic_cac_types::{
    ChallengeIndices, DepositId, EvaluationIndices, HeapArray, Index,
    state_machine::evaluator::{Action, EvaluatorState, StateMut, Step},
};
use mosaic_common::constants::N_EVAL_CIRCUITS;
use mosaic_storage_inmemory::evaluator::StoredEvaluatorState;

use super::stf::restore;
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

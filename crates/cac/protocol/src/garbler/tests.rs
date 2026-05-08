use mosaic_cac_types::{
    Adaptor, AdaptorMsgChunk, ChallengeMsg, DepositId, GarblingTableCommitment, HeapArray, Index,
    KeyPair, Polynomial, SecretKey, TableTransferReceiptMsg, TableTransferRequestMsg,
    WideLabelWireAdaptors, WithdrawalAdaptorsChunk,
    state_machine::garbler::{
        Action, ActionId, ActionResult, Config, DepositState, DepositStep, GarblerDepositInitData,
        GarblerInitData, GarblerState, GarblingMetadata, Input, StateMut, StateRead, Step,
    },
};
use mosaic_common::constants::{N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_SETUP_INPUT_WIRES};
use mosaic_storage_inmemory::garbler::StoredGarblerState;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::stf::{handle_action_result, handle_event, restore};

fn rand_byte_array<const N: usize, R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn sample_adaptor() -> Adaptor {
    let sk = SecretKey::from_raw_bytes(&[1; 32]);
    let point = sk.to_pubkey().0;
    Adaptor {
        tweaked_s: sk.0,
        R_dash_commit: point,
        share_commitment: point,
    }
}

#[tokio::test]
async fn test_handle_init() {
    let mut state = StoredGarblerState::default();

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let seed = rand_byte_array(&mut rng).into();
    let setup_inputs = rand_byte_array(&mut rng);

    let input = Input::Init(GarblerInitData { seed, setup_inputs });

    let mut actions = Vec::new();
    handle_event(&mut state, input, &mut actions).await.unwrap();

    let root_state = state.get_root_state().await.unwrap().unwrap();
    assert_eq!(root_state.config.unwrap(), Config { seed, setup_inputs });
    assert!(matches!(
        root_state.step,
        Step::GeneratingPolynomialCommitments { .. }
    ));
    assert!(!actions.is_empty());
}

#[tokio::test]
async fn test_deposit_init() {
    let mut state = StoredGarblerState::default();
    state
        .put_root_state(&GarblerState {
            config: Some(Config {
                seed: [0; 32].into(),
                setup_inputs: [0; N_SETUP_INPUT_WIRES],
            }),
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let deposit_id = rand_byte_array(&mut rng).into();

    let keypair = KeyPair::rand(&mut rng);
    let sighashes = HeapArray::new(|_| rand_byte_array(&mut rng).into());
    let deposit_inputs = rand_byte_array(&mut rng);
    let deposit_init_data = GarblerDepositInitData {
        pk: keypair.public_key(),
        sighashes: sighashes.clone(),
        deposit_inputs,
    };
    let input = Input::DepositInit(deposit_id, deposit_init_data);

    let mut actions = Vec::new();
    handle_event(&mut state, input, &mut actions).await.unwrap();

    let deposit_state = state.get_deposit(&deposit_id).await.unwrap().unwrap();
    assert_eq!(deposit_state.pk, keypair.public_key());
    assert!(matches!(
        deposit_state.step,
        DepositStep::WaitingForAdaptors { .. }
    ));
    let stored_sighashes = state
        .get_deposit_sighashes(&deposit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_sighashes, sighashes);
    let stored_deposit_inputs = state
        .get_deposit_inputs(&deposit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_deposit_inputs, deposit_inputs);
    assert!(actions.is_empty());
}

#[tokio::test]
async fn test_reject_mismatched_adaptor_chunk_deposit_id() {
    let mut state = StoredGarblerState::default();
    state
        .put_root_state(&GarblerState {
            config: Some(Config {
                seed: [0; 32].into(),
                setup_inputs: [0; N_SETUP_INPUT_WIRES],
            }),
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let deposit_id = DepositId::from([2; 32]);
    let other_deposit_id = DepositId::from([3; 32]);
    let pk = SecretKey::from_raw_bytes(&[5; 32]).to_pubkey();
    let sighashes = HeapArray::new(|_| [8; 32].into());
    let deposit_inputs = [9; 4];

    let mut actions = Vec::new();
    handle_event(
        &mut state,
        Input::DepositInit(
            deposit_id,
            GarblerDepositInitData {
                pk,
                sighashes,
                deposit_inputs,
            },
        ),
        &mut actions,
    )
    .await
    .unwrap();

    let chunk = AdaptorMsgChunk {
        deposit_id: other_deposit_id,
        chunk_index: 0,
        deposit_adaptor: sample_adaptor(),
        withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|_| {
            WideLabelWireAdaptors::new(|_| sample_adaptor())
        }),
    };

    let err = handle_event(
        &mut state,
        Input::DepositRecvAdaptorMsgChunk(deposit_id, chunk),
        &mut actions,
    )
    .await;
    assert!(err.is_err(), "mismatched deposit_id must fail closed");
}

#[tokio::test]
async fn restore_sending_commit_replays_only_unacked_header_and_chunks() {
    let mut state = StoredGarblerState::default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let poly_commitment = Polynomial::rand(&mut rng).commit();
    let wire_commitments = HeapArray::from_elem(poly_commitment.clone());
    let output_polynomial_commitment = HeapArray::from_elem(poly_commitment);

    for wire_idx in 0..N_INPUT_WIRES {
        state
            .put_input_polynomial_commitments_chunk(wire_idx as u16, &wire_commitments)
            .await
            .expect("store input commitments");
    }
    state
        .put_output_polynomial_commitment(&output_polynomial_commitment)
        .await
        .expect("store output commitment");
    for ii in 0..N_CIRCUITS {
        let index = Index::new(ii + 1).expect("valid index");
        state
            .put_garbling_table_commitment(index, &[ii as u8; 32].into())
            .await
            .expect("store garbling table commitment");
        state
            .put_garbling_table_metadata(
                index,
                &GarblingMetadata {
                    aes128_key: [ii as u8; 16],
                    public_s: [ii as u8 + 1; 16],
                    constant_zero_label: [ii as u8 + 2; 16],
                    constant_one_label: [ii as u8 + 3; 16],
                    output_label_ct: [ii as u8; 32].into(),
                },
            )
            .await
            .expect("store garbling metadata");
    }

    let mut acked = HeapArray::from_elem(false);
    acked[0] = true;
    acked[3] = true;
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SendingCommit {
                header_acked: false,
                chunk_acked: acked.clone(),
            },
        })
        .await
        .expect("write root state");

    let mut actions = Vec::new();
    restore(&state, &mut actions)
        .await
        .expect("restore succeeds");

    let mut header_count = 0usize;
    let mut chunk_count = 0usize;
    for action in actions {
        let fasm::actions::Action::Tracked(tracked) = action;
        let (_id, action) = tracked.into_parts();
        match action {
            Action::SendCommitMsgHeader(_) => header_count += 1,
            Action::SendCommitMsgChunk(wire_index) => {
                assert!(!acked[wire_index as usize]);
                chunk_count += 1;
            }
            _ => panic!("unexpected action emitted while restoring SendingCommit"),
        }
    }
    assert_eq!(header_count, 1);
    assert_eq!(
        chunk_count,
        acked.iter().filter(|seen| !**seen).count(),
        "restore should only replay unacked commit chunks"
    );
}

#[tokio::test]
async fn sending_commit_requires_header_and_chunks_acked_before_transition() {
    let mut state = StoredGarblerState::default();
    let mut acked = HeapArray::from_elem(true);
    acked[0] = false;
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SendingCommit {
                header_acked: false,
                chunk_acked: acked,
            },
        })
        .await
        .expect("write root state");

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::SendCommitMsgChunk(0),
        ActionResult::CommitMsgChunkAcked,
        &mut actions,
    )
    .await
    .expect("chunk ack should be accepted");

    let root_state = state.get_root_state().await.unwrap().unwrap();
    assert!(
        matches!(
            root_state.step,
            Step::SendingCommit {
                header_acked: false,
                ..
            }
        ),
        "must remain in SendingCommit until header is acked"
    );

    handle_action_result(
        &mut state,
        ActionId::SendCommitMsgHeader,
        ActionResult::CommitMsgHeaderAcked,
        &mut actions,
    )
    .await
    .expect("header ack should be accepted");

    let root_state = state.get_root_state().await.unwrap().unwrap();
    assert!(
        matches!(root_state.step, Step::WaitingForChallenge),
        "must transition once header and all chunks are acked"
    );
}

// ============================================================================
// "Ack and ignore" tests
//
// Each test puts the STF in a step where the incoming message is no longer
// relevant (the machine already advanced past it), and asserts that
// handle_event returns Ok(()) with an empty action queue.
// ============================================================================

/// Helper: build a valid `ChallengeMsg` whose indices are all non-reserved.
fn dummy_challenge_msg() -> ChallengeMsg {
    ChallengeMsg {
        challenge_indices: HeapArray::new(|i| Index::new(i + 1).unwrap()),
    }
}

#[tokio::test]
async fn challenge_after_sending_challenge_response_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SendingChallengeResponse {
                header_acked: false,
                chunk_acked: HeapArray::from_elem(false),
            },
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvChallengeMsg(dummy_challenge_msg()),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn table_transfer_request_after_setup_complete_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvTableTransferRequest(TableTransferRequestMsg {
            garbling_table_commitment: [0xAA; 32].into(),
        }),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn table_transfer_receipt_after_setup_complete_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::RecvTableTransferReceipt(TableTransferReceiptMsg {
            garbling_table_commitment: [0xBB; 32].into(),
        }),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn adaptor_chunk_after_deposit_past_waiting_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    let deposit_id = DepositId::from([0x01; 32]);
    let pk = SecretKey::from_raw_bytes(&[5; 32]).to_pubkey();

    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    // Put deposit in VerifyingAdaptors (past WaitingForAdaptors).
    state
        .put_deposit(
            deposit_id,
            &DepositState {
                step: DepositStep::VerifyingAdaptors,
                pk,
            },
        )
        .await
        .unwrap();

    let chunk = AdaptorMsgChunk {
        deposit_id,
        chunk_index: 0,
        deposit_adaptor: sample_adaptor(),
        withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|_| {
            WideLabelWireAdaptors::new(|_| sample_adaptor())
        }),
    };

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::DepositRecvAdaptorMsgChunk(deposit_id, chunk),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn duplicate_adaptor_chunk_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    let deposit_id = DepositId::from([0x02; 32]);
    let pk = SecretKey::from_raw_bytes(&[5; 32]).to_pubkey();

    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    // Put deposit in WaitingForAdaptors with chunk 0 already received.
    let mut chunks = HeapArray::from_elem(false);
    chunks[0] = true;
    state
        .put_deposit(
            deposit_id,
            &DepositState {
                step: DepositStep::WaitingForAdaptors { chunks },
                pk,
            },
        )
        .await
        .unwrap();

    let chunk = AdaptorMsgChunk {
        deposit_id,
        chunk_index: 0, // duplicate
        deposit_adaptor: sample_adaptor(),
        withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|_| {
            WideLabelWireAdaptors::new(|_| sample_adaptor())
        }),
    };

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::DepositRecvAdaptorMsgChunk(deposit_id, chunk),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

#[tokio::test]
async fn adaptor_chunk_when_root_completing_adaptors_is_ack_and_ignore() {
    let mut state = StoredGarblerState::default();
    let deposit_id = DepositId::from([0x03; 32]);
    let other_deposit_id = DepositId::from([0x04; 32]);
    let pk = SecretKey::from_raw_bytes(&[5; 32]).to_pubkey();

    // Root state has moved to CompletingAdaptors for a different deposit.
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::CompletingAdaptors {
                deposit_id: other_deposit_id,
            },
        })
        .await
        .unwrap();

    // The target deposit still exists in storage.
    state
        .put_deposit(
            deposit_id,
            &DepositState {
                step: DepositStep::WaitingForAdaptors {
                    chunks: HeapArray::from_elem(false),
                },
                pk,
            },
        )
        .await
        .unwrap();

    let chunk = AdaptorMsgChunk {
        deposit_id,
        chunk_index: 0,
        deposit_adaptor: sample_adaptor(),
        withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|_| {
            WideLabelWireAdaptors::new(|_| sample_adaptor())
        }),
    };

    let mut actions = Vec::new();
    let result = handle_event(
        &mut state,
        Input::DepositRecvAdaptorMsgChunk(deposit_id, chunk),
        &mut actions,
    )
    .await;

    assert!(result.is_ok(), "should ack and ignore, got: {result:?}");
    assert!(actions.is_empty(), "should produce no actions");
}

// ---------------------------------------------------------------------------
// Table-transfer soundness: receipts must follow a successful local transfer.
// Also covers duplicate-request amplification mitigation.
// ---------------------------------------------------------------------------

fn transferring_state_with(
    seed_byte: u8,
) -> (
    GarblerState,
    HeapArray<GarblingTableCommitment, N_EVAL_CIRCUITS>,
) {
    let eval_seeds: HeapArray<_, N_EVAL_CIRCUITS> =
        HeapArray::new(|i| [seed_byte.wrapping_add(i as u8); 32].into());
    let eval_commitments: HeapArray<GarblingTableCommitment, N_EVAL_CIRCUITS> =
        HeapArray::new(|i| [seed_byte.wrapping_add(i as u8).wrapping_add(0x80); 32].into());

    let state = GarblerState {
        config: None,
        step: Step::TransferringGarblingTables {
            eval_seeds,
            eval_commitments: eval_commitments.clone(),
            locally_transferred: HeapArray::from_elem(false),
            pending_receipts: HeapArray::from_elem(false),
            transferred: HeapArray::from_elem(false),
        },
    };
    (state, eval_commitments)
}

#[tokio::test]
async fn table_transfer_receipt_before_local_transfer_is_stashed_without_redispatch() {
    // The SM executor processes job completions and inbound network requests
    // on independent select branches, so a real evaluator's receipt can land
    // before our own GarblingTableTransferred completion does. The STF must
    // not reject the receipt as invalid (it would never be re-delivered, and
    // the slot would deadlock).
    //
    // The deferred path stashes the receipt as `pending_receipts[pos] = true`
    // and trusts the in-flight `TransferGarblingTable` completion to drain
    // it. We must NOT re-dispatch a fresh action here: the original
    // completion is in flight; if it lands first and advances the step to
    // `SetupComplete`, the duplicate would be rejected by
    // `setup_transfer_session` and the garbling coordinator would retry the
    // rejection forever, occupying a coordinator slot. Crash recovery and
    // rolling-upgrade migration are handled by `restore()` instead.
    let mut state = StoredGarblerState::default();
    let (root, eval_commitments) = transferring_state_with(0x10);
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_event(
        &mut state,
        Input::RecvTableTransferReceipt(TableTransferReceiptMsg {
            garbling_table_commitment: eval_commitments[0],
        }),
        &mut actions,
    )
    .await
    .expect("early receipt must be deferred, not rejected");
    assert!(
        actions.is_empty(),
        "early receipt must not re-dispatch any action; got {} actions",
        actions.len()
    );

    let root = state.get_root_state().await.unwrap().unwrap();
    let Step::TransferringGarblingTables {
        pending_receipts,
        transferred,
        ..
    } = root.step
    else {
        panic!(
            "expected step to remain TransferringGarblingTables, got {:?}",
            root.step
        );
    };
    assert!(
        pending_receipts[0],
        "slot 0 must be marked pending after early receipt"
    );
    assert_eq!(
        transferred.count_ones(),
        0,
        "no slot should be marked transferred until local transfer also lands"
    );
}

#[tokio::test]
async fn duplicate_pending_receipt_does_not_redispatch() {
    // Two receipts arrive for the same slot before any local completion
    // (e.g. evaluator restarted and re-sent). The first stashes
    // `pending_receipts[0] = true`; the second hits the `else` branch
    // ("duplicate pending; ignored"). Neither must enqueue a
    // `TransferGarblingTable` action — the in-flight original transfer
    // owns the local-completion path.
    let mut state = StoredGarblerState::default();
    let (root, eval_commitments) = transferring_state_with(0x12);
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    for _ in 0..2 {
        handle_event(
            &mut state,
            Input::RecvTableTransferReceipt(TableTransferReceiptMsg {
                garbling_table_commitment: eval_commitments[0],
            }),
            &mut actions,
        )
        .await
        .expect("repeated early receipt must be deferred, not rejected");
    }
    assert!(
        actions.is_empty(),
        "duplicate early receipts must not enqueue any action; got {} actions",
        actions.len()
    );
}

#[tokio::test]
async fn pending_receipt_is_consumed_when_local_transfer_completes() {
    // Race scenario: receipt arrives first (pending_receipts set), then
    // GarblingTableTransferred lands. The action-completion path must
    // graduate the slot to `transferred` and clear `pending_receipts`.
    let mut state = StoredGarblerState::default();
    let (mut root, eval_commitments) = transferring_state_with(0x50);
    let seed = match &root.step {
        Step::TransferringGarblingTables { eval_seeds, .. } => eval_seeds[0],
        _ => unreachable!(),
    };
    if let Step::TransferringGarblingTables {
        pending_receipts, ..
    } = &mut root.step
    {
        pending_receipts[0] = true;
    }
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::TransferGarblingTable(seed),
        ActionResult::GarblingTableTransferred(seed, eval_commitments[0]),
        &mut actions,
    )
    .await
    .expect("draining a pending receipt must succeed");

    let root = state.get_root_state().await.unwrap().unwrap();
    let Step::TransferringGarblingTables {
        locally_transferred,
        pending_receipts,
        transferred,
        ..
    } = root.step
    else {
        panic!("expected TransferringGarblingTables");
    };
    assert!(locally_transferred[0]);
    assert!(
        !pending_receipts[0],
        "pending receipt must be cleared after draining"
    );
    assert!(
        transferred[0],
        "slot must graduate to transferred when both halves are observed"
    );
}

#[tokio::test]
async fn table_transfer_receipt_succeeds_after_local_transfer_completes() {
    // Happy-path counterpart to the rejection test: once the local
    // GarblingTableTransferred action result has been recorded for a slot,
    // the matching receipt should advance that slot to transferred=true.
    let mut state = StoredGarblerState::default();
    let (mut root, eval_commitments) = transferring_state_with(0x20);
    if let Step::TransferringGarblingTables {
        locally_transferred,
        ..
    } = &mut root.step
    {
        locally_transferred[0] = true;
    }
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_event(
        &mut state,
        Input::RecvTableTransferReceipt(TableTransferReceiptMsg {
            garbling_table_commitment: eval_commitments[0],
        }),
        &mut actions,
    )
    .await
    .expect("receipt after local transfer must be accepted");
    assert!(actions.is_empty());

    let root = state.get_root_state().await.unwrap().unwrap();
    let Step::TransferringGarblingTables { transferred, .. } = root.step else {
        panic!("expected step to remain TransferringGarblingTables");
    };
    assert!(transferred[0], "slot 0 should be marked transferred");
}

#[tokio::test]
async fn duplicate_table_transfer_request_after_receipt_emits_no_action() {
    // Once the evaluator has confirmed receipt for a slot
    // (`transferred[pos] = true`), a re-issued `TableTransferRequest` is
    // idempotent: ack and ignore, no new `TransferGarblingTable` action.
    let mut state = StoredGarblerState::default();
    let (mut root, eval_commitments) = transferring_state_with(0x30);
    if let Step::TransferringGarblingTables {
        locally_transferred,
        transferred,
        ..
    } = &mut root.step
    {
        locally_transferred[0] = true;
        transferred[0] = true;
    }
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_event(
        &mut state,
        Input::RecvTableTransferRequest(TableTransferRequestMsg {
            garbling_table_commitment: eval_commitments[0],
        }),
        &mut actions,
    )
    .await
    .expect("duplicate request after receipt must ack-and-ignore");

    assert!(
        actions.is_empty(),
        "no TransferGarblingTable action should be emitted on duplicate request after receipt; got {} actions",
        actions.len()
    );
}

#[tokio::test]
async fn retry_request_between_local_transfer_and_receipt_redispatches_action() {
    // If a previous transfer completed locally but the evaluator failed to
    // persist the table on its side and retries, we must re-dispatch
    // `TransferGarblingTable` rather than ack-and-ignore — otherwise the
    // evaluator's retry waits forever and setup deadlocks.
    let mut state = StoredGarblerState::default();
    let (mut root, eval_commitments) = transferring_state_with(0x35);
    if let Step::TransferringGarblingTables {
        locally_transferred,
        ..
    } = &mut root.step
    {
        locally_transferred[0] = true;
    }
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_event(
        &mut state,
        Input::RecvTableTransferRequest(TableTransferRequestMsg {
            garbling_table_commitment: eval_commitments[0],
        }),
        &mut actions,
    )
    .await
    .expect("retry request before receipt must succeed");

    assert_eq!(
        actions.len(),
        1,
        "exactly one TransferGarblingTable action should be redispatched on retry before receipt"
    );
}

#[tokio::test]
async fn garbling_table_transferred_action_result_marks_locally_transferred() {
    // Sanity: the action-completion path that the soundness gate depends on
    // actually flips `locally_transferred[index] = true`.
    let mut state = StoredGarblerState::default();
    let (root, eval_commitments) = transferring_state_with(0x40);
    let seed = match &root.step {
        Step::TransferringGarblingTables { eval_seeds, .. } => eval_seeds[0],
        _ => unreachable!(),
    };
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::TransferGarblingTable(seed),
        ActionResult::GarblingTableTransferred(seed, eval_commitments[0]),
        &mut actions,
    )
    .await
    .expect("recording a successful local transfer must succeed");

    let root = state.get_root_state().await.unwrap().unwrap();
    let Step::TransferringGarblingTables {
        locally_transferred,
        transferred,
        ..
    } = root.step
    else {
        panic!("expected TransferringGarblingTables");
    };
    assert!(locally_transferred[0]);
    assert!(
        !transferred[0],
        "transferred is gated on receipt, not on local-transfer alone"
    );
}

#[tokio::test]
async fn late_garbling_table_transferred_after_setup_complete_is_ack_and_ignore() {
    // A retry's local completion may arrive AFTER the slot has already
    // graduated to transferred via a receipt + earlier completion, and the
    // STF may even have advanced to `SetupComplete`. The completion handler
    // must treat that as a no-op rather than `unexpected_input`, otherwise
    // the worker pool's retry path keeps surfacing failure signals on a
    // setup that is already done.
    let mut state = StoredGarblerState::default();
    let (root, eval_commitments) = transferring_state_with(0x60);
    let seed = match &root.step {
        Step::TransferringGarblingTables { eval_seeds, .. } => eval_seeds[0],
        _ => unreachable!(),
    };
    // Place the SM directly in SetupComplete to simulate the slot having
    // already graduated and the rest of setup having moved on.
    state
        .put_root_state(&GarblerState {
            config: None,
            step: Step::SetupComplete,
        })
        .await
        .unwrap();

    let mut actions = Vec::new();
    handle_action_result(
        &mut state,
        ActionId::TransferGarblingTable(seed),
        ActionResult::GarblingTableTransferred(seed, eval_commitments[0]),
        &mut actions,
    )
    .await
    .expect("late completion after SetupComplete must ack-and-ignore");

    let root = state.get_root_state().await.unwrap().unwrap();
    assert!(matches!(root.step, Step::SetupComplete));
    assert!(actions.is_empty());
}

#[tokio::test]
async fn restore_redispatches_transfers_for_slots_with_pending_receipts() {
    // Crash-recovery scenario: receipt arrived for a slot before the local
    // transfer completion was committed; we crashed; on restart we have
    // `pending_receipts[i] = true` and `locally_transferred[i] = false`.
    // The evaluator considers itself done and won't resend the request, so
    // restore() must re-dispatch `TransferGarblingTable` for every such
    // slot to drive a fresh local completion that will drain the pending
    // receipt.
    let mut state = StoredGarblerState::default();
    let (mut root, _eval_commitments) = transferring_state_with(0x70);
    let seeds = match &root.step {
        Step::TransferringGarblingTables { eval_seeds, .. } => eval_seeds.clone(),
        _ => unreachable!(),
    };
    if let Step::TransferringGarblingTables {
        pending_receipts, ..
    } = &mut root.step
    {
        pending_receipts[0] = true;
        pending_receipts[1] = true;
    }
    state.put_root_state(&root).await.unwrap();

    let mut actions = Vec::new();
    super::stf::restore(&state, &mut actions).await.unwrap();

    let redispatched: std::collections::HashSet<_> = actions
        .into_iter()
        .filter_map(|action| {
            let fasm::actions::Action::Tracked(tracked) = action;
            let (_id, action) = tracked.into_parts();
            match action {
                Action::TransferGarblingTable(seed) => Some(seed.to_hex()),
                _ => None,
            }
        })
        .collect();
    let expected: std::collections::HashSet<_> =
        [seeds[0].to_hex(), seeds[1].to_hex()].into_iter().collect();
    assert_eq!(
        redispatched, expected,
        "expected restore to re-dispatch TransferGarblingTable for both pending-receipt slots"
    );
}

use mosaic_cac_types::{
    Adaptor, AdaptorMsgChunk, DepositId, HeapArray, Index, KeyPair, Polynomial, SecretKey,
    WideLabelWireAdaptors, WithdrawalAdaptorsChunk,
    state_machine::garbler::{
        Action, ActionId, ActionResult, Config, DepositStep, GarblerDepositInitData,
        GarblerInitData, GarblerState, GarblingMetadata, Input, StateMut, StateRead, Step,
    },
};
use mosaic_common::constants::{N_CIRCUITS, N_INPUT_WIRES, N_SETUP_INPUT_WIRES};
use mosaic_storage_inmemory::garbler::StoredGarblerState;
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

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

    let mut rng = ChaChaRng::seed_from_u64(0);
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

    let mut rng = ChaChaRng::seed_from_u64(0);
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
    let mut rng = ChaChaRng::seed_from_u64(7);
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
            Action::SendCommitMsgChunk(chunk) => {
                assert!(!acked[chunk.wire_index as usize]);
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

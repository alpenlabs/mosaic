//! Tests for [`DefaultMosaicApi`].

use ark_ff::AdditiveGroup;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use mosaic_cac_types::{
    DepositId, HeapArray, KeyPair, SecretKey, Seed, Sighashes, Signature,
    state_machine::{
        Role, StateMachineId,
        evaluator::{self, EvaluatorState, StateMut as EvaluatorStateMut},
        garbler::{self, GarblerState, StateMut as GarblerStateMut},
    },
};
use mosaic_common::{
    Byte32,
    constants::{N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES},
};
use mosaic_net_svc_api::PeerId;
use mosaic_sm_executor_api::{
    DepositInitData, DisputedWithdrawalData, InitData, SmCommand, SmCommandKind, SmExecutorHandle,
};
use mosaic_storage_api::{Commit, StorageProviderMut};
use mosaic_storage_inmemory::InMemoryStorageProvider;
use mosaic_vs3::{Index, Polynomial, Share};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{
    DefaultMosaicApi, DepositStatus, EvaluatorDepositInit, EvaluatorWithdrawalData,
    GarblerDepositInit, MosaicApi, ServiceError, SetupConfig, TablesetStatus,
    crypto_conversions::{into_schnorr_signature, try_into_x_only_pubkey},
};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct TestHarness {
    api: DefaultMosaicApi<InMemoryStorageProvider, ChaCha20Rng>,
    storage: InMemoryStorageProvider,
    rx: kanal::AsyncReceiver<SmCommand>,
    peer_id: PeerId,
}

impl TestHarness {
    fn new() -> Self {
        let peer_id = PeerId::from([1u8; 32]);
        Self::with_peers(vec![peer_id])
    }

    fn with_peers(other_peer_ids: Vec<PeerId>) -> Self {
        let storage = InMemoryStorageProvider::new();
        let (tx, rx) = kanal::bounded_async::<SmCommand>(16);
        let executor_handle = SmExecutorHandle::new(tx);
        let rng = ChaCha20Rng::seed_from_u64(42);
        let own_peer_id = PeerId::from([0u8; 32]);
        let peer_id = *other_peer_ids.first().unwrap_or(&PeerId::from([1u8; 32]));
        let api = DefaultMosaicApi::new(
            own_peer_id,
            other_peer_ids,
            executor_handle,
            storage.clone(),
            rng,
        );
        Self {
            api,
            storage,
            rx,
            peer_id,
        }
    }

    fn garbler_sm_id(&self) -> mosaic_cac_types::state_machine::StateMachineId {
        StateMachineId::garbler(self.peer_id)
    }

    fn evaluator_sm_id(&self) -> mosaic_cac_types::state_machine::StateMachineId {
        StateMachineId::evaluator(self.peer_id)
    }

    async fn setup_garbler(&self, step: garbler::Step) {
        let mut session = self.storage.garbler_state_mut(&self.peer_id).await.unwrap();
        let state = GarblerState {
            config: Some(garbler::Config {
                seed: Seed::from([1u8; 32]),
                setup_inputs: [0u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
            }),
            step,
        };
        session.put_root_state(&state).await.unwrap();
        session.commit().await.unwrap();
    }

    async fn setup_evaluator(&self, step: evaluator::Step) {
        self.setup_evaluator_with_config(
            step,
            Some(evaluator::Config {
                seed: Seed::from([2u8; 32]),
                setup_inputs: [0u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
            }),
        )
        .await;
    }

    async fn setup_evaluator_with_config(
        &self,
        step: evaluator::Step,
        config: Option<evaluator::Config>,
    ) {
        let mut session = self
            .storage
            .evaluator_state_mut(&self.peer_id)
            .await
            .unwrap();
        let state = EvaluatorState { config, step };
        session.put_root_state(&state).await.unwrap();
        session.commit().await.unwrap();
    }

    async fn add_garbler_deposit(&self, deposit_id: DepositId, step: garbler::DepositStep) {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let keypair = KeyPair::rand(&mut rng);
        let deposit_state = garbler::DepositState {
            step,
            pk: keypair.public_key(),
        };
        let mut session = self.storage.garbler_state_mut(&self.peer_id).await.unwrap();
        session
            .put_deposit(deposit_id, &deposit_state)
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    async fn add_evaluator_deposit(&self, deposit_id: DepositId, step: evaluator::DepositStep) {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let keypair = KeyPair::rand(&mut rng);
        let deposit_state = evaluator::DepositState {
            step,
            sk: keypair.secret_key(),
        };
        let mut session = self
            .storage
            .evaluator_state_mut(&self.peer_id)
            .await
            .unwrap();
        session
            .put_deposit(&deposit_id, &deposit_state)
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    async fn recv_command(&self) -> SmCommand {
        self.rx
            .recv()
            .await
            .expect("expected a dispatched command on the executor channel")
    }

    fn assert_channel_empty(&self) {
        match self.rx.try_recv() {
            Ok(None) => {} // channel open, no message — correct
            Ok(Some(_)) => panic!("expected no dispatched input, but channel had a message"),
            Err(e) => panic!("channel error in assert_channel_empty: {e:?}"),
        }
    }
}

fn test_deposit_id(n: u8) -> DepositId {
    DepositId(Byte32::from([n; 32]))
}

fn test_sighashes() -> Sighashes {
    let sighash = mosaic_cac_types::Sighash(Byte32::from([0xAA; 32]));
    HeapArray::from_vec(vec![
        sighash;
        N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
    ])
}

fn test_completed_schnorr_signatures() -> Vec<SchnorrSignature> {
    let sig = Signature::from_bytes([1u8; 64]).expect("valid signature bytes");
    let schnorr = into_schnorr_signature(sig);
    vec![schnorr; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES]
}

fn test_completed_signatures() -> mosaic_cac_types::CompletedSignatures {
    // Signature has no Default; construct from valid field elements.
    let sig = Signature::from_bytes([1u8; 64]).expect("valid signature bytes");
    mosaic_cac_types::HeapArray::from_vec(vec![
        sig;
        N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
    ])
}

// ---------------------------------------------------------------------------
// Group 1: setup_tableset
// ---------------------------------------------------------------------------

#[tokio::test]
async fn setup_tableset_garbler_dispatches_init() {
    let h = TestHarness::new();
    let config = SetupConfig {
        role: Role::Garbler,
        peer_id: h.peer_id,
        setup_inputs: [42u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
        instance: Byte32::from([0u8; 32]),
    };

    let sm_id = h.api.setup_tableset(config).await.unwrap();
    assert_eq!(sm_id, h.garbler_sm_id());

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::Init(InitData::Garbler(data)) => {
            assert_eq!(
                data.setup_inputs,
                [42u8; mosaic_common::constants::N_SETUP_INPUT_WIRES]
            );
            assert_ne!(
                data.seed.to_bytes(),
                [0u8; 32],
                "seed should be random, not zero"
            );
        }
        other => panic!("expected Garbler Init, got {other:?}"),
    }
}

#[tokio::test]
async fn setup_tableset_evaluator_dispatches_init() {
    let h = TestHarness::new();
    let config = SetupConfig {
        role: Role::Evaluator,
        peer_id: h.peer_id,
        setup_inputs: [7u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
        instance: Byte32::from([0u8; 32]),
    };

    let sm_id = h.api.setup_tableset(config).await.unwrap();
    assert_eq!(sm_id, h.evaluator_sm_id());

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::Init(InitData::Evaluator(data)) => {
            assert_eq!(
                data.setup_inputs,
                [7u8; mosaic_common::constants::N_SETUP_INPUT_WIRES]
            );
            assert_ne!(data.seed.to_bytes(), [0u8; 32]);
        }
        other => panic!("expected Evaluator Init, got {other:?}"),
    }
}

#[tokio::test]
async fn setup_tableset_garbler_idempotent_when_already_setup() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let config = SetupConfig {
        role: Role::Garbler,
        peer_id: h.peer_id,
        setup_inputs: [0u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
        instance: Byte32::from([0u8; 32]),
    };

    let sm_id = h.api.setup_tableset(config).await.unwrap();
    assert_eq!(sm_id, h.garbler_sm_id());
    h.assert_channel_empty();
}

#[tokio::test]
async fn setup_tableset_evaluator_idempotent_when_already_setup() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;

    let config = SetupConfig {
        role: Role::Evaluator,
        peer_id: h.peer_id,
        setup_inputs: [0u8; mosaic_common::constants::N_SETUP_INPUT_WIRES],
        instance: Byte32::from([0u8; 32]),
    };

    let sm_id = h.api.setup_tableset(config).await.unwrap();
    assert_eq!(sm_id, h.evaluator_sm_id());
    h.assert_channel_empty();
}

// ---------------------------------------------------------------------------
// Group 2: list_tableset_ids
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tableset_ids_returns_only_committed_peers() {
    let peer1 = PeerId::from([1u8; 32]);
    let peer2 = PeerId::from([2u8; 32]);
    let peer3 = PeerId::from([3u8; 32]);
    let h = TestHarness::with_peers(vec![peer1, peer2, peer3]);

    // Commit garbler for peer1
    {
        let mut session = h.storage.garbler_state_mut(&peer1).await.unwrap();
        session
            .put_root_state(&GarblerState {
                config: None,
                step: garbler::Step::SetupComplete,
            })
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    // Commit evaluator for peer2
    {
        let mut session = h.storage.evaluator_state_mut(&peer2).await.unwrap();
        session
            .put_root_state(&EvaluatorState {
                config: None,
                step: evaluator::Step::SetupComplete,
            })
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    // Commit both for peer3
    {
        let mut session = h.storage.garbler_state_mut(&peer3).await.unwrap();
        session
            .put_root_state(&GarblerState {
                config: None,
                step: garbler::Step::SetupComplete,
            })
            .await
            .unwrap();
        session.commit().await.unwrap();
    }
    {
        let mut session = h.storage.evaluator_state_mut(&peer3).await.unwrap();
        session
            .put_root_state(&EvaluatorState {
                config: None,
                step: evaluator::Step::SetupComplete,
            })
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    let ids = h.api.list_tableset_ids().await.unwrap();
    assert_eq!(ids.len(), 4); // garbler1, evaluator2, garbler3, evaluator3

    assert!(ids.contains(&StateMachineId::garbler(peer1)));
    assert!(!ids.contains(&StateMachineId::evaluator(peer1)));
    assert!(!ids.contains(&StateMachineId::garbler(peer2)));
    assert!(ids.contains(&StateMachineId::evaluator(peer2)));
    assert!(ids.contains(&StateMachineId::garbler(peer3)));
    assert!(ids.contains(&StateMachineId::evaluator(peer3)));
}

// ---------------------------------------------------------------------------
// Group 3: get_tableset_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_tableset_status_garbler_setup_complete() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let status = h.api.get_tableset_status(&h.garbler_sm_id()).await.unwrap();
    assert!(matches!(status, Some(TablesetStatus::SetupComplete)));
}

#[tokio::test]
async fn get_tableset_status_evaluator_consumed() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_evaluator(evaluator::Step::SetupConsumed {
        deposit_id,
        slash: None,
    })
    .await;

    let status = h
        .api
        .get_tableset_status(&h.evaluator_sm_id())
        .await
        .unwrap();
    match status {
        Some(TablesetStatus::Consumed {
            deposit_id: id,
            success,
        }) => {
            assert_eq!(id, deposit_id);
            assert!(success);
        }
        other => panic!("expected Some(Consumed), got {other:?}"),
    }
}

#[tokio::test]
async fn get_tableset_status_garbler_aborted() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::Aborted {
        reason: "protocol violation".into(),
    })
    .await;

    let status = h.api.get_tableset_status(&h.garbler_sm_id()).await.unwrap();
    match status {
        Some(TablesetStatus::Aborted { reason }) => {
            assert_eq!(reason, "protocol violation");
        }
        other => panic!("expected Some(Aborted), got {other:?}"),
    }
}

#[tokio::test]
async fn get_tableset_status_returns_none_for_uninit() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::Uninit).await;

    let status = h.api.get_tableset_status(&h.garbler_sm_id()).await.unwrap();
    assert!(status.is_none(), "expected None, got {status:?}");
}

#[tokio::test]
async fn get_tableset_status_returns_none_when_not_found() {
    let h = TestHarness::new();
    // No state committed for this peer
    let status = h.api.get_tableset_status(&h.garbler_sm_id()).await.unwrap();
    assert!(status.is_none(), "expected None, got {status:?}");
}

// ---------------------------------------------------------------------------
// Group 4: init_garbler_deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn init_garbler_deposit_dispatches_correct_input() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let deposit_id = test_deposit_id(1);
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let keypair = KeyPair::rand(&mut rng);
    let internal_pk = keypair.public_key();
    let adaptor_pk = try_into_x_only_pubkey(internal_pk).unwrap();
    let sighashes = test_sighashes();
    let deposit_inputs = [0xBBu8; N_DEPOSIT_INPUT_WIRES];

    let init = GarblerDepositInit {
        adaptor_pk,
        sighashes: sighashes.clone(),
        deposit_inputs,
    };

    h.api
        .init_garbler_deposit(&h.garbler_sm_id(), &deposit_id, init)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::DepositInit {
            deposit_id: id,
            data: DepositInitData::Garbler(data),
        } => {
            assert_eq!(id, deposit_id);
            assert_eq!(data.pk, internal_pk);
            assert_eq!(data.sighashes, sighashes);
            assert_eq!(data.deposit_inputs, deposit_inputs);
        }
        other => panic!("expected Garbler DepositInit, got {other:?}"),
    }
}

#[tokio::test]
async fn init_garbler_deposit_rejects_wrong_step() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::WaitingForChallenge).await;

    let deposit_id = test_deposit_id(1);
    let init = GarblerDepositInit {
        adaptor_pk: try_into_x_only_pubkey(
            KeyPair::rand(&mut ChaCha20Rng::seed_from_u64(0)).public_key(),
        )
        .unwrap(),
        sighashes: test_sighashes(),
        deposit_inputs: [0u8; N_DEPOSIT_INPUT_WIRES],
    };

    let err = h
        .api
        .init_garbler_deposit(&h.garbler_sm_id(), &deposit_id, init)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
    h.assert_channel_empty();
}

#[tokio::test]
async fn init_garbler_deposit_rejects_duplicate_deposit() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::DepositReady)
        .await;

    let init = GarblerDepositInit {
        adaptor_pk: try_into_x_only_pubkey(
            KeyPair::rand(&mut ChaCha20Rng::seed_from_u64(0)).public_key(),
        )
        .unwrap(),
        sighashes: test_sighashes(),
        deposit_inputs: [0u8; N_DEPOSIT_INPUT_WIRES],
    };

    let err = h
        .api
        .init_garbler_deposit(&h.garbler_sm_id(), &deposit_id, init)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::DuplicateDeposit(id) if id == deposit_id),
        "expected DuplicateDeposit, got {err:?}"
    );
    h.assert_channel_empty();
}

// ---------------------------------------------------------------------------
// Group 5: init_evaluator_deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn init_evaluator_deposit_rejects_wrong_step() {
    let h = TestHarness::new();
    h.setup_evaluator_with_config(evaluator::Step::Uninit, None)
        .await;

    let deposit_id = test_deposit_id(1);
    let init = EvaluatorDepositInit {
        sighashes: test_sighashes(),
        deposit_inputs: [0u8; N_DEPOSIT_INPUT_WIRES],
    };

    let err = h
        .api
        .init_evaluator_deposit(&h.evaluator_sm_id(), &deposit_id, init)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

#[tokio::test]
async fn init_evaluator_deposit_rejects_duplicate() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_evaluator_deposit(deposit_id, evaluator::DepositStep::DepositReady)
        .await;

    let init = EvaluatorDepositInit {
        sighashes: test_sighashes(),
        deposit_inputs: [0u8; N_DEPOSIT_INPUT_WIRES],
    };

    let err = h
        .api
        .init_evaluator_deposit(&h.evaluator_sm_id(), &deposit_id, init)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::DuplicateDeposit(_)),
        "expected DuplicateDeposit, got {err:?}"
    );
}

#[tokio::test]
async fn init_evaluator_deposit_dispatches_correct_input() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);

    let init = EvaluatorDepositInit {
        sighashes: test_sighashes(),
        deposit_inputs: [0xCCu8; N_DEPOSIT_INPUT_WIRES],
    };

    h.api
        .init_evaluator_deposit(&h.evaluator_sm_id(), &deposit_id, init)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::DepositInit {
            deposit_id: id,
            data: DepositInitData::Evaluator(data),
        } => {
            assert_eq!(id, deposit_id);
            assert_eq!(data.deposit_inputs, [0xCCu8; N_DEPOSIT_INPUT_WIRES]);
        }
        other => panic!("expected Evaluator DepositInit, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 6: mark_deposit_withdrawn
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_deposit_withdrawn_garbler_dispatches_undisputed() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::DepositReady)
        .await;

    h.api
        .mark_deposit_withdrawn(&h.garbler_sm_id(), &deposit_id)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::UndisputedWithdrawal { deposit_id: id } => {
            assert_eq!(id, deposit_id);
        }
        other => panic!("expected UndisputedWithdrawal, got {other:?}"),
    }
}

#[tokio::test]
async fn mark_deposit_withdrawn_evaluator_dispatches_undisputed() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_evaluator_deposit(deposit_id, evaluator::DepositStep::DepositReady)
        .await;

    h.api
        .mark_deposit_withdrawn(&h.evaluator_sm_id(), &deposit_id)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::UndisputedWithdrawal { deposit_id: id } => {
            assert_eq!(id, deposit_id);
        }
        other => panic!("expected UndisputedWithdrawal, got {other:?}"),
    }
}

#[tokio::test]
async fn mark_deposit_withdrawn_rejects_wrong_root_step() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::Aborted {
        reason: "test".into(),
    })
    .await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::DepositReady)
        .await;

    let err = h
        .api
        .mark_deposit_withdrawn(&h.garbler_sm_id(), &deposit_id)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

#[tokio::test]
async fn mark_deposit_withdrawn_rejects_wrong_deposit_step() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::WithdrawnUndisputed)
        .await;

    let err = h
        .api
        .mark_deposit_withdrawn(&h.garbler_sm_id(), &deposit_id)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

#[tokio::test]
async fn mark_deposit_withdrawn_rejects_missing_deposit() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);

    let err = h
        .api
        .mark_deposit_withdrawn(&h.garbler_sm_id(), &deposit_id)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::DepositNotFound),
        "expected DepositNotFound, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 7: complete_adaptor_sigs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_adaptor_sigs_garbler_dispatches_disputed_withdrawal() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::DepositReady)
        .await;

    let withdrawal_inputs = [0xDDu8; N_WITHDRAWAL_INPUT_WIRES];

    h.api
        .complete_adaptor_sigs(&h.garbler_sm_id(), &deposit_id, withdrawal_inputs)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::DisputedWithdrawal {
            deposit_id: id,
            data: DisputedWithdrawalData::Garbler(wi),
        } => {
            assert_eq!(id, deposit_id);
            assert_eq!(wi, withdrawal_inputs);
        }
        other => panic!("expected Garbler DisputedWithdrawal, got {other:?}"),
    }
}

#[tokio::test]
async fn complete_adaptor_sigs_rejects_evaluator_role() {
    let h = TestHarness::new();

    let err = h
        .api
        .complete_adaptor_sigs(
            &h.evaluator_sm_id(),
            &test_deposit_id(1),
            [0u8; N_WITHDRAWAL_INPUT_WIRES],
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::RoleMismatch(_)),
        "expected RoleMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn complete_adaptor_sigs_rejects_deposit_not_ready() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_garbler_deposit(
        deposit_id,
        garbler::DepositStep::WaitingForAdaptors {
            chunks: HeapArray::from_vec(vec![false; N_DEPOSIT_INPUT_WIRES]),
        },
    )
    .await;

    let err = h
        .api
        .complete_adaptor_sigs(
            &h.garbler_sm_id(),
            &deposit_id,
            [0u8; N_WITHDRAWAL_INPUT_WIRES],
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 8: get_completed_adaptor_sigs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_completed_adaptor_sigs_returns_signatures() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_garbler(garbler::Step::SetupConsumed { deposit_id })
        .await;

    // Write completed signatures for the deposit
    let sigs = test_completed_signatures();
    {
        let mut session = h.storage.garbler_state_mut(&h.peer_id).await.unwrap();
        session
            .put_completed_signatures(&deposit_id, &sigs)
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    let result = h
        .api
        .get_completed_adaptor_sigs(&h.garbler_sm_id())
        .await
        .unwrap();
    assert_eq!(result.len(), sigs.len());
}

#[tokio::test]
async fn get_completed_adaptor_sigs_rejects_evaluator() {
    let h = TestHarness::new();

    let err = h
        .api
        .get_completed_adaptor_sigs(&h.evaluator_sm_id())
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::RoleMismatch(_)),
        "expected RoleMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn get_completed_adaptor_sigs_rejects_non_consumed_step() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let err = h
        .api
        .get_completed_adaptor_sigs(&h.garbler_sm_id())
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

#[tokio::test]
async fn get_completed_adaptor_sigs_errors_when_sigs_missing() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_garbler(garbler::Step::SetupConsumed { deposit_id })
        .await;
    // Add deposit entry but no completed_sigs
    h.add_garbler_deposit(deposit_id, garbler::DepositStep::DepositReady)
        .await;

    let err = h
        .api
        .get_completed_adaptor_sigs(&h.garbler_sm_id())
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::CompletedSigsNotFound),
        "expected CompletedSigsNotFound, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 9: evaluate_tableset
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evaluate_tableset_dispatches_disputed_withdrawal() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);
    h.add_evaluator_deposit(deposit_id, evaluator::DepositStep::DepositReady)
        .await;

    let data = EvaluatorWithdrawalData {
        withdrawal_inputs: [0xEEu8; N_WITHDRAWAL_INPUT_WIRES],
        signatures: test_completed_schnorr_signatures(),
    };

    h.api
        .evaluate_tableset(&h.evaluator_sm_id(), &deposit_id, data)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::DisputedWithdrawal {
            deposit_id: id,
            data: DisputedWithdrawalData::Evaluator(_),
        } => {
            assert_eq!(id, deposit_id);
        }
        other => panic!("expected Evaluator DisputedWithdrawal, got {other:?}"),
    }
}

#[tokio::test]
async fn evaluate_tableset_rejects_garbler_role() {
    let h = TestHarness::new();

    let data = EvaluatorWithdrawalData {
        withdrawal_inputs: [0u8; N_WITHDRAWAL_INPUT_WIRES],
        signatures: test_completed_schnorr_signatures(),
    };

    let err = h
        .api
        .evaluate_tableset(&h.garbler_sm_id(), &test_deposit_id(1), data)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::RoleMismatch(_)),
        "expected RoleMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn evaluate_tableset_rejects_wrong_step() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::Aborted {
        reason: "test".into(),
    })
    .await;

    let data = EvaluatorWithdrawalData {
        withdrawal_inputs: [0u8; N_WITHDRAWAL_INPUT_WIRES],
        signatures: test_completed_schnorr_signatures(),
    };

    let err = h
        .api
        .evaluate_tableset(&h.evaluator_sm_id(), &test_deposit_id(1), data)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 10: sign_with_fault_secret
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sign_with_fault_secret_signs_when_successful() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_evaluator(evaluator::Step::SetupConsumed {
        deposit_id,
        slash: None,
    })
    .await;

    // Write a fault secret share
    let scalar = ark_ff::UniformRand::rand(&mut ChaCha20Rng::seed_from_u64(123));
    let share = Share::new(Index::new(1).unwrap(), scalar);
    {
        let mut session = h.storage.evaluator_state_mut(&h.peer_id).await.unwrap();
        session.put_fault_secret_share(&share).await.unwrap();
        session.commit().await.unwrap();
    }

    let digest = [0xFFu8; 32];
    let result = h
        .api
        .sign_with_fault_secret(&h.evaluator_sm_id(), digest, None)
        .await
        .unwrap();

    let sig = result.expect("expected Some signature");

    // Derive the expected public key from the same scalar and verify the signature
    let sk_bytes: [u8; 32] = {
        use ark_ff::{BigInteger, PrimeField};
        scalar.into_bigint().to_bytes_be().try_into().unwrap()
    };
    use bitcoin::key::TapTweak;
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let (xonly, _) = keypair
        .tap_tweak(&secp, None)
        .to_keypair()
        .x_only_public_key();
    let msg = secp256k1::Message::from_digest(digest);
    xonly
        .verify(&secp, &msg, &sig)
        .expect("signature should verify against the derived public key");
}

#[tokio::test]
async fn sign_with_fault_secret_signs_with_tweak() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_evaluator(evaluator::Step::SetupConsumed {
        deposit_id,
        slash: None,
    })
    .await;

    let scalar = ark_ff::UniformRand::rand(&mut ChaCha20Rng::seed_from_u64(123));
    let share = Share::new(Index::new(1).unwrap(), scalar);
    {
        let mut session = h.storage.evaluator_state_mut(&h.peer_id).await.unwrap();
        session.put_fault_secret_share(&share).await.unwrap();
        session.commit().await.unwrap();
    }

    let digest = [0xFFu8; 32];
    let tweak = [0xABu8; 32];
    let result = h
        .api
        .sign_with_fault_secret(&h.evaluator_sm_id(), digest, Some(tweak))
        .await
        .unwrap();

    let sig = result.expect("expected Some signature");

    // Verify with the tap-tweaked public key
    let sk_bytes: [u8; 32] = {
        use ark_ff::{BigInteger, PrimeField};
        scalar.into_bigint().to_bytes_be().try_into().unwrap()
    };
    use bitcoin::key::TapTweak;
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let tap_node = bitcoin::TapNodeHash::assume_hidden(tweak);
    let (xonly, _) = keypair
        .tap_tweak(&secp, Some(tap_node))
        .to_keypair()
        .x_only_public_key();
    let msg = secp256k1::Message::from_digest(digest);
    xonly
        .verify(&secp, &msg, &sig)
        .expect("signature should verify against the tweaked public key");
}

#[tokio::test]
async fn sign_with_fault_secret_returns_none_on_unsuccessful_consume() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_evaluator(evaluator::Step::SetupConsumed {
        deposit_id,
        slash: None,
    })
    .await;

    let result = h
        .api
        .sign_with_fault_secret(&h.evaluator_sm_id(), [0u8; 32], None)
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn sign_with_fault_secret_returns_none_when_secret_missing() {
    let h = TestHarness::new();
    let deposit_id = test_deposit_id(1);
    h.setup_evaluator(evaluator::Step::SetupConsumed {
        deposit_id,
        slash: Some(SecretKey(ark_secp256k1::Fr::ZERO)),
    })
    .await;
    // No fault_secret_share written

    let result = h
        .api
        .sign_with_fault_secret(&h.evaluator_sm_id(), [0u8; 32], None)
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn sign_with_fault_secret_rejects_non_consumed_step() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;

    let err = h
        .api
        .sign_with_fault_secret(&h.evaluator_sm_id(), [0u8; 32], None)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidInputForState(_)),
        "expected InvalidInputForState, got {err:?}"
    );
}

#[tokio::test]
async fn sign_with_fault_secret_rejects_garbler_role() {
    let h = TestHarness::new();

    let err = h
        .api
        .sign_with_fault_secret(&h.garbler_sm_id(), [0u8; 32], None)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::RoleMismatch(_)),
        "expected RoleMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 11: list_deposits + get_deposit_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_deposits_returns_multiple_garbler_deposits_with_status() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let dep1 = test_deposit_id(1);
    let dep2 = test_deposit_id(2);
    h.add_garbler_deposit(dep1, garbler::DepositStep::DepositReady)
        .await;
    h.add_garbler_deposit(dep2, garbler::DepositStep::WithdrawnUndisputed)
        .await;

    let deposits = h.api.list_deposits(&h.garbler_sm_id()).await.unwrap();
    assert_eq!(deposits.len(), 2);

    let by_id: std::collections::HashMap<_, _> =
        deposits.iter().map(|d| (d.deposit_id, &d.status)).collect();

    assert!(matches!(by_id[&dep1], DepositStatus::Ready));
    assert!(matches!(by_id[&dep2], DepositStatus::UncontestedWithdrawal));
}

#[tokio::test]
async fn list_deposits_empty() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;

    let deposits = h.api.list_deposits(&h.evaluator_sm_id()).await.unwrap();
    assert!(deposits.is_empty());
}

#[tokio::test]
async fn get_deposit_status_returns_none_when_not_found() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let status = h
        .api
        .get_deposit_status(&h.garbler_sm_id(), &test_deposit_id(99))
        .await
        .unwrap();

    assert!(status.is_none(), "expected None, got {status:?}");
}

// ---------------------------------------------------------------------------
// Group 12: get_fault_secret_pubkey
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_fault_secret_pubkey_returns_pubkey_from_commitment() {
    let h = TestHarness::new();
    h.setup_garbler(garbler::Step::SetupComplete).await;

    let mut rng = ChaCha20Rng::seed_from_u64(200);
    let polynomial = Polynomial::rand(&mut rng);
    let commitment = polynomial.commit();
    let output_commitment = HeapArray::from_vec(vec![commitment.clone()]);

    {
        let mut session = h.storage.garbler_state_mut(&h.peer_id).await.unwrap();
        session
            .put_output_polynomial_commitment(&output_commitment)
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    let pubkey = h
        .api
        .get_fault_secret_pubkey(&h.garbler_sm_id())
        .await
        .unwrap()
        .expect("expected Some pubkey");

    let expected_pk = mosaic_cac_types::PubKey(commitment.eval(Index::reserved()).point());
    let expected_x_only = try_into_x_only_pubkey(expected_pk).unwrap();
    assert_eq!(pubkey, expected_x_only);
}

#[tokio::test]
async fn get_fault_secret_pubkey_returns_none_when_no_commitment() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    // No output_polynomial_commitment written

    let result = h
        .api
        .get_fault_secret_pubkey(&h.evaluator_sm_id())
        .await
        .unwrap();

    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Group 13: get_adaptor_pubkey
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_adaptor_pubkey_is_deterministic_across_calls() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(5);

    let pk1 = h
        .api
        .get_adaptor_pubkey(&h.evaluator_sm_id(), &deposit_id)
        .await
        .unwrap();
    let pk2 = h
        .api
        .get_adaptor_pubkey(&h.evaluator_sm_id(), &deposit_id)
        .await
        .unwrap();

    assert_eq!(pk1, pk2, "same seed + deposit_id must yield same pubkey");
}

#[tokio::test]
async fn get_adaptor_pubkey_differs_per_deposit() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;

    let pk1 = h
        .api
        .get_adaptor_pubkey(&h.evaluator_sm_id(), &test_deposit_id(1))
        .await
        .unwrap();
    let pk2 = h
        .api
        .get_adaptor_pubkey(&h.evaluator_sm_id(), &test_deposit_id(2))
        .await
        .unwrap();

    assert_ne!(
        pk1, pk2,
        "different deposit_ids must yield different pubkeys"
    );
}

// ---------------------------------------------------------------------------
// Group 14: init_evaluator_deposit derived key verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn init_evaluator_deposit_sk_matches_get_adaptor_pubkey() {
    let h = TestHarness::new();
    h.setup_evaluator(evaluator::Step::SetupComplete).await;
    let deposit_id = test_deposit_id(1);

    // Get the adaptor pubkey before init
    let adaptor_pk = h
        .api
        .get_adaptor_pubkey(&h.evaluator_sm_id(), &deposit_id)
        .await
        .unwrap()
        .expect("expected Some pubkey");

    let init = EvaluatorDepositInit {
        sighashes: test_sighashes(),
        deposit_inputs: [0u8; N_DEPOSIT_INPUT_WIRES],
    };

    h.api
        .init_evaluator_deposit(&h.evaluator_sm_id(), &deposit_id, init)
        .await
        .unwrap();

    let cmd = h.recv_command().await;
    match cmd.kind {
        SmCommandKind::DepositInit {
            data: DepositInitData::Evaluator(data),
            ..
        } => {
            let derived_x_only = try_into_x_only_pubkey(data.sk.to_pubkey()).unwrap();
            assert_eq!(
                derived_x_only, adaptor_pk,
                "dispatched sk must correspond to the pubkey from get_adaptor_pubkey"
            );
        }
        other => panic!("expected Evaluator DepositInit, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 15: executor channel failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatch_returns_executor_error_when_channel_closed() {
    let storage = InMemoryStorageProvider::new();
    let (tx, rx) = kanal::bounded_async::<SmCommand>(16);
    let executor_handle = SmExecutorHandle::new(tx);
    let rng = ChaCha20Rng::seed_from_u64(42);
    let peer_id = PeerId::from([1u8; 32]);

    let api = DefaultMosaicApi::new(
        PeerId::from([0u8; 32]),
        vec![peer_id],
        executor_handle,
        storage.clone(),
        rng,
    );

    // Setup garbler at SetupComplete with a ready deposit
    {
        let mut session = storage.garbler_state_mut(&peer_id).await.unwrap();
        session
            .put_root_state(&GarblerState {
                config: None,
                step: garbler::Step::SetupComplete,
            })
            .await
            .unwrap();

        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let keypair = KeyPair::rand(&mut rng2);
        session
            .put_deposit(
                test_deposit_id(1),
                &garbler::DepositState {
                    step: garbler::DepositStep::DepositReady,
                    pk: keypair.public_key(),
                },
            )
            .await
            .unwrap();
        session.commit().await.unwrap();
    }

    // Drop the receiver to close the channel
    drop(rx);

    let sm_id = StateMachineId::garbler(peer_id);
    let err = api
        .mark_deposit_withdrawn(&sm_id, &test_deposit_id(1))
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::Executor(_)),
        "expected Executor error, got {err:?}"
    );
}

use mosaic_cac_types::{
    HeapArray, SecretKey,
    state_machine::garbler::{
        Config, DepositStep, GarblerDepositInitData, GarblerInitData, GarblerState, Input,
        StateMut, StateRead, Step,
    },
};
use mosaic_common::constants::N_SETUP_INPUT_WIRES;
use mosaic_storage_inmemory::garbler::StoredGarblerState;
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

use super::stf::handle_event;

fn rand_byte_array<const N: usize, R: rand::Rng>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
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
    assert_eq!(actions.len(), 1);
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
    let sk = SecretKey::rand(&mut rng);
    let pk = sk.to_pubkey();
    let sighashes = HeapArray::new(|_| rand_byte_array(&mut rng).into());
    let deposit_inputs = rand_byte_array(&mut rng);
    let deposit_init_data = GarblerDepositInitData {
        pk,
        sighashes: sighashes.clone(),
        deposit_inputs,
    };
    let input = Input::DepositInit(deposit_id, deposit_init_data);

    let mut actions = Vec::new();
    handle_event(&mut state, input, &mut actions).await.unwrap();

    let deposit_state = state.get_deposit(&deposit_id).await.unwrap().unwrap();
    assert_eq!(deposit_state.pk, pk);
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

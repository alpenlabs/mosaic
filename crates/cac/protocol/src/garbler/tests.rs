use std::{
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, Once,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use ckt_fmtv5_types::v5::c::{Block, ReaderV5c, get_block_num_gates};
use fasm::actions;
use mosaic_cac_types::{
    HeapArray, SecretKey,
    state_machine::{
        evaluator::{
            ActionResult as EvalActionResult, EvaluatorInitData, EvaluatorTrackedActionTypes,
            Input as EvalInput,
        },
        garbler::{
            ActionResult as GarbActionResult, Config, DepositStep, GarblerDepositInitData,
            GarblerInitData, GarblerState, GarblerTrackedActionTypes, Input as GarbInput, StateMut,
            StateRead, Step,
        },
    },
};
use mosaic_common::constants::{N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES};
use mosaic_job_api::{ActionCompletion, ExecuteGarblerJob, HandlerOutcome, OwnedBlock, OwnedChunk};
use mosaic_job_executors::{
    circuit_sessions::{CommitmentSession, EvaluatorCircuitSession, GarblerCircuitSession}, MosaicExecutor
};
use mosaic_net_client::{NetClient, NetClientConfig};
use mosaic_net_svc::{NetService, NetServiceConfig, PeerConfig, peer_id_from_signing_key};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{StorageProvider, TableReader, TableStore, TableWriter};
use mosaic_storage_inmemory::{evaluator::StoredEvaluatorState, garbler::StoredGarblerState};
use rand_chacha::{ChaCha20Rng, ChaChaRng, rand_core::SeedableRng};

use super::stf::handle_event;
use crate::{evaluator, garbler};

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

    let input = GarbInput::Init(GarblerInitData { seed, setup_inputs });

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
    let sk = SecretKey::rand(&mut rng);
    let pk = sk.to_pubkey();
    let sighashes = HeapArray::new(|_| rand_byte_array(&mut rng).into());
    let deposit_inputs = rand_byte_array(&mut rng);
    let deposit_init_data = GarblerDepositInitData {
        pk,
        sighashes: sighashes.clone(),
        deposit_inputs,
    };
    let input = GarbInput::DepositInit(deposit_id, deposit_init_data);

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

use fasm::StateMachine;

#[tokio::test]
async fn test_e2e() {
    let mut garb_state = StoredGarblerState::default();
    let mut garb_rng = ChaChaRng::seed_from_u64(42);
    let mut eval_state = StoredEvaluatorState::default();
    let mut eval_rng = ChaCha20Rng::seed_from_u64(43);

    let ts = DummyTableStore {};
    let circuit_path = PathBuf::from_str("").unwrap();
    let (peer_id_a, peer_id_b, net_client_a, net_client_b) = dummy_net_client();

    let garb_seed = rand_byte_array(&mut garb_rng).into();
    let setup_inputs = rand_byte_array(&mut garb_rng);

    // Initialize garbler
    let mut garb_actions: Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    > = Vec::new();
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(GarbInput::Init(GarblerInitData {
            seed: garb_seed,
            setup_inputs,
        })),
        &mut garb_actions,
    )
    .await
    .unwrap();

    // Initialize evaluator
    let mut eval_actions: Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    > = Vec::new();
    evaluator::EvaluatorSM::stf(
        &mut eval_state,
        fasm::Input::Normal(EvalInput::Init(EvaluatorInitData {
            seed: garb_seed,
            setup_inputs,
        })),
        &mut eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), 0); // Step Waiting For Commit

    // Run Garbler STF
    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    let mut exec = MosaicExecutor::new(net_client_a, sp, ts, circuit_path);

    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id_b).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    // returns Action::GenerateShares
    assert_eq!(garb_actions.len(), N_CIRCUITS + 1);

    // update garbler state read by executor manually; TODO: avoidable with a shared copy of State
    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    exec.update_state(sp);
    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id_b).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    // [Action::GenerateTableCommitment; N_CIRCUITS]
    assert_eq!(garb_actions.len(), N_CIRCUITS);

    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    exec.update_state(sp);
    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id_b).await;
    assert_eq!(results.len(), N_CIRCUITS); // GarblerActionResult::TableCommitmentGenerated

    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); // Action::SendCommitMsgHeader + Action::SendCommitMsgChunk

    // Make evaluator listen

    // sends commit msg header then chunks; evaluator should have been listening
    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    exec.update_state(sp);
    let (mut eval_inputs, mut garb_results) = mock_dispatchgarbler_network(&mut garb_actions).await;

    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Step: WaitForChallenge; No Action // network ack

    // Evaluator receives commit msg
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(&mut eval_state, fasm::Input::Normal(ei), &mut eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // SendChallenge

    // Evaluator sends challenge over network
    let (mut garb_inputs, mut eval_results) =
        mock_dispatch_evaluator_network(&mut eval_actions).await;

    // eval's tx is acked
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
         evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, &mut eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0); // Challenge was acked; step WaitingForChallengeResponse
    // garbler processes challenge
    while let Some(inp) = garb_inputs.pop() {
        garbler::GarblerSM::stf(&mut garb_state, fasm::Input::Normal(inp), &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1 + N_OPEN_CIRCUITS); // Challenge Response Header + Challenge Response Chunks (one chunk for each circuit)


    let (mut eval_inputs, mut garb_results) = mock_dispatchgarbler_network(&mut garb_actions).await;

        while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), N_EVAL_CIRCUITS); //  Step::TransferringGarblingTables; Action::TransferGarblingTable

    // Evaluator receives challenge response
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(&mut eval_state, fasm::Input::Normal(ei), &mut eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // Step::VerifyingOpenedInputShares; Action::VerifyOpenedInputShares

    let results = mock_dispatch_evaluator(&mut eval_actions, &exec, &peer_id_a).await;
    assert_eq!(results.len(), 1); // ActionResult::VerifyOpenedInputSharesResult
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
         evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, &mut eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_OPEN_CIRCUITS); // Action::GenerateTableCommitment(index, seed), Step::VerifyingTableCommitments


    let results = mock_dispatch_evaluator(&mut eval_actions, &exec, &peer_id_a).await;
    assert_eq!(results.len(), N_OPEN_CIRCUITS); // ActionResult::TableCommitmentGenerated
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
         evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, &mut eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Step::ReceivingGarblingTables, Action::ReceiveGarblingTable


    // Garbler should transfer tables
    

}

struct DummyStorageProvider {
    garb_state: StoredGarblerState,
    eval_state: StoredEvaluatorState,
}

impl StorageProvider for DummyStorageProvider {
    type GarblerState = StoredGarblerState;
    type EvaluatorState = StoredEvaluatorState;

    fn garbler_state(&self, _peer_id: &PeerId) -> Self::GarblerState {
        self.garb_state.clone()
    }

    fn evaluator_state(&self, _peer_id: &PeerId) -> Self::EvaluatorState {
        self.eval_state.clone()
    }
}

struct DummyTableStore {}

impl TableStore for DummyTableStore {
    type Error = std::io::Error;
    type Writer = FileTableWriter;
    type Reader = FileTableReader;

    fn create(
        &self,
        id: &mosaic_storage_api::TableId,
    ) -> impl Future<Output = Result<Self::Writer, Self::Error>> + Send {
        async { todo!() }
    }

    fn open(
        &self,
        id: &mosaic_storage_api::TableId,
    ) -> impl Future<Output = Result<Self::Reader, Self::Error>> + Send {
        async { todo!() }
    }

    fn exists(
        &self,
        id: &mosaic_storage_api::TableId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { todo!() }
    }

    fn delete(
        &self,
        id: &mosaic_storage_api::TableId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { todo!() }
    }
}

struct FileTableWriter {}

impl TableWriter for FileTableWriter {
    type Error = std::io::Error;

    fn write_ciphertext(
        &mut self,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { todo!() }
    }

    fn finish(
        self,
        translation: &[u8],
        metadata: mosaic_storage_api::TableMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { todo!() }
    }
}

struct FileTableReader {}

impl TableReader for FileTableReader {
    type Error = std::io::Error;

    fn metadata(
        &self,
    ) -> impl Future<Output = Result<mosaic_storage_api::TableMetadata, Self::Error>> + Send {
        async { todo!() }
    }

    fn read_translation(&self) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async { todo!() }
    }

    fn read_ciphertext(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send {
        async { todo!() }
    }
}

fn dummy_net_client() -> (PeerId, PeerId, NetClient, NetClient) {
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);
    static PORT_INIT: Once = Once::new();
    fn next_port() -> u16 {
        PORT_INIT.call_once(|| {
            // Range 50000-59999 — must NOT overlap with net-svc tests (30000-39999).
            let start = 50000 + (std::process::id() as u16 % 10000);
            PORT_COUNTER.store(start, Ordering::SeqCst);
        });
        PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    use ed25519_dalek::SigningKey;
    fn test_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed;
        SigningKey::from_bytes(&bytes)
    }

    fn test_addr(port: u16) -> std::net::SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    let port_a = next_port();
    let port_b = next_port();

    let key_a = test_key(1);
    let key_b = test_key(2);

    let peer_id_a = peer_id_from_signing_key(&key_a);
    let peer_id_b = peer_id_from_signing_key(&key_b);

    let addr_a = test_addr(port_a);
    let addr_b = test_addr(port_b);

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)])
        .with_reconnect_backoff(Duration::from_millis(200));

    let (handle_a, _) = match NetService::new(config_a) {
        Ok(result) => result,
        Err(e) => {
            panic!("create net service A {}", e);
        }
    };

    let config_b = NetServiceConfig::new(key_b, addr_b, vec![PeerConfig::new(peer_id_a, addr_a)])
        .with_reconnect_backoff(Duration::from_millis(200));

    let (handle_b, _) = match NetService::new(config_b) {
        Ok(result) => result,
        Err(e) => {
            panic!("create net service A {}", e);
        }
    };

    (
        peer_id_a,
        peer_id_b,
        NetClient::with_config(handle_a, NetClientConfig::default()),
        NetClient::with_config(handle_b, NetClientConfig::default()),
    )
}

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};

async fn mock_dispatchgarbler_network(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
) -> (Vec<EvalInput>, Vec<ActionCompletion>) {
    let mut garb_results = vec![];
    let mut eval_input = vec![];
    while let Some(fasm_action) = actions.pop() {
        match fasm_action {
            fasm::actions::Action::Tracked(tracked) => {
                let action = tracked.action();
                match action {
                    GarblerAction::SendCommitMsgHeader(header) => {
                        eval_input.push(EvalInput::RecvCommitMsgHeader(header.clone()));
                        garb_results.push(ActionCompletion::Garbler {
                            id: action.id(),
                            result: GarbActionResult::CommitMsgHeaderAcked,
                        });
                    }
                    GarblerAction::SendCommitMsgChunk(chunk) => {
                        eval_input.push(EvalInput::RecvCommitMsgChunk(chunk.clone()));
                        garb_results.push(ActionCompletion::Garbler {
                            id: action.id(),
                            result: GarbActionResult::CommitMsgChunkAcked,
                        });
                    }
                    GarblerAction::SendChallengeResponseMsgHeader(header) => {
                        eval_input.push(EvalInput::RecvChallengeResponseMsgHeader(header.clone()));
                        garb_results.push(ActionCompletion::Garbler {
                            id: action.id(),
                            result: GarbActionResult::ChallengeResponseHeaderAcked,
                        });
                    }
                    GarblerAction::SendChallengeResponseMsgChunk(chunk) => {
                        eval_input.push(EvalInput::RecvChallengeResponseMsgChunk(chunk.clone()));
                        garb_results.push(ActionCompletion::Garbler {
                            id: action.id(),
                            result: GarbActionResult::ChallengeResponseChunkAcked,
                        });
                    }
                    _ => {
                        println!("unhandled garbler action variant");
                    }
                }
            }
            _ => panic!(),
        };
    }
    (eval_input, garb_results)
}

async fn mock_dispatchgarbler(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<DummyStorageProvider, DummyTableStore>,
    peer_id: &PeerId,
) -> Vec<mosaic_job_api::ActionCompletion> {
    let mut garb_results = vec![];
    while let Some(fasm_action) = actions.pop() {
        let outcome = match fasm_action {
            fasm::actions::Action::Tracked(tracked) => {
                let action = tracked.action();
                match action {
                    GarblerAction::GeneratePolynomialCommitments(seed, wire) => {
                        exec.generate_polynomial_commitments(peer_id, *seed, *wire)
                            .await
                    }
                    GarblerAction::GenerateShares(seed, index) => {
                        exec.generate_shares(peer_id, *seed, *index).await
                    }
                    GarblerAction::GenerateTableCommitment(index, seed) => {
                        let session =
                            ExecuteGarblerJob::begin_table_commitment(exec, peer_id, *index, *seed)
                                .await
                                .unwrap();
                        if let GarblerCircuitSession::Commitment(session) = session {
                            garb_coord_do_your_thing(&exec.circuit_path, *session).await
                        } else {
                            panic!()
                        }
                    }
                    GarblerAction::SendCommitMsgHeader(header) => {
                        exec.send_commit_msg_header(peer_id, header).await
                    }
                    GarblerAction::SendCommitMsgChunk(chunk) => {
                        exec.send_commit_msg_chunk(peer_id, chunk).await
                    }
                    GarblerAction::SendChallengeResponseMsgHeader(header) => {
                        exec.send_challenge_response_header(peer_id, header).await
                    }
                    GarblerAction::SendChallengeResponseMsgChunk(chunk) => {
                        exec.send_challenge_response_chunk(peer_id, chunk).await
                    }
                    GarblerAction::TransferGarblingTable(seed) => {
                        let session =
                            ExecuteGarblerJob::begin_table_transfer(exec, peer_id, *seed)
                                .await
                                .unwrap();
                        if let GarblerCircuitSession::Transfer(session) = session {
                            garb_coord_do_your_thing(&exec.circuit_path, *session).await // GarblerActionResult::GarblingTableTransferred(self.seed, self.commitment)
                        } else {
                            panic!()
                        }
                    }
                    GarblerAction::DepositVerifyAdaptors(deposit_id) => {
                        exec.deposit_verify_adaptors(peer_id, *deposit_id).await
                    }
                    GarblerAction::CompleteAdaptorSignatures(deposit_id) => {
                        exec.complete_adaptor_signatures(peer_id, *deposit_id).await
                    }
                    _ => {
                        println!("unhandled garbler action variant");
                        HandlerOutcome::Retry
                    }
                }
            }
            _ => panic!(),
        };
        match outcome {
            HandlerOutcome::Done(completion) => {
                garb_results.push(completion);
            }
            _ => panic!(),
        }
    }
    garb_results
}

async fn mock_dispatch_evaluator_network(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    let mut eval_results = vec![];
    let mut garb_input = vec![];
    while let Some(fasm_action) = actions.pop() {
        match fasm_action {
            fasm::actions::Action::Tracked(tracked) => {
                let action = tracked.action();
                match action {
                    EvaluatorAction::SendChallengeMsg(chal) => {
                        garb_input.push(GarbInput::RecvChallengeMsg(chal.clone()));
                        eval_results.push(ActionCompletion::Evaluator {
                            id: action.id(),
                            result: EvalActionResult::ChallengeMsgAcked,
                        });
                    }
                    _ => {
                        println!("unhandled garbler action variant");
                    }
                }
            }
            _ => panic!(),
        };
    }
    (garb_input, eval_results)
}

use mosaic_job_api::ExecuteEvaluatorJob;
async fn mock_dispatch_evaluator(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<DummyStorageProvider, DummyTableStore>,
    peer_id: &PeerId,
) -> Vec<ActionCompletion> {
    let mut eval_results = vec![];
    while let Some(fasm_action) = actions.pop() {
        let outcome = match fasm_action {
            fasm::actions::Action::Tracked(tracked) => {
                let action = tracked.action();
                match action {
                    EvaluatorAction::SendChallengeMsg(msg) => {
                        exec.send_challenge_msg(peer_id, msg).await
                    }
                    EvaluatorAction::VerifyOpenedInputShares => exec.verify_opened_input_shares(peer_id).await,
                    EvaluatorAction::GenerateTableCommitment(index, seed) => {
                        let session =
                            ExecuteEvaluatorJob::begin_table_commitment(exec, peer_id, *index, *seed)
                                .await
                                .unwrap();
                        if let EvaluatorCircuitSession::Commitment(session) = session {
                            let res = garb_coord_do_your_thing(&exec.circuit_path, *session).await;
                            res
                        } else {
                            panic!()
                        }
                    }
                    _ => {
                        println!("unhandled evaluator action variant");
                        HandlerOutcome::Retry
                    },
                }
            }
            _ => panic!(),
        };
        match outcome {
            HandlerOutcome::Done(completion) => {
                eval_results.push(completion);
            }
            _ => panic!(),
        }
    }
    eval_results
}

use mosaic_job_api::CircuitSession;

async fn garb_coord_do_your_thing<S: CircuitSession>(
    circuit_path: &PathBuf,
    mut session: S,
) -> HandlerOutcome {
    let mut reader = ReaderV5c::open(circuit_path).unwrap();
    let total_gates = reader.header().total_gates();
    let mut block_idx: usize = 0;

    while let Some(chunk_result) = reader.next_blocks_chunk().await.transpose() {
        let reader_chunk = chunk_result.unwrap();
        let owned = convert_chunk(&reader_chunk, total_gates, &mut block_idx);
        (&mut session)
            .process_chunk(&Arc::new(owned))
            .await
            .unwrap();
    }
    let result = Box::new(session).finish().await;
    result
}

fn convert_chunk(
    reader_chunk: &ckt_fmtv5_types::v5::c::Chunk<'_>,
    total_gates: u64,
    block_idx: &mut usize,
) -> OwnedChunk {
    let mut blocks = Vec::new();

    for block in reader_chunk.blocks_iter() {
        let num_gates = get_block_num_gates(total_gates, *block_idx);
        *block_idx += 1;

        blocks.push(convert_block(block, num_gates));
    }

    OwnedChunk { blocks }
}

fn convert_block(block: &Block, num_gates: usize) -> OwnedBlock {
    const GATE_SIZE: usize = 12;
    // Copy gate data: num_gates × 12 bytes (3 × u32 LE).
    let gate_bytes = num_gates * GATE_SIZE;
    let gate_ptr = block.gates.as_ptr() as *const u8;
    // SAFETY: `Block::gates` is a contiguous array of `Gate` structs, each
    // containing three `u32` fields (in1, in2, out) with no padding (same-
    // sized fields guarantee no inter-field padding on all targets). The
    // resulting byte slice is immediately copied into a Vec, so no aliasing
    // concerns. `gate_bytes = num_gates * 12` never exceeds the allocation
    // because `num_gates <= block.gates.len()` (enforced by the caller via
    // `get_block_num_gates`).
    let gate_data = unsafe { std::slice::from_raw_parts(gate_ptr, gate_bytes) }.to_vec();

    // Copy gate type bits: ceil(num_gates / 8) bytes.
    let type_bytes = num_gates.div_ceil(8);
    let gate_types = block.types[..type_bytes].to_vec();

    OwnedBlock {
        gate_data,
        gate_types,
        num_gates,
    }
}

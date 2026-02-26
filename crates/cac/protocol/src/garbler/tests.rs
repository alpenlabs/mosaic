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
    state_machine::garbler::{
        ActionId as GarblerActionId, Config, DepositStep, GarblerDepositInitData, GarblerInitData,
        GarblerState, GarblerTrackedActionTypes, Input, StateMut, StateRead, Step,
    },
};
use mosaic_common::constants::{N_CIRCUITS, N_INPUT_WIRES, N_SETUP_INPUT_WIRES};
use mosaic_job_api::{ActionCompletion, ExecuteGarblerJob, HandlerOutcome, OwnedBlock, OwnedChunk};
use mosaic_job_executors::{
    MosaicExecutor,
    circuit_sessions::{CommitmentSession, GarblerCircuitSession},
};
use mosaic_net_client::{NetClient, NetClientConfig};
use mosaic_net_svc::{NetService, NetServiceConfig, PeerConfig, peer_id_from_signing_key};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{StorageProvider, TableReader, TableStore, TableWriter};
use mosaic_storage_inmemory::{evaluator::StoredEvaluatorState, garbler::StoredGarblerState};
use rand_chacha::{ChaCha20Rng, ChaChaRng, rand_core::SeedableRng};

use super::stf::handle_event;
use crate::garbler;

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

use fasm::StateMachine;

#[tokio::test]
async fn test_e2e() {
    let mut garb_state = StoredGarblerState::default();
    let mut garb_rng = ChaChaRng::seed_from_u64(42);
    let mut eval_state = StoredEvaluatorState::default();
    let mut eval_rng = ChaCha20Rng::seed_from_u64(43);

    let ts = DummyTableStore {};
    let circuit_path = PathBuf::from_str("").unwrap();
    let (peer_id, net_client) = dummy_net_client();

    let seed = rand_byte_array(&mut garb_rng).into();
    let setup_inputs = rand_byte_array(&mut garb_rng);

    let mut garb_actions: Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    > = Vec::new();
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(Input::Init(GarblerInitData { seed, setup_inputs })),
        &mut garb_actions,
    )
    .await
    .unwrap();

    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    let mut exec = MosaicExecutor::new(net_client, sp, ts, circuit_path);

    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, Input> =
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
    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, Input> =
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
    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id).await;
    assert_eq!(results.len(), N_CIRCUITS); // GarblerActionResult::TableCommitmentGenerated

    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, Input> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); // CommitMsgHeader + CommitMsgChunks

    // sends commit msg header then chunks
    let sp: DummyStorageProvider = DummyStorageProvider {
        garb_state: garb_state.clone(),
        eval_state: eval_state.clone(),
    };
    exec.update_state(sp);
    let mut results = mock_dispatchgarbler(&mut garb_actions, &exec, &peer_id).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, Input> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, &mut garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Step: WaitForChallenge; No Action
    // receives acknowledgements
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

fn dummy_net_client() -> (PeerId, NetClient) {
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

    (
        peer_id_a,
        NetClient::with_config(handle_a, NetClientConfig::default()),
    )
}

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};

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
                        let session = exec
                            .begin_table_commitment(peer_id, *index, *seed)
                            .await
                            .unwrap();
                        if let GarblerCircuitSession::Commitment(session) = session {
                            generate_table_commitment(&exec.circuit_path, *session).await
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
                    GarblerAction::DepositVerifyAdaptors(deposit_id) => {
                        exec.deposit_verify_adaptors(peer_id, *deposit_id).await
                    }
                    GarblerAction::CompleteAdaptorSignatures(deposit_id) => {
                        exec.complete_adaptor_signatures(peer_id, *deposit_id).await
                    }
                    // Circuit actions should be routed to the garbling coordinator,
                    // not to worker pool threads. If they arrive here, something is
                    // wrong with the scheduler's routing logic.
                    GarblerAction::TransferGarblingTable(..) => {
                        println!(
                            "circuit action reached worker pool — should go to garbling coordinator"
                        );
                        HandlerOutcome::Retry
                    }
                    _ => {
                        println!("unhandled garbler action variant");
                        HandlerOutcome::Retry
                    }
                    _ => panic!(),
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

use mosaic_job_api::CircuitSession;

async fn generate_table_commitment(
    circuit_path: &PathBuf,
    mut session: CommitmentSession,
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

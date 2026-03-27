use std::{env::temp_dir, path::PathBuf, sync::Arc, time::Duration};

use ckt_fmtv5_types::v5::c::{Block, ReaderV5c, get_block_num_gates};
use fasm::actions;
use mosaic_cac_types::{
    CompletedSignatures, DepositId, DepositInputs, HeapArray, KeyPair, PubKey, SecretKey, Seed,
    SetupInputs, Sighash, Sighashes, WithdrawalInputs,
    state_machine::{
        evaluator::{
            DepositStep as EvalDepositStep, EvaluatorDepositInitData,
            EvaluatorDisputedWithdrawalData, EvaluatorInitData, EvaluatorTrackedActionTypes,
            Input as EvalInput, Step as EvalStep,
        },
        garbler::{
            DepositStep as GarbDepositStep, GarblerDepositInitData, GarblerInitData,
            GarblerTrackedActionTypes, Input as GarbInput, Step as GarbStep,
        },
    },
};
use mosaic_common::{
    Byte32,
    constants::{
        N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_EVAL_CIRCUITS, N_INPUT_WIRES,
        N_OPEN_CIRCUITS, N_WITHDRAWAL_INPUT_WIRES,
    },
};
use mosaic_job_api::{ActionCompletion, ExecuteGarblerJob, HandlerOutcome, OwnedBlock, OwnedChunk};
use mosaic_job_executors::{
    MosaicExecutor,
    circuit_sessions::{EvaluationSession, EvaluatorCircuitSession, GarblerCircuitSession},
};
use mosaic_net_client::NetClient;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_storage_inmemory::{evaluator::StoredEvaluatorState, garbler::StoredGarblerState};
use mosaic_storage_s3::S3TableStore;
use object_store::{ObjectStore, local::LocalFileSystem};
use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::{
    evaluator, garbler,
    tests::netcl::{
        handle_receive_adaptor_msg_chunks, handle_receive_challenge,
        handle_receive_challenge_response, handle_receive_commit_msg,
    },
};

fn rand_byte_array<const N: usize, R: rand_chacha::rand_core::RngCore>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// copied from net/client/integration.rs except
/// handle_receive_challenge, handle_receive_challenge_response, handle_receive_commit_msg
mod netcl {
    use std::{
        net::SocketAddr,
        sync::{
            Once,
            atomic::{AtomicU16, Ordering},
        },
        time::Duration,
    };

    use ed25519_dalek::SigningKey;
    use mosaic_cac_types::{
        DepositId, Msg,
        state_machine::{evaluator::Input as EvalInput, garbler::Input as GarbInputs},
    };
    use mosaic_common::constants::{
        N_CHALLENGE_RESPONSE_CHUNKS, N_COMMIT_MSG_CHUNKS, N_DEPOSIT_INPUT_WIRES, N_EVAL_CIRCUITS,
    };
    use mosaic_net_client::{NetClient, NetClientConfig};
    use mosaic_net_svc::{
        NetService, NetServiceConfig, PeerConfig, PeerId, peer_id_from_signing_key,
    };

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

    fn test_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed;
        SigningKey::from_bytes(&bytes)
    }

    fn test_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    pub(super) struct TestPeer {
        pub client: NetClient,
        pub peer_id: PeerId,
        _controller: mosaic_net_svc::svc::NetServiceController,
    }

    /// Create a pair of connected peers with NetClient instances.
    ///
    /// Services are created in sequence with a delay to avoid the simultaneous
    /// connect race condition in net-svc's deterministic connection selection.
    pub(super) fn create_client_pair() -> (TestPeer, TestPeer) {
        create_client_pair_with_config(NetClientConfig::default())
    }

    fn create_client_pair_with_config(config: NetClientConfig) -> (TestPeer, TestPeer) {
        for attempt in 0..50 {
            let port_a = next_port();
            let port_b = next_port();

            let key_a = test_key(1);
            let key_b = test_key(2);

            let peer_id_a = peer_id_from_signing_key(&key_a);
            let peer_id_b = peer_id_from_signing_key(&key_b);

            let addr_a = test_addr(port_a);
            let addr_b = test_addr(port_b);

            let config_a =
                NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)])
                    .with_reconnect_backoff(Duration::from_millis(200));

            let (handle_a, ctrl_a) = match NetService::new(config_a) {
                Ok(result) => result,
                Err(e) => {
                    if attempt < 49 {
                        continue;
                    }
                    panic!("create net service A after 50 attempts: {}", e);
                }
            };

            let config_b =
                NetServiceConfig::new(key_b, addr_b, vec![PeerConfig::new(peer_id_a, addr_a)])
                    .with_reconnect_backoff(Duration::from_millis(200));

            let (handle_b, ctrl_b) = match NetService::new(config_b) {
                Ok(result) => result,
                Err(e) => {
                    let _ = ctrl_a.shutdown();
                    if attempt < 49 {
                        continue;
                    }
                    panic!("create net service B after 50 attempts: {}", e);
                }
            };

            // No fixed sleep - send_and_receive handles connection stabilization with retries

            return (
                TestPeer {
                    client: NetClient::with_config(handle_a, config),
                    peer_id: peer_id_a,
                    _controller: ctrl_a,
                },
                TestPeer {
                    client: NetClient::with_config(handle_b, config),
                    peer_id: peer_id_b,
                    _controller: ctrl_b,
                },
            );
        }

        unreachable!()
    }

    pub(crate) async fn handle_receive_commit_msg(net_client: NetClient) -> Vec<EvalInput> {
        let mut collections = vec![];

        for _ in 0..N_COMMIT_MSG_CHUNKS + 1 {
            const CI_TIMEOUT: Duration = Duration::from_secs(300);
            let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
                Ok(Ok(request)) => request,
                Ok(Err(err)) => panic!("recv failed: {:?}", err),
                Err(_) => {
                    // send_handle.abort();
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::CommitHeader(header) => EvalInput::RecvCommitMsgHeader(header.clone()),
                Msg::CommitChunk(chunk) => EvalInput::RecvCommitMsgChunk(chunk.clone()),
                _ => panic!(),
            };
            request.ack().await.expect("ack failed");
            collections.push(header);
        }

        collections
    }

    pub(crate) async fn handle_receive_challenge_response(net_client: NetClient) -> Vec<EvalInput> {
        let mut collections = vec![];

        for _ in 0..N_CHALLENGE_RESPONSE_CHUNKS + 1 {
            const CI_TIMEOUT: Duration = Duration::from_secs(300);
            let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
                Ok(Ok(request)) => request,
                Ok(Err(err)) => panic!("recv failed: {:?}", err),
                Err(_) => {
                    // send_handle.abort();
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::ChallengeResponseHeader(header) => {
                    EvalInput::RecvChallengeResponseMsgHeader(header.clone())
                }
                Msg::ChallengeResponseChunk(chunk) => {
                    EvalInput::RecvChallengeResponseMsgChunk(chunk.clone())
                }
                _ => panic!(),
            };
            request.ack().await.expect("ack failed");
            collections.push(header);
        }

        collections
    }

    pub(crate) async fn handle_receive_challenge(net_client: &NetClient) -> GarbInputs {
        const CI_TIMEOUT: Duration = Duration::from_secs(300);
        let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
            Ok(Ok(request)) => request,
            Ok(Err(err)) => panic!("recv failed: {:?}", err),
            Err(_) => {
                // send_handle.abort();
                panic!("recv timed out after {CI_TIMEOUT:?}");
            }
        };
        let header = match &request.message {
            Msg::Challenge(header) => GarbInputs::RecvChallengeMsg(header.clone()),
            _ => panic!(),
        };
        request.ack().await.expect("ack failed");
        header
    }

    pub(crate) async fn handle_receive_adaptor_msg_chunks(
        net_client: &NetClient,
        deposit_id: DepositId,
    ) -> Vec<GarbInputs> {
        let mut collections = vec![];

        for _ in 0..N_DEPOSIT_INPUT_WIRES {
            const CI_TIMEOUT: Duration = Duration::from_secs(300);
            let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
                Ok(Ok(request)) => request,
                Ok(Err(err)) => panic!("recv failed: {:?}", err),
                Err(_) => {
                    // send_handle.abort();
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::AdaptorChunk(header) => {
                    GarbInputs::DepositRecvAdaptorMsgChunk(deposit_id, header.clone())
                }
                _ => panic!(),
            };
            request.ack().await.expect("ack failed");
            collections.push(header);
        }

        collections
    }

    pub(crate) async fn handle_receive_table_transfer_receipt(
        net_client: &NetClient,
    ) -> Vec<GarbInputs> {
        let mut collections = vec![];
        for _ in 0..N_EVAL_CIRCUITS {
            const CI_TIMEOUT: Duration = Duration::from_secs(300);
            let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
                Ok(Ok(request)) => request,
                Ok(Err(err)) => panic!("recv failed: {:?}", err),
                Err(_) => {
                    // send_handle.abort();
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::TableTransferReceipt(index) => GarbInputs::RecvTableTransferReceipt(*index),
                _ => panic!(),
            };
            request.ack().await.expect("ack failed");
            collections.push(header);
        }
        collections
    }
}

async fn handle_init_garbler(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_seed: Seed,
    setup_inputs: SetupInputs,
) {
    garbler::GarblerSM::stf(
        garb_state,
        fasm::Input::Normal(GarbInput::Init(GarblerInitData {
            seed: garb_seed,
            setup_inputs,
        })),
        garb_actions,
    )
    .await
    .unwrap();
}

async fn handle_init_evaluator(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_seed: Seed,
    setup_inputs: SetupInputs,
) {
    evaluator::EvaluatorSM::stf(
        eval_state,
        fasm::Input::Normal(EvalInput::Init(EvaluatorInitData {
            seed: eval_seed,
            setup_inputs,
        })),
        eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), 0); // Step Waiting For Commit
}

async fn handle_garbler_prepares_commit_msg(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garbler_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_peer_id: PeerId,
) {
    assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); //  Action::GeneratePolynomialCommitments: [Output, Inputs..]
    let mut results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    assert_eq!(results.len(), N_INPUT_WIRES + 1); // ActionResult::PolynomialCommitmentsGenerated: [Output, Inputs..]
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    // returns Action::GenerateShares
    assert_eq!(garb_actions.len(), N_CIRCUITS + 1);

    garbler_exec.storage.garb_state = garb_state.clone();

    let mut results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }

    assert_eq!(garb_actions.len(), N_CIRCUITS); // [Action::GenerateTableCommitment; N_CIRCUITS]

    garbler_exec.storage.garb_state = garb_state.clone();
    let mut results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    assert_eq!(results.len(), N_CIRCUITS); // GarblerActionResult::TableCommitmentGenerated

    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); // Action::SendCommitMsgHeader + Action::SendCommitMsgChunk
}

async fn handlle_garbler_transfers_commit_msg(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garbler_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_peer_id: PeerId,
    net_client_evaluator: NetClient,
) -> (Vec<EvalInput>, Vec<ActionCompletion>) {
    // Make evaluator listen
    let encl = net_client_evaluator.clone();
    let commit_msg_listener = tokio::spawn(async move { handle_receive_commit_msg(encl).await });

    tracing::info!("send commit msg");
    // sends commit msg header then chunks; evaluator should have been listening
    garbler_exec.storage.garb_state = garb_state.clone();
    let garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;

    tracing::info!("receive commit msg");
    // Evaluator reads
    let eval_inputs = commit_msg_listener.await.unwrap();
    assert_eq!(eval_inputs.len(), 1 + N_INPUT_WIRES);

    (eval_inputs, garb_results)
}

async fn handle_garbler_waits_for_challenge(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Step: WaitForChallenge; No Action // network ack
}

async fn handle_evaluator_prepares_challenge(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_inputs: &mut Vec<EvalInput>,
) {
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(eval_state, fasm::Input::Normal(ei), eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // SendChallenge
}

async fn handle_evaluator_transfers_challenge_msg(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    garbler_peer_id: PeerId,
    net_client_garbler: NetClient,
) -> (GarbInput, Vec<ActionCompletion>) {
    let ncl = net_client_garbler;
    let challenge_msg_listener = tokio::spawn(async move { handle_receive_challenge(&ncl).await });

    // Evaluator sends challenge over network
    tracing::info!("mock_dispatch_evaluator; send_challenge");
    eval_exec.storage.eval_state = eval_state.clone();
    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;

    let garb_inputs = challenge_msg_listener.await.unwrap(); // ChallengeMsg
    (garb_inputs, eval_results)
}

async fn handle_evaluator_waits_for_challenge_response(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_results: &mut Vec<ActionCompletion>,
) {
    // eval's tx is acked
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0); // Challenge was acked; step WaitingForChallengeResponse
}

async fn handle_garbler_prepares_challenge_response(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_inputs: GarbInput,
) {
    garbler::GarblerSM::stf(garb_state, fasm::Input::Normal(garb_inputs), garb_actions)
        .await
        .unwrap();
    assert_eq!(garb_actions.len(), 1 + N_OPEN_CIRCUITS); // Challenge Response Header + Challenge Response Chunks (one chunk for each circuit)
}

async fn handle_garbler_transfers_challenge_response(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garbler_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_peer_id: PeerId,
    net_client_evaluator: NetClient,
) -> (Vec<EvalInput>, Vec<ActionCompletion>) {
    let encl = net_client_evaluator.clone();
    let challenge_response_listener =
        tokio::spawn(async move { handle_receive_challenge_response(encl).await });

    garbler_exec.storage.garb_state = garb_state.clone();
    let garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;

    let eval_inputs = challenge_response_listener.await.unwrap();

    (eval_inputs, garb_results)
}

async fn handle_garbler_prepares_for_table_transfer(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), N_EVAL_CIRCUITS); //  Step::TransferringGarblingTables; Action::TransferGarblingTable
}

async fn handle_evaluator_processes_challenge_response(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_inputs: &mut Vec<EvalInput>,
    garbler_peer_id: PeerId,
) {
    // Evaluator receives challenge response
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(eval_state, fasm::Input::Normal(ei), eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // Step::VerifyingOpenedInputShares; Action::VerifyOpenedInputShares

    tracing::info!("mock_dispatch_evaluator; verify shares");
    eval_exec.storage.eval_state = eval_state.clone();
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    tracing::info!("shares verified");
    assert_eq!(eval_results.len(), 1); // ActionResult::VerifyOpenedInputSharesResult
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_OPEN_CIRCUITS); // Action::GenerateTableCommitment(index, seed), Step::VerifyingTableCommitments

    tracing::info!("mock_dispatch_evaluator; generate table commitment");
    eval_exec.storage.eval_state = eval_state.clone();
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_OPEN_CIRCUITS); // ActionResult::TableCommitmentGenerated
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Step::ReceivingGarblingTables, Action::ReceiveGarblingTable
}

async fn handle_evaluator_processes_table(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_results: &mut Vec<ActionCompletion>,
) {
    // process receipt
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Step::SetupComplete, Action::SendTableTransferReceipt
    assert_eq!(
        eval_state.clone().state.unwrap().step,
        EvalStep::SetupComplete
    );
}

async fn handle_garbler_waits_for_receipt(
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // step: waiting for table transfer receipt
}

async fn handle_evaluator_transfers_receipt(
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_state: &mut StoredEvaluatorState,
    garbler_peer_id: PeerId,
    net_client_gabler: NetClient,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    // garbler listens for table transfer receipt
    let ncl = net_client_gabler.clone();
    let tx = tokio::spawn(async move {
        use crate::tests::netcl::handle_receive_table_transfer_receipt;
        handle_receive_table_transfer_receipt(&ncl).await
    });

    // evaluator sends table receipt
    eval_exec.storage.eval_state = eval_state.clone();

    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_EVAL_CIRCUITS); // ActionResult::GarblingTableTransferReceiptAcked
    // garbler received table transfer receipts
    let garb_inputs = tx.await.unwrap();
    assert_eq!(garb_inputs.len(), N_EVAL_CIRCUITS);
    (garb_inputs, eval_results)
}

async fn handle_evaluator_consumes_receipt_ack(
    eval_results: &mut Vec<ActionCompletion>,
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
) {
    // Stf ignores ack as state has been transitioned to SetupComplete already
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);
    assert_eq!(
        eval_state.clone().state.unwrap().step,
        EvalStep::SetupComplete
    );
}

async fn handle_garbler_consumes_receipt_ack(
    garb_inputs: &mut Vec<GarbInput>,
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
) {
    while let Some(input) = garb_inputs.pop() {
        garbler::GarblerSM::stf(garb_state, fasm::Input::Normal(input), garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // setup complete
    assert_eq!(
        garb_state.clone().state.unwrap().step,
        GarbStep::SetupComplete
    );
}

async fn handle_garbler_inits_deposit(
    sighashes: Sighashes,
    deposit_inputs: DepositInputs,
    eval_pubkey: PubKey,
    deposit_id: DepositId,
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
) {
    let deposit_input: GarblerDepositInitData = GarblerDepositInitData {
        pk: eval_pubkey,
        sighashes: HeapArray::from_vec(sighashes.to_vec()),
        deposit_inputs,
    };
    garbler::GarblerSM::stf(
        garb_state,
        fasm::Input::Normal(GarbInput::DepositInit(deposit_id, deposit_input)),
        garb_actions,
    )
    .await
    .unwrap();
    assert_eq!(garb_actions.len(), 0);
}

#[allow(clippy::too_many_arguments)]
async fn handle_evaluator_inits_deposit(
    sighashes: Sighashes,
    eval_sk: SecretKey,
    deposit_inputs: DepositInputs,
    deposit_id: DepositId,
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    garbler_peer_id: PeerId,
) {
    let deposit_input: EvaluatorDepositInitData = EvaluatorDepositInitData {
        sk: eval_sk,
        sighashes: HeapArray::from_vec(sighashes.to_vec()),
        deposit_inputs,
    };

    evaluator::EvaluatorSM::stf(
        eval_state,
        fasm::Input::Normal(EvalInput::DepositInit(deposit_id, deposit_input)),
        eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), 1 + N_ADAPTOR_MSG_CHUNKS); // Action::GenerateDepositAdaptors + [Action::GenerateWithdrawalAdaptorsChunk]

    eval_exec.storage.eval_state = eval_state.clone();

    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_DEPOSIT_INPUT_WIRES); //  Action::DepositSendAdaptorMsgChunk
}

async fn handle_evaluator_sends_adaptors(
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    garbler_peer_id: PeerId,
    net_client_gabler: NetClient,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    tracing::info!("handle_receive_adaptor_msg_chunks");
    // adaptor chunks listener
    let ncl = net_client_gabler.clone();
    let challenge_msg_listener =
        tokio::spawn(async move { handle_receive_adaptor_msg_chunks(&ncl, deposit_id).await });

    // send adaptor msg chunks
    eval_exec.storage.eval_state = eval_state.clone();
    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_DEPOSIT_INPUT_WIRES); // ActionResult::DepositAdaptorChunkSent

    // garbler listens for adaptors
    let garb_inputs = challenge_msg_listener.await.unwrap();
    assert_eq!(garb_inputs.len(), N_DEPOSIT_INPUT_WIRES);

    (garb_inputs, eval_results)
}

async fn handle_evaluator_is_deposit_ready(
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    eval_results: &mut Vec<ActionCompletion>,
) {
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);

    assert_eq!(
        eval_state
            .deposits
            .get(&deposit_id)
            .unwrap()
            .state
            .as_ref()
            .unwrap()
            .step,
        EvalDepositStep::DepositReady
    );
    // assert evaluator is deposit ready
}

async fn handle_garbler_verifies_adaptors(
    garbler_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    garb_state: &mut StoredGarblerState,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    eval_peer_id: PeerId,
    deposit_id: DepositId,
) {
    let mut garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    // results ActionResult::DepositAdaptorVerificationResult
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0);
    assert_eq!(
        garb_state
            .deposits
            .get(&deposit_id)
            .unwrap()
            .state
            .as_ref()
            .unwrap()
            .step,
        GarbDepositStep::DepositReady
    );
    // garbler is deposit ready
    tracing::info!("garbler is deposit ready");
    // garbler is deposit ready
    tracing::info!("garbler is deposit ready");
}

async fn handle_garbler_starts_adaptor_verification_job(
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_inputs: &mut Vec<GarbInput>,
    garb_state: &mut StoredGarblerState,
) {
    while let Some(ei) = garb_inputs.pop() {
        garbler::GarblerSM::stf(garb_state, fasm::Input::Normal(ei), garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1); // DepositStep::VerifyingAdaptors
}

async fn handle_garbler_completes_signatures(
    garbler_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_state: &mut StoredGarblerState,
    deposit_id: DepositId,
    withdrawal_input: WithdrawalInputs,
    eval_peer_id: PeerId,
) -> CompletedSignatures {
    garbler::GarblerSM::stf(
        garb_state,
        fasm::Input::Normal(GarbInput::DisputedWithdrawal(deposit_id, withdrawal_input)),
        garb_actions,
    )
    .await
    .unwrap();
    assert_eq!(garb_actions.len(), 1); // Action::CompleteAdaptorSignatures

    garbler_exec.storage.garb_state = garb_state.clone();
    let mut garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await; // ActionResult::AdaptorSignaturesCompleted
    assert_eq!(garb_results.len(), 1);

    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Setup Consumed
    assert_eq!(
        garb_state.clone().state.as_ref().unwrap().step,
        GarbStep::SetupConsumed { deposit_id }
    );

    let on_chain_sigs = garb_state
        .deposits
        .get(&deposit_id)
        .unwrap()
        .completed_sigs
        .as_ref()
        .unwrap();
    on_chain_sigs.clone()
}

async fn handle_evaluator_finds_fault_secret(
    eval_exec: &mut MosaicExecutor<DummyStorageProvider, S3TableStore>,
    on_chain_sigs: CompletedSignatures,
    eval_state: &mut StoredEvaluatorState,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    garbler_peer_id: PeerId,
) {
    let eval_disputed_withdrawal = EvaluatorDisputedWithdrawalData {
        signatures: on_chain_sigs.clone(),
    };
    evaluator::EvaluatorSM::stf(
        eval_state,
        fasm::Input::Normal(EvalInput::DisputedWithdrawal(
            deposit_id,
            eval_disputed_withdrawal,
        )),
        eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Action::EvaluateGarblingTable

    tracing::info!("evaluate garbling table");
    eval_exec.storage.eval_state = eval_state.clone();
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_EVAL_CIRCUITS);
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);
}

use fasm::StateMachine;
#[tokio::test]
// OPTIONAL steps to generate v5c file yourself:
// 1. clone: g16 repo and switch to branch test/simple_circuit_postaudit
// test/simple_circuit_postaudit branch generates small ckt file that does input validation
// only; not the actually groth16 verification afterwards; Meant for test purposes only]
// 2. generate v5a ckt file: cd g16gen && cargo run generate 6 && cargo run write-input-bits 6
// 3. clone: ckt repo
// 4. move g16gen/g16.ckt file to ckt/lvl/
// 5. generate v5c file: cd crates/lvl && cargo run prealloc g16.ckt g16.v5c
// 6. move lvl/g16.v5c to mosaic/cac/protocol/
// 7. Run test with: cargo test --release --package mosaic-cac-protocol --lib -- tests::test_e2e
//    --exact --show-output --nocapture
async fn test_e2e() {
    use mosaic_cac_types::WithdrawalInputs;
    use mosaic_common::constants::N_SETUP_INPUT_WIRES;

    let test_vector = {
        let mut test_vecs = vec![];
        let mut rng = ChaCha20Rng::seed_from_u64(70);

        let mut setup_inputs = [0; N_SETUP_INPUT_WIRES];
        let mut deposit_inputs = [0u8; N_DEPOSIT_INPUT_WIRES];
        let mut withdrawal_input: WithdrawalInputs = [0; N_WITHDRAWAL_INPUT_WIRES];
        rng.fill_bytes(&mut setup_inputs);
        rng.fill_bytes(&mut deposit_inputs);
        rng.fill_bytes(&mut withdrawal_input);

        deposit_inputs[0] = 0;
        test_vecs.push((setup_inputs, deposit_inputs, withdrawal_input, true)); // reveal secret = true because output is 0

        deposit_inputs[0] = 1;
        test_vecs.push((setup_inputs, deposit_inputs, withdrawal_input, false)); // reveal secret = false because output is 1

        test_vecs
    };

    for (iter, (setup_inputs, deposit_inputs, withdrawal_input, reveals_secret)) in
        test_vector.into_iter().enumerate()
    {
        tracing::info!("ITERATION {}", iter + 1);
        let mut garb_state = StoredGarblerState::default();
        let mut garb_rng = ChaCha20Rng::seed_from_u64(42);
        let mut eval_state = StoredEvaluatorState::default();
        let mut eval_rng = ChaCha20Rng::seed_from_u64(43);

        let temp_dir = temp_dir();
        let prefix = "garbling-tables";
        std::fs::create_dir_all(temp_dir.clone()).unwrap();
        let local = LocalFileSystem::new_with_prefix(temp_dir.clone()).unwrap();
        let ts = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);

        let circuit_path = PathBuf::from(env!("MOSAIC_ARTIFACTS_DIR")).join("g16.v5c");
        assert!(
            std::fs::exists(circuit_path.clone()).unwrap(),
            "expects v5c format ckt file on circuit_path"
        );
        let (peer_a, peer_b) = netcl::create_client_pair();
        let (net_client_gabler, garbler_peer_id, net_client_evaluator, eval_peer_id) =
            (peer_a.client, peer_a.peer_id, peer_b.client, peer_b.peer_id);

        let garb_seed = rand_byte_array(&mut garb_rng).into();
        let eval_seed = rand_byte_array(&mut eval_rng).into();

        // Run Garbler STF
        let sp: DummyStorageProvider = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut garbler_exec =
            MosaicExecutor::new(net_client_gabler.clone(), sp, ts, circuit_path.clone());

        let sp: DummyStorageProvider = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };

        let prefix = "evaluating-tables";
        let local = LocalFileSystem::new_with_prefix(temp_dir.clone()).unwrap();
        let ts = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);

        let mut eval_exec =
            MosaicExecutor::new(net_client_evaluator.clone(), sp, ts, circuit_path.clone());

        let mut garb_actions: Vec<
            actions::Action<
                mosaic_cac_types::state_machine::garbler::UntrackedAction,
                GarblerTrackedActionTypes,
            >,
        > = Vec::new();

        // Initialize evaluator
        let mut eval_actions: Vec<
            actions::Action<
                mosaic_cac_types::state_machine::evaluator::UntrackedAction,
                EvaluatorTrackedActionTypes,
            >,
        > = Vec::new();

        handle_init_garbler(&mut garb_state, &mut garb_actions, garb_seed, setup_inputs).await;

        handle_init_evaluator(&mut eval_state, &mut eval_actions, eval_seed, setup_inputs).await;

        handle_garbler_prepares_commit_msg(
            &mut garb_state,
            &mut garb_actions,
            &mut garbler_exec,
            eval_peer_id,
        )
        .await;

        tracing::info!("spawn commit msg listener");
        let (mut eval_inputs, mut garb_results) = handlle_garbler_transfers_commit_msg(
            &mut garb_state,
            &mut garb_actions,
            &mut garbler_exec,
            eval_peer_id,
            net_client_evaluator.clone(),
        )
        .await;

        // garbler waits for challenge
        handle_garbler_waits_for_challenge(&mut garb_state, &mut garb_actions, &mut garb_results)
            .await;

        //Evaluator receives commit msg
        handle_evaluator_prepares_challenge(&mut eval_state, &mut eval_actions, &mut eval_inputs)
            .await;

        tracing::info!("Evaluator Wants to Send Challenge; Garbler should be listening");

        let (garb_inputs, mut eval_results) = handle_evaluator_transfers_challenge_msg(
            &mut eval_state,
            &mut eval_actions,
            &mut eval_exec,
            garbler_peer_id,
            net_client_gabler.clone(),
        )
        .await;

        // evaluator waits for challenge response
        handle_evaluator_waits_for_challenge_response(
            &mut eval_state,
            &mut eval_actions,
            &mut eval_results,
        )
        .await;

        // garbler processes challenge and prepares challenge response
        handle_garbler_prepares_challenge_response(&mut garb_state, &mut garb_actions, garb_inputs)
            .await;

        let (mut eval_inputs, mut garb_results) = handle_garbler_transfers_challenge_response(
            &mut garb_state,
            &mut garb_actions,
            &mut garbler_exec,
            eval_peer_id,
            net_client_evaluator,
        )
        .await;

        handle_garbler_prepares_for_table_transfer(
            &mut garb_state,
            &mut garb_actions,
            &mut garb_results,
        )
        .await;

        handle_evaluator_processes_challenge_response(
            &mut eval_state,
            &mut eval_actions,
            &mut eval_exec,
            &mut eval_inputs,
            garbler_peer_id,
        )
        .await;

        // Table Transfer
        let (mut garb_results, mut eval_results) = {
            garbler_exec.storage.garb_state = garb_state.clone();
            // transfer tables background
            let tx = tokio::spawn(async move {
                mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await
            });
            // evaluator receives table
            eval_exec.storage.eval_state = eval_state.clone();
            let eval_results =
                mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
            assert_eq!(eval_results.len(), N_EVAL_CIRCUITS);
            // garbler transfer tables done
            let garb_results = tx.await.unwrap();
            assert_eq!(garb_results.len(), N_EVAL_CIRCUITS);
            (garb_results, eval_results)
        };

        // process table and prepare receipt
        handle_evaluator_processes_table(&mut eval_state, &mut eval_actions, &mut eval_results)
            .await;

        let mut garb_actions = vec![];
        handle_garbler_waits_for_receipt(&mut garb_state, &mut garb_actions, &mut garb_results)
            .await;

        let (mut garb_inputs, mut eval_results) = handle_evaluator_transfers_receipt(
            &mut eval_actions,
            &mut eval_exec,
            &mut eval_state,
            garbler_peer_id,
            net_client_gabler.clone(),
        )
        .await;

        handle_evaluator_consumes_receipt_ack(
            &mut eval_results,
            &mut eval_state,
            &mut eval_actions,
        )
        .await;

        handle_garbler_consumes_receipt_ack(&mut garb_inputs, &mut garb_state, &mut garb_actions)
            .await;

        tracing::info!("setup complete");

        let deposit_id = {
            let mut empty: [u8; 32] = [0; 32];
            empty[0] = 7;
            DepositId(Byte32::from(empty))
        };
        let sighashes =
            [Sighash(Byte32::from([0u8; 32])); N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];
        let eval_keypair = KeyPair::rand(&mut eval_rng);

        handle_garbler_inits_deposit(
            HeapArray::from_vec(sighashes.to_vec()),
            deposit_inputs,
            eval_keypair.public_key(),
            deposit_id,
            &mut garb_state,
            &mut garb_actions,
        )
        .await;

        handle_evaluator_inits_deposit(
            HeapArray::from_vec(sighashes.to_vec()),
            eval_keypair.secret_key(),
            deposit_inputs,
            deposit_id,
            &mut eval_state,
            &mut eval_actions,
            &mut eval_exec,
            garbler_peer_id,
        )
        .await;

        let (mut garb_inputs, mut eval_results) = handle_evaluator_sends_adaptors(
            &mut eval_exec,
            &mut eval_state,
            &mut eval_actions,
            deposit_id,
            garbler_peer_id,
            net_client_gabler.clone(),
        )
        .await;

        handle_evaluator_is_deposit_ready(
            &mut eval_state,
            &mut eval_actions,
            deposit_id,
            &mut eval_results,
        )
        .await;

        handle_garbler_starts_adaptor_verification_job(
            &mut garb_actions,
            &mut garb_inputs,
            &mut garb_state,
        )
        .await;

        let sp = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let prefix = "garbling-tables";
        let local = LocalFileSystem::new_with_prefix(temp_dir.clone()).unwrap();
        let ts = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);
        let mut garbler_exec =
            MosaicExecutor::new(net_client_gabler.clone(), sp, ts, circuit_path.clone());
        handle_garbler_verifies_adaptors(
            &mut garbler_exec,
            &mut garb_state,
            &mut garb_actions,
            eval_peer_id,
            deposit_id,
        )
        .await;

        tracing::info!("Withdrawal Stage");
        // STARTING WITHDRAWAL STAGE for Disputed Withdrawal

        tracing::info!("Withdrawal Stage");
        // STARTING WITHDRAWAL STAGE for Disputed Withdrawal

        let on_chain_sigs = handle_garbler_completes_signatures(
            &mut garbler_exec,
            &mut garb_actions,
            &mut garb_state,
            deposit_id,
            withdrawal_input,
            eval_peer_id,
        )
        .await;

        handle_evaluator_finds_fault_secret(
            &mut eval_exec,
            on_chain_sigs,
            &mut eval_state,
            &mut eval_actions,
            deposit_id,
            garbler_peer_id,
        )
        .await;

        match eval_state.clone().state.unwrap().step {
            EvalStep::SetupConsumed {
                deposit_id: deposit_idx,
                slash,
            } => {
                assert_eq!(deposit_id, deposit_idx);
                assert_eq!(slash.is_some(), reveals_secret);
                if reveals_secret {
                    use mosaic_cac_types::state_machine::evaluator::StateRead;
                    let output_poly_commit = eval_state
                        .get_output_polynomial_commitment()
                        .await
                        .unwrap()
                        .unwrap()[0]
                        .get_zeroth_coefficient();

                    let share_commit = slash.unwrap().to_pubkey();
                    assert_eq!(share_commit.0, output_poly_commit, "should be keypairs");
                }
            }
            _ => panic!(),
        };
    }
}

struct DummyStorageProvider {
    garb_state: StoredGarblerState,
    eval_state: StoredEvaluatorState,
}

impl StorageProvider for DummyStorageProvider {
    type GarblerState = StoredGarblerState;
    type EvaluatorState = StoredEvaluatorState;

    async fn garbler_state(
        &self,
        _peer_id: &PeerId,
    ) -> mosaic_storage_api::StorageProviderResult<Self::GarblerState> {
        Ok(self.garb_state.clone())
    }

    async fn evaluator_state(
        &self,
        _peer_id: &PeerId,
    ) -> mosaic_storage_api::StorageProviderResult<Self::EvaluatorState> {
        Ok(self.eval_state.clone())
    }
}

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};

async fn mock_dispatch_garbler(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<DummyStorageProvider, S3TableStore>,
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
                            garb_coordinator(&exec.circuit_path, *session).await
                        } else {
                            panic!()
                        }
                    }
                    GarblerAction::SendCommitMsgHeader(header) => {
                        exec.send_commit_msg_header(peer_id, header).await
                    }
                    GarblerAction::SendCommitMsgChunk(chunk) => {
                        exec.send_commit_msg_chunk(peer_id, *chunk).await
                    }
                    GarblerAction::SendChallengeResponseMsgHeader(header) => {
                        exec.send_challenge_response_header(peer_id, header).await
                    }
                    GarblerAction::SendChallengeResponseMsgChunk(chunk) => {
                        exec.send_challenge_response_chunk(peer_id, chunk).await
                    }
                    GarblerAction::TransferGarblingTable(seed) => {
                        let session = ExecuteGarblerJob::begin_table_transfer(exec, peer_id, *seed)
                            .await
                            .unwrap();
                        if let GarblerCircuitSession::Transfer(session) = session {
                            let r = garb_coordinator(&exec.circuit_path, *session).await;
                            tokio::time::sleep(Duration::from_secs(1)).await; // added sleep to give time for transfer; else we get PeerFinished Error
                            r
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
                        tracing::info!("unhandled garbler action variant {:?}", action);
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

use mosaic_job_api::ExecuteEvaluatorJob;
async fn mock_dispatch_evaluator(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<DummyStorageProvider, S3TableStore>,
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
                    EvaluatorAction::VerifyOpenedInputShares => {
                        exec.verify_opened_input_shares(peer_id).await
                    }
                    EvaluatorAction::GenerateTableCommitment(index, seed) => {
                        let session = ExecuteEvaluatorJob::begin_table_commitment(
                            exec, peer_id, *index, *seed,
                        )
                        .await
                        .unwrap();
                        if let EvaluatorCircuitSession::Commitment(session) = session {
                            garb_coordinator(&exec.circuit_path, *session).await
                        } else {
                            panic!()
                        }
                    }
                    EvaluatorAction::ReceiveGarblingTable(commitment) => {
                        exec.receive_garbling_table(peer_id, *commitment).await
                    }
                    EvaluatorAction::SendTableTransferReceipt(idx) => {
                        exec.send_table_transfer_receipt(peer_id, idx).await
                    }
                    EvaluatorAction::GenerateDepositAdaptors(deposit_id) => {
                        exec.generate_deposit_adaptors(peer_id, *deposit_id).await
                    }
                    EvaluatorAction::GenerateWithdrawalAdaptorsChunk(deposit_id, chunk_idx) => {
                        exec.generate_withdrawal_adaptors_chunk(peer_id, *deposit_id, chunk_idx)
                            .await
                    }
                    EvaluatorAction::DepositSendAdaptorMsgChunk(deposit_id, chunk) => {
                        exec.deposit_send_adaptor_msg_chunk(peer_id, *deposit_id, chunk)
                            .await
                    }
                    EvaluatorAction::EvaluateGarblingTable(circuit_index, commitment) => {
                        let session = ExecuteEvaluatorJob::begin_evaluation(
                            exec,
                            peer_id,
                            *circuit_index,
                            *commitment,
                        )
                        .await
                        .unwrap();
                        if let EvaluatorCircuitSession::Evaluation(session) = session {
                            let session: EvaluationSession = *session;
                            garb_coordinator(&exec.circuit_path, session).await
                        } else {
                            panic!()
                        }
                    }
                    _ => {
                        panic!("unhandled evaluator action variant");
                    }
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

async fn garb_coordinator<S: CircuitSession>(
    circuit_path: &PathBuf,
    mut session: S,
) -> HandlerOutcome {
    let mut reader = ReaderV5c::open(circuit_path).unwrap();
    let total_gates = reader.header().total_gates();
    let mut block_idx: usize = 0;

    while let Some(chunk_result) = reader.next_blocks_chunk().await.transpose() {
        let reader_chunk = chunk_result.unwrap();
        let owned = convert_chunk(&reader_chunk, total_gates, &mut block_idx);
        session.process_chunk(&Arc::new(owned)).await.unwrap();
    }
    Box::new(session).finish().await
}

/// Copied from scheduler/src/garbling
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

/// Copied from scheduler/src/garbling
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

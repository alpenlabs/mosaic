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
            Input as EvalInput, StateRead as EvalStateRead, Step as EvalStep,
        },
        garbler::{
            DepositStep as GarbDepositStep, GarblerDepositInitData, GarblerInitData,
            GarblerTrackedActionTypes, Input as GarbInput, StateRead as GarblerStateRead,
            Step as GarbStep,
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
use mosaic_storage_kvstore::btreemap::BTreeMapStorageProvider;
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

    pub(crate) async fn handle_receive_table_transfer_request(
        net_client: &NetClient,
    ) -> Vec<GarbInputs> {
        let mut collections = vec![];
        for _ in 0..N_EVAL_CIRCUITS {
            const CI_TIMEOUT: Duration = Duration::from_secs(300);
            let request = match tokio::time::timeout(CI_TIMEOUT, net_client.recv()).await {
                Ok(Ok(request)) => request,
                Ok(Err(err)) => panic!("recv failed: {:?}", err),
                Err(_) => {
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::TableTransferRequest(msg) => GarbInputs::RecvTableTransferRequest(msg.clone()),
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
                    panic!("recv timed out after {CI_TIMEOUT:?}");
                }
            };
            let header = match &request.message {
                Msg::TableTransferReceipt(msg) => GarbInputs::RecvTableTransferReceipt(msg.clone()),
                _ => panic!(),
            };
            request.ack().await.expect("ack failed");
            collections.push(header);
        }
        collections
    }
}

async fn handle_init_garbler<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    eval_peer_id: &PeerId,
    garb_seed: Seed,
    setup_inputs: SetupInputs,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(eval_peer_id)
        .await
        .unwrap();
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(GarbInput::Init(GarblerInitData {
            seed: garb_seed,
            setup_inputs,
        })),
        garb_actions,
    )
    .await
    .unwrap();
}

async fn handle_init_evaluator<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    garbler_peer_id: PeerId,
    eval_seed: Seed,
    setup_inputs: SetupInputs,
) {
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(&garbler_peer_id)
        .await
        .unwrap();
    evaluator::EvaluatorSM::stf(
        &mut eval_state,
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

async fn handle_garbler_prepares_commit_msg<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    eval_peer_id: PeerId,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&garbler_peer_id)
        .await
        .unwrap();
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
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    // returns Action::GenerateShares
    assert_eq!(garb_actions.len(), N_CIRCUITS + 1);

    let mut results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }

    assert_eq!(garb_actions.len(), N_CIRCUITS); // [Action::GenerateTableCommitment; N_CIRCUITS]

    let mut results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    assert_eq!(results.len(), N_CIRCUITS); // GarblerActionResult::TableCommitmentGenerated

    while let Some(completion) = results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); // Action::SendCommitMsgHeader + Action::SendCommitMsgChunk
}

async fn handle_garbler_transfers_commit_msg<SP: StorageProvider + StorageProviderMut>(
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    net_client_evaluator: NetClient,
) -> (Vec<EvalInput>, Vec<ActionCompletion>) {
    // Make evaluator listen
    let encl = net_client_evaluator.clone();
    let commit_msg_listener = tokio::spawn(async move { handle_receive_commit_msg(encl).await });

    println!("send commit msg");
    // sends commit msg header then chunks; evaluator should have been listening
    let garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;

    println!("receive commit msg");
    // Evaluator reads
    let eval_inputs = commit_msg_listener.await.unwrap();
    assert_eq!(eval_inputs.len(), 1 + N_INPUT_WIRES);

    (eval_inputs, garb_results)
}

async fn handle_garbler_waits_for_challenge<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: &PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(eval_peer_id)
        .await
        .unwrap();
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Step: WaitForChallenge; No Action // network ack
}

async fn handle_evaluator_prepares_challenge<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_inputs: &mut Vec<EvalInput>,
) {
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(&mut eval_state, fasm::Input::Normal(ei), eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // SendChallenge
}

async fn handle_evaluator_transfers_challenge_msg<SP: StorageProvider + StorageProviderMut>(
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: PeerId,
    net_client_garbler: NetClient,
) -> (GarbInput, Vec<ActionCompletion>) {
    let ncl = net_client_garbler;
    let challenge_msg_listener = tokio::spawn(async move { handle_receive_challenge(&ncl).await });

    // Evaluator sends challenge over network
    println!("mock_dispatch_evaluator; send_challenge");
    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;

    let garb_inputs = challenge_msg_listener.await.unwrap(); // ChallengeMsg
    (garb_inputs, eval_results)
}

async fn handle_evaluator_waits_for_challenge_response<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_results: &mut Vec<ActionCompletion>,
) {
    // eval's tx is acked
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0); // Challenge was acked; step WaitingForChallengeResponse
}

async fn handle_garbler_prepares_challenge_response<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_inputs: GarbInput,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(garb_inputs),
        garb_actions,
    )
    .await
    .unwrap();
    assert_eq!(garb_actions.len(), 1 + N_OPEN_CIRCUITS); // Challenge Response Header + Challenge Response Chunks (one chunk for each circuit)
}

async fn handle_garbler_transfers_challenge_response<SP: StorageProvider + StorageProviderMut>(
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    net_client_evaluator: NetClient,
) -> (Vec<EvalInput>, Vec<ActionCompletion>) {
    let encl = net_client_evaluator.clone();
    let challenge_response_listener =
        tokio::spawn(async move { handle_receive_challenge_response(encl).await });

    let garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;

    let eval_inputs = challenge_response_listener.await.unwrap();

    (eval_inputs, garb_results)
}

async fn handle_garbler_prepares_for_table_transfer<SP: StorageProviderMut + StorageProvider>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    // Garbler transitions to TransferringGarblingTables but emits no actions —
    // it waits for explicit TableTransferRequest messages from the evaluator.
    assert_eq!(garb_actions.len(), 0);
}

/// Evaluator sends TableTransferRequest messages over the network; garbler receives them.
///
/// Returns: (garbler inputs from received requests, evaluator action results from sending)
async fn handle_evaluator_sends_table_requests<SP: StorageProvider + StorageProviderMut>(
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: PeerId,
    net_client_garbler: NetClient,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    // Separate request actions from receive actions.
    // eval_actions contains interleaved [SendTableTransferRequest, ReceiveGarblingTable] pairs.
    let mut request_actions = vec![];
    let mut receive_actions = vec![];
    while let Some(action) = eval_actions.pop() {
        match &action {
            fasm::actions::Action::Tracked(tracked) => match tracked.action() {
                EvaluatorAction::SendTableTransferRequest(_) => request_actions.push(action),
                EvaluatorAction::ReceiveGarblingTable(_) => receive_actions.push(action),
                other => panic!("unexpected action in table transfer phase: {:?}", other),
            },
            _ => panic!("expected tracked action"),
        }
    }
    assert_eq!(request_actions.len(), N_EVAL_CIRCUITS);
    assert_eq!(receive_actions.len(), N_EVAL_CIRCUITS);

    // Put receive actions back — they'll be dispatched during the actual table transfer.
    *eval_actions = receive_actions;

    // Garbler listens for table transfer requests.
    let ncl = net_client_garbler.clone();
    let rx = tokio::spawn(async move {
        use crate::tests::netcl::handle_receive_table_transfer_request;
        handle_receive_table_transfer_request(&ncl).await
    });

    // Evaluator sends table transfer requests over the network.
    let eval_results =
        mock_dispatch_evaluator(&mut request_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_EVAL_CIRCUITS); // TableTransferRequestAcked

    // Garbler received all requests.
    let garb_inputs = rx.await.unwrap();
    assert_eq!(garb_inputs.len(), N_EVAL_CIRCUITS);

    (garb_inputs, eval_results)
}

/// Garbler processes received TableTransferRequest inputs, emitting TransferGarblingTable actions.
async fn handle_garbler_processes_table_requests<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_inputs: &mut Vec<GarbInput>,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    while let Some(input) = garb_inputs.pop() {
        garbler::GarblerSM::stf(&mut garb_state, fasm::Input::Normal(input), garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), N_EVAL_CIRCUITS); // Action::TransferGarblingTable per request
}

/// Evaluator consumes TableTransferRequestAcked results (no-op for state machine).
async fn handle_evaluator_consumes_request_ack<SP: StorageProvider + StorageProviderMut>(
    eval_results: &mut Vec<ActionCompletion>,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
) {
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    let prev_len = eval_actions.len();
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    // TableTransferRequestAcked is a no-op — no new actions emitted.
    assert_eq!(eval_actions.len(), prev_len);
}

async fn handle_evaluator_processes_challenge_response<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_inputs: &mut Vec<EvalInput>,
    garbler_peer_id: PeerId,
) {
    // Evaluator receives challenge response
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(&garbler_peer_id)
        .await
        .unwrap();
    while let Some(ei) = eval_inputs.pop() {
        evaluator::EvaluatorSM::stf(&mut eval_state, fasm::Input::Normal(ei), eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 1); // Step::VerifyingOpenedInputShares; Action::VerifyOpenedInputShares

    println!("mock_dispatch_evaluator; verify shares");
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    println!("shares verified");
    assert_eq!(eval_results.len(), 1); // ActionResult::VerifyOpenedInputSharesResult
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_OPEN_CIRCUITS); // Action::GenerateTableCommitment(index, seed), Step::VerifyingTableCommitments

    println!("mock_dispatch_evaluator; generate table commitment");
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_OPEN_CIRCUITS); // ActionResult::TableCommitmentGenerated
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    // Step::ReceivingGarblingTables emits SendTableTransferRequest + ReceiveGarblingTable per
    // circuit.
    assert_eq!(eval_actions.len(), 2 * N_EVAL_CIRCUITS);
}

async fn handle_evaluator_processes_table<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_results: &mut Vec<ActionCompletion>,
) {
    // process receipt
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Step::SetupComplete, Action::SendTableTransferReceipt
    assert_eq!(
        eval_state.get_root_state().await.unwrap().unwrap().step,
        EvalStep::SetupComplete
    );
}

async fn handle_garbler_waits_for_receipt<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_results: &mut Vec<ActionCompletion>,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // step: waiting for table transfer receipt
}

async fn handle_evaluator_transfers_receipt<SP: StorageProvider + StorageProviderMut>(
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: PeerId,
    net_client_garbler: NetClient,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    // garbler listens for table transfer receipt
    let ncl = net_client_garbler.clone();
    let tx = tokio::spawn(async move {
        use crate::tests::netcl::handle_receive_table_transfer_receipt;
        handle_receive_table_transfer_receipt(&ncl).await
    });

    // evaluator sends table receipt
    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_EVAL_CIRCUITS); // ActionResult::TableTransferReceiptAcked
    // garbler received table transfer receipts
    let garb_inputs = tx.await.unwrap();
    assert_eq!(garb_inputs.len(), N_EVAL_CIRCUITS);
    (garb_inputs, eval_results)
}

async fn handle_evaluator_consumes_receipt_ack<SP: StorageProvider + StorageProviderMut>(
    eval_results: &mut Vec<ActionCompletion>,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
) {
    // Stf ignores ack as state has been transitioned to SetupComplete already
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);
    assert_eq!(
        eval_state.get_root_state().await.unwrap().unwrap().step,
        EvalStep::SetupComplete
    );
}

async fn handle_garbler_consumes_receipt_ack<SP: StorageProvider + StorageProviderMut>(
    garb_inputs: &mut Vec<GarbInput>,
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    while let Some(input) = garb_inputs.pop() {
        garbler::GarblerSM::stf(&mut garb_state, fasm::Input::Normal(input), garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // setup complete
    assert_eq!(
        garb_state.get_root_state().await.unwrap().unwrap().step,
        GarbStep::SetupComplete
    );
}

async fn handle_garbler_inits_deposit<SP: StorageProvider + StorageProviderMut>(
    sighashes: Sighashes,
    deposit_inputs: DepositInputs,
    eval_pubkey: PubKey,
    deposit_id: DepositId,
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    let deposit_input: GarblerDepositInitData = GarblerDepositInitData {
        pk: eval_pubkey,
        sighashes: HeapArray::from_vec(sighashes.to_vec()),
        deposit_inputs,
    };
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(GarbInput::DepositInit(deposit_id, deposit_input)),
        garb_actions,
    )
    .await
    .unwrap();
    assert_eq!(garb_actions.len(), 0);
}

async fn handle_evaluator_inits_deposit<SP: StorageProvider + StorageProviderMut>(
    sighashes: Sighashes,
    eval_sk: SecretKey,
    deposit_inputs: DepositInputs,
    deposit_id: DepositId,
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
) {
    let deposit_input: EvaluatorDepositInitData = EvaluatorDepositInitData {
        sk: eval_sk,
        sighashes: HeapArray::from_vec(sighashes.to_vec()),
        deposit_inputs,
    };
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();

    evaluator::EvaluatorSM::stf(
        &mut eval_state,
        fasm::Input::Normal(EvalInput::DepositInit(deposit_id, deposit_input)),
        eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), 1 + N_ADAPTOR_MSG_CHUNKS); // Action::GenerateDepositAdaptors + [Action::GenerateWithdrawalAdaptorsChunk]

    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, garbler_peer_id).await;
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), N_DEPOSIT_INPUT_WIRES); //  Action::DepositSendAdaptorMsgChunk
}

async fn handle_evaluator_sends_adaptors<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    garbler_peer_id: PeerId,
    net_client_garbler: NetClient,
) -> (Vec<GarbInput>, Vec<ActionCompletion>) {
    println!("handle_receive_adaptor_msg_chunks");
    // adaptor chunks listener
    let ncl = net_client_garbler.clone();
    let challenge_msg_listener =
        tokio::spawn(async move { handle_receive_adaptor_msg_chunks(&ncl, deposit_id).await });

    // send adaptor msg chunks
    let eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, &garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_DEPOSIT_INPUT_WIRES); // ActionResult::DepositAdaptorChunkSent

    // garbler listens for adaptors
    let garb_inputs = challenge_msg_listener.await.unwrap();
    assert_eq!(garb_inputs.len(), N_DEPOSIT_INPUT_WIRES);

    (garb_inputs, eval_results)
}

async fn handle_evaluator_is_deposit_ready<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    eval_results: &mut Vec<ActionCompletion>,
) {
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);

    assert_eq!(
        eval_state
            .get_deposit(&deposit_id)
            .await
            .unwrap()
            .unwrap()
            .step,
        EvalDepositStep::DepositReady
    );
    // assert evaluator is deposit ready
}

async fn handle_garbler_verifies_adaptors<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    let mut garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await;
    // results ActionResult::DepositAdaptorVerificationResult
    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0);
    assert_eq!(
        garb_state
            .get_deposit(&deposit_id)
            .await
            .unwrap()
            .unwrap()
            .step,
        GarbDepositStep::DepositReady
    );
    // garbler is deposit ready
    println!("garbler is deposit ready");
    // garbler is deposit ready
    println!("garbler is deposit ready");
}

async fn handle_garbler_starts_adaptor_verification_job<
    SP: StorageProvider + StorageProviderMut,
>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    garb_inputs: &mut Vec<GarbInput>,
) {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    while let Some(ei) = garb_inputs.pop() {
        garbler::GarblerSM::stf(&mut garb_state, fasm::Input::Normal(ei), garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 1); // DepositStep::VerifyingAdaptors
}

async fn handle_garbler_completes_signatures<SP: StorageProvider + StorageProviderMut>(
    garbler_exec: &mut MosaicExecutor<SP, S3TableStore>,
    eval_peer_id: PeerId,
    garb_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
    withdrawal_input: WithdrawalInputs,
) -> CompletedSignatures {
    let mut garb_state = garbler_exec
        .storage
        .garbler_state_mut(&eval_peer_id)
        .await
        .unwrap();
    garbler::GarblerSM::stf(
        &mut garb_state,
        fasm::Input::Normal(GarbInput::DisputedWithdrawal(deposit_id, withdrawal_input)),
        garb_actions,
    )
    .await
    .unwrap();
    assert_eq!(garb_actions.len(), 1); // Action::CompleteAdaptorSignatures

    let mut garb_results = mock_dispatch_garbler(garb_actions, garbler_exec, &eval_peer_id).await; // ActionResult::AdaptorSignaturesCompleted
    assert_eq!(garb_results.len(), 1);

    while let Some(completion) = garb_results.pop() {
        let (action_id, action_result) = completion.as_garbler().unwrap();
        let tracked_input: fasm::Input<GarblerTrackedActionTypes, GarbInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        garbler::GarblerSM::stf(&mut garb_state, tracked_input, garb_actions)
            .await
            .unwrap();
    }
    assert_eq!(garb_actions.len(), 0); // Setup Consumed
    assert_eq!(
        garb_state.get_root_state().await.unwrap().unwrap().step,
        GarbStep::SetupConsumed { deposit_id }
    );

    garb_state
        .get_completed_signatures(&deposit_id)
        .await
        .unwrap()
        .unwrap()
}

async fn handle_evaluator_finds_fault_secret<SP: StorageProvider + StorageProviderMut>(
    eval_exec: &mut MosaicExecutor<SP, S3TableStore>,
    garbler_peer_id: &PeerId,
    on_chain_sigs: CompletedSignatures,
    eval_actions: &mut Vec<
        actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    deposit_id: DepositId,
) {
    let mut eval_state = eval_exec
        .storage
        .evaluator_state_mut(garbler_peer_id)
        .await
        .unwrap();
    let eval_disputed_withdrawal = EvaluatorDisputedWithdrawalData {
        signatures: on_chain_sigs.clone(),
    };
    evaluator::EvaluatorSM::stf(
        &mut eval_state,
        fasm::Input::Normal(EvalInput::DisputedWithdrawal(
            deposit_id,
            eval_disputed_withdrawal,
        )),
        eval_actions,
    )
    .await
    .unwrap();
    assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Action::EvaluateGarblingTable

    println!("evaluate garbling table");
    let mut eval_results = mock_dispatch_evaluator(eval_actions, eval_exec, garbler_peer_id).await;
    assert_eq!(eval_results.len(), N_EVAL_CIRCUITS);
    while let Some(completion) = eval_results.pop() {
        let (action_id, action_result) = completion.as_evaluator().unwrap();
        let tracked_input: fasm::Input<EvaluatorTrackedActionTypes, EvalInput> =
            fasm::Input::TrackedActionCompleted {
                id: action_id.clone(),
                result: action_result.clone(),
            };
        evaluator::EvaluatorSM::stf(&mut eval_state, tracked_input, eval_actions)
            .await
            .unwrap();
    }
    assert_eq!(eval_actions.len(), 0);
}

use fasm::StateMachine;
use mosaic_storage_api::{StorageProvider, StorageProviderMut};

#[tokio::test]
// OPTIONAL steps to generate v5c file yourself:
// 1. Clone g16 repo and switch to branch test/simple_circuit_postaudit_smallest
//   test/simple_circuit_postaudit_smallest branch generates sample ckt meant for test purposes
//   only. The binary circuit's function is as follows:
//   combine_all_wires <- AND(all_wires) // we use up all input wires
//   wire_a <-XOR(combine_all_wires, combine_all_wires) // wire_a is now always zero
//   output_wire <-  wire_a  OR deposit_id_lsb // result is dependent only on deposit_id_lsb
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
        println!("ITERATION {}", iter + 1);
        let mut garb_rng = ChaCha20Rng::seed_from_u64(42);
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
        let (net_client_garbler, garbler_peer_id, net_client_evaluator, eval_peer_id) =
            (peer_a.client, peer_a.peer_id, peer_b.client, peer_b.peer_id);

        let garb_seed = rand_byte_array(&mut garb_rng).into();
        let eval_seed = rand_byte_array(&mut eval_rng).into();

        // Run Garbler STF
        let garb_storage = BTreeMapStorageProvider::new();
        let mut garbler_exec = MosaicExecutor::new(
            net_client_garbler.clone(),
            garb_storage.clone(),
            ts,
            circuit_path.clone(),
        );

        let prefix = "evaluating-tables";
        let local = LocalFileSystem::new_with_prefix(temp_dir.clone()).unwrap();
        let ts = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);

        let eval_storage = BTreeMapStorageProvider::new();
        let mut eval_exec = MosaicExecutor::new(
            net_client_evaluator.clone(),
            eval_storage.clone(),
            ts,
            circuit_path.clone(),
        );

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

        handle_init_garbler(
            &mut garbler_exec,
            &mut garb_actions,
            &eval_peer_id,
            garb_seed,
            setup_inputs,
        )
        .await;

        handle_init_evaluator(
            &mut eval_exec,
            &mut eval_actions,
            garbler_peer_id,
            eval_seed,
            setup_inputs,
        )
        .await;

        println!("garbler prepares commit msg");
        handle_garbler_prepares_commit_msg(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            eval_peer_id,
        )
        .await;

        println!("spawn commit msg listener");
        let (mut eval_inputs, mut garb_results) = handle_garbler_transfers_commit_msg(
            &mut garb_actions,
            &mut garbler_exec,
            eval_peer_id,
            net_client_evaluator.clone(),
        )
        .await;
        println!("commit msg prepared");

        handle_garbler_waits_for_challenge(
            &mut garbler_exec,
            &eval_peer_id,
            &mut garb_actions,
            &mut garb_results,
        )
        .await;

        handle_evaluator_prepares_challenge(
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
            &mut eval_inputs,
        )
        .await;

        println!("Evaluator Wants to Send Challenge; Garbler should be listening");

        let (garb_inputs, mut eval_results) = handle_evaluator_transfers_challenge_msg(
            &mut eval_actions,
            &mut eval_exec,
            garbler_peer_id,
            net_client_garbler.clone(),
        )
        .await;

        handle_evaluator_waits_for_challenge_response(
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
            &mut eval_results,
        )
        .await;

        handle_garbler_prepares_challenge_response(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            garb_inputs,
        )
        .await;

        let (mut eval_inputs, mut garb_results) = handle_garbler_transfers_challenge_response(
            &mut garb_actions,
            &mut garbler_exec,
            eval_peer_id,
            net_client_evaluator.clone(),
        )
        .await;

        handle_garbler_prepares_for_table_transfer(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            &mut garb_results,
        )
        .await;

        handle_evaluator_processes_challenge_response(
            &mut eval_exec,
            &mut eval_actions,
            &mut eval_inputs,
            garbler_peer_id,
        )
        .await;

        // =====================================================================
        // Table Transfer (pull-based):
        //   1. Evaluator sends TableTransferRequest, garbler receives them
        //   2. Evaluator consumes request acks (no-op)
        //   3. Garbler processes requests → emits TransferGarblingTable actions
        //   4. Garbler transfers tables + evaluator receives tables (concurrent)
        //   5. Garbler consumes transfer results (informational)
        //   6. Evaluator processes received tables → emits SendTableTransferReceipt
        //   7. Evaluator sends receipts, garbler receives them
        //   8. Evaluator consumes receipt acks (no-op)
        //   9. Garbler processes receipts → transitions to SetupComplete
        // =====================================================================

        // Step 1: Evaluator sends table transfer requests; garbler receives them.
        let (mut garb_inputs, mut eval_results) = handle_evaluator_sends_table_requests(
            &mut eval_actions,
            &mut eval_exec,
            garbler_peer_id,
            net_client_garbler.clone(),
        )
        .await;

        // Step 2: Evaluator consumes TableTransferRequestAcked (no-op).
        handle_evaluator_consumes_request_ack(
            &mut eval_results,
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
        )
        .await;

        // Step 3: Garbler processes requests → emits TransferGarblingTable actions.
        let mut garb_actions = vec![];
        handle_garbler_processes_table_requests(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            &mut garb_inputs,
        )
        .await;

        // Step 4: Garbler transfers tables + evaluator receives tables (concurrent).
        let (mut garb_results, mut eval_results) = {
            let tx = tokio::spawn(async move {
                mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await
            });
            let eval_results =
                mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
            assert_eq!(eval_results.len(), N_EVAL_CIRCUITS); // GarblingTableReceived
            let garb_results = tx.await.unwrap();
            assert_eq!(garb_results.len(), N_EVAL_CIRCUITS); // GarblingTableTransferred
            (garb_results, eval_results)
        };

        // Step 5: Garbler consumes transfer results (informational, no state change).
        let mut garb_actions = vec![];
        let prefix = "garbling-tables";
        let local = LocalFileSystem::new_with_prefix(temp_dir.clone()).unwrap();
        let ts = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);
        let mut garbler_exec = MosaicExecutor::new(
            net_client_garbler.clone(),
            garb_storage,
            ts,
            circuit_path.clone(),
        );
        handle_garbler_waits_for_receipt(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            &mut garb_results,
        )
        .await;

        // Step 6: Evaluator processes received tables → emits SendTableTransferReceipt.
        handle_evaluator_processes_table(
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
            &mut eval_results,
        )
        .await;

        // Step 7: Evaluator sends receipts; garbler receives them.
        let (mut garb_inputs, mut eval_results) = handle_evaluator_transfers_receipt(
            &mut eval_actions,
            &mut eval_exec,
            garbler_peer_id,
            net_client_garbler.clone(),
        )
        .await;

        // Step 8: Evaluator consumes TableTransferReceiptAcked (no-op).
        handle_evaluator_consumes_receipt_ack(
            &mut eval_results,
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
        )
        .await;

        // Step 9: Garbler processes receipts → transitions to SetupComplete.
        handle_garbler_consumes_receipt_ack(
            &mut garb_inputs,
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
        )
        .await;

        println!("setup complete");

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
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
        )
        .await;

        handle_evaluator_inits_deposit(
            HeapArray::from_vec(sighashes.to_vec()),
            eval_keypair.secret_key(),
            deposit_inputs,
            deposit_id,
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
        )
        .await;

        let (mut garb_inputs, mut eval_results) = handle_evaluator_sends_adaptors(
            &mut eval_exec,
            &mut eval_actions,
            deposit_id,
            garbler_peer_id,
            net_client_garbler.clone(),
        )
        .await;

        handle_evaluator_is_deposit_ready(
            &mut eval_exec,
            &garbler_peer_id,
            &mut eval_actions,
            deposit_id,
            &mut eval_results,
        )
        .await;

        handle_garbler_starts_adaptor_verification_job(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            &mut garb_inputs,
        )
        .await;

        handle_garbler_verifies_adaptors(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            deposit_id,
        )
        .await;

        println!("Withdrawal Stage");
        // STARTING WITHDRAWAL STAGE for Disputed Withdrawal

        println!("Withdrawal Stage");
        // STARTING WITHDRAWAL STAGE for Disputed Withdrawal

        let on_chain_sigs = handle_garbler_completes_signatures(
            &mut garbler_exec,
            eval_peer_id,
            &mut garb_actions,
            deposit_id,
            withdrawal_input,
        )
        .await;

        handle_evaluator_finds_fault_secret(
            &mut eval_exec,
            &garbler_peer_id,
            on_chain_sigs,
            &mut eval_actions,
            deposit_id,
        )
        .await;

        let eval_state = eval_storage
            .evaluator_state(&garbler_peer_id)
            .await
            .unwrap();
        match eval_state.get_root_state().await.unwrap().unwrap().step {
            EvalStep::SetupConsumed {
                deposit_id: deposit_idx,
                slash,
            } => {
                assert_eq!(deposit_id, deposit_idx);
                assert_eq!(slash.is_some(), reveals_secret);
                if reveals_secret {
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

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};

async fn mock_dispatch_garbler<SP: StorageProvider + StorageProviderMut>(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            GarblerTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<SP, S3TableStore>,
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
async fn mock_dispatch_evaluator<SP: StorageProvider + StorageProviderMut>(
    actions: &mut Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            EvaluatorTrackedActionTypes,
        >,
    >,
    exec: &MosaicExecutor<SP, S3TableStore>,
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
                    EvaluatorAction::SendTableTransferRequest(msg) => {
                        exec.send_table_transfer_request(peer_id, msg).await
                    }
                    EvaluatorAction::SendTableTransferReceipt(msg) => {
                        exec.send_table_transfer_receipt(peer_id, msg).await
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

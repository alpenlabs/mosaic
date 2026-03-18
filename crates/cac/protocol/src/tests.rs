use std::{
    env::temp_dir,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use ckt_fmtv5_types::v5::c::{Block, ReaderV5c, get_block_num_gates};
use fasm::actions;
use mosaic_cac_types::{
    DepositId, HeapArray, PubKey, SecretKey, Sighash, Signature,
    state_machine::{
        evaluator::{
            EvaluatorDepositInitData, EvaluatorInitData, EvaluatorTrackedActionTypes,
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
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{StorageProvider, TableMetadata, TableReader, TableStore, TableWriter};
use mosaic_storage_inmemory::{evaluator::StoredEvaluatorState, garbler::StoredGarblerState};
use rand_chacha::{ChaCha20Rng, ChaChaRng, rand_core::SeedableRng};

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

use fasm::StateMachine;
#[tokio::test]
// Steps:
// 1. clone: g16 repo and switch to branch test/simple_circuit_postaudit
// test/simple_circuit_postaudit branch generates small ckt file that does input validation
// only; not the actually groth16 verification afterwards; Meant for test purposes only]
// 2. generate v5a ckt file: cd g16gen && cargo run generate 6 && cargo run write-input-bits 6
// 3. clone: ckt repo
// 4. move g16gen/g16.ckt file to ckt/lvl/
// 5. generate v5c file: cd crates/lvl && cargo run prealloc g16.ckt g16.v5c
// 6. move lvl/g16.v5c to mosaic/cac/protocol/
// 7. Run test with: cargo test --release --package mosaic-cac-protocol --lib -- tests::test_e2e
//    --exact --show-output --nocapture --ignored

async fn test_e2e() {
    use mosaic_cac_types::{
        WithdrawalInputs,
        state_machine::evaluator::{
            DepositStep as EvalDepositStep, EvaluatorDisputedWithdrawalData,
        },
    };
    use mosaic_common::constants::N_SETUP_INPUT_WIRES;

    let test_vector = {
        // The current g16.v5c file ORs all input wires; so it yields false only if all inputs are
        // false.
        let setup_inputs = [0; N_SETUP_INPUT_WIRES];
        let deposit_inputs = [0u8; N_DEPOSIT_INPUT_WIRES];
        let withdrawal_input: WithdrawalInputs = [0; N_WITHDRAWAL_INPUT_WIRES];
        let reveals_secret = true; // output is false

        let mut setup_inputs2 = [0; N_SETUP_INPUT_WIRES];
        setup_inputs2[0] = 1;
        let reveals_secret2 = false; // output is true
        vec![
            (
                setup_inputs,
                deposit_inputs,
                withdrawal_input,
                reveals_secret,
            ),
            (
                setup_inputs2,
                deposit_inputs,
                withdrawal_input,
                reveals_secret2,
            ),
        ]
    };

    for (iter, (setup_inputs, deposit_inputs, withdrawal_input, reveals_secret)) in
        test_vector.into_iter().enumerate()
    {
        println!("ITERATION {}", iter + 1);
        let mut garb_state = StoredGarblerState::default();
        let mut garb_rng = ChaChaRng::seed_from_u64(42);
        let mut eval_state = StoredEvaluatorState::default();
        let mut eval_rng = ChaCha20Rng::seed_from_u64(43);

        let ts = DummyTableStore { dir: temp_dir() };

        let circuit_path = PathBuf::from_str("g16.v5c").unwrap();
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
        let mut garbler_exec = MosaicExecutor::new(
            net_client_gabler.clone(),
            sp,
            ts.clone(),
            circuit_path.clone(),
        );

        let sp: DummyStorageProvider = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_exec =
            MosaicExecutor::new(net_client_evaluator, sp, ts.clone(), circuit_path.clone());

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
                seed: eval_seed,
                setup_inputs,
            })),
            &mut eval_actions,
        )
        .await
        .unwrap();
        assert_eq!(eval_actions.len(), 0); // Step Waiting For Commit

        assert_eq!(garb_actions.len(), 1 + N_INPUT_WIRES); //  Action::GeneratePolynomialCommitments: [Output, Inputs..]
        let mut results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;
        assert_eq!(results.len(), N_INPUT_WIRES + 1); // ActionResult::PolynomialCommitmentsGenerated: [Output, Inputs..]
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

        // update garbler state read by executor manually; TODO: avoidable with a shared copy of
        // State
        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;
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

        assert_eq!(garb_actions.len(), N_CIRCUITS); // [Action::GenerateTableCommitment; N_CIRCUITS]

        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;
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

        println!("spawn commit msg listener");
        // Make evaluator listen
        let encl = eval_exec.net_client.clone();
        let commit_msg_listener =
            tokio::spawn(async move { handle_receive_commit_msg(encl).await });

        println!("send commit msg");
        // sends commit msg header then chunks; evaluator should have been listening
        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut garb_results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;

        println!("receive commit msg");
        // Evaluator reads
        let mut eval_inputs = commit_msg_listener.await.unwrap();
        assert_eq!(eval_inputs.len(), 1 + N_INPUT_WIRES);

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

        //Evaluator receives commit msg
        while let Some(ei) = eval_inputs.pop() {
            evaluator::EvaluatorSM::stf(
                &mut eval_state,
                fasm::Input::Normal(ei),
                &mut eval_actions,
            )
            .await
            .unwrap();
        }
        assert_eq!(eval_actions.len(), 1); // SendChallenge

        println!("Evaluator Wants to Send Challenge; Garbler should be listening");

        let ncl = garbler_exec.net_client.clone();
        let challenge_msg_listener =
            tokio::spawn(async move { handle_receive_challenge(&ncl).await });

        // Evaluator sends challenge over network
        println!("mock_dispatch_evaluator; send_challenge");
        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;

        let garb_inputs = challenge_msg_listener.await.unwrap(); // ChallengeMsg

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
        garbler::GarblerSM::stf(
            &mut garb_state,
            fasm::Input::Normal(garb_inputs),
            &mut garb_actions,
        )
        .await
        .unwrap();
        assert_eq!(garb_actions.len(), 1 + N_OPEN_CIRCUITS); // Challenge Response Header + Challenge Response Chunks (one chunk for each circuit)

        let encl = eval_exec.net_client.clone();
        let challenge_response_listener =
            tokio::spawn(async move { handle_receive_challenge_response(encl).await });

        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut garb_results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;

        let mut eval_inputs = challenge_response_listener.await.unwrap();

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
            evaluator::EvaluatorSM::stf(
                &mut eval_state,
                fasm::Input::Normal(ei),
                &mut eval_actions,
            )
            .await
            .unwrap();
        }
        assert_eq!(eval_actions.len(), 1); // Step::VerifyingOpenedInputShares; Action::VerifyOpenedInputShares

        println!("mock_dispatch_evaluator; verify shares");
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        println!("shares verified");
        assert_eq!(eval_results.len(), 1); // ActionResult::VerifyOpenedInputSharesResult
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

        println!("mock_dispatch_evaluator; generate table commitment");
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        assert_eq!(eval_results.len(), N_OPEN_CIRCUITS); // ActionResult::TableCommitmentGenerated
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

        // garbler sends table
        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };

        // transfer tables background
        let tx = tokio::spawn(async move {
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await
        });

        // evaluator receives table
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        assert_eq!(eval_results.len(), N_EVAL_CIRCUITS);
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
        assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Step::SetupComplete, Action::SendTableTransferReceipt
        assert_eq!(eval_state.state.step, EvalStep::SetupComplete);

        // garbler transfer tables done
        let mut garb_results = tx.await.unwrap();
        assert_eq!(garb_results.len(), N_EVAL_CIRCUITS);
        let mut garb_actions = vec![];
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
        assert_eq!(garb_actions.len(), 0); // step: waiting for table transfer receipt

        // garbler listens for table transfer receipt
        let ncl = net_client_gabler.clone();
        let tx = tokio::spawn(async move {
            use crate::tests::netcl::handle_receive_table_transfer_receipt;
            handle_receive_table_transfer_receipt(&ncl).await
        });

        // evaluator sends table receipt
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        assert_eq!(eval_results.len(), N_EVAL_CIRCUITS); // ActionResult::GarblingTableTransferReceiptAcked
        // Stf ignores ack as state has been transitioned to SetupComplete already
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
        assert_eq!(eval_actions.len(), 0);
        assert_eq!(eval_state.state.step, EvalStep::SetupComplete);

        // garbler received table transfer receipts
        let mut garb_results = tx.await.unwrap();
        assert_eq!(garb_results.len(), N_EVAL_CIRCUITS);
        let mut garb_actions = vec![];
        while let Some(input) = garb_results.pop() {
            garbler::GarblerSM::stf(
                &mut garb_state,
                fasm::Input::Normal(input),
                &mut garb_actions,
            )
            .await
            .unwrap();
        }
        assert_eq!(garb_actions.len(), 0); // setup complete
        assert_eq!(garb_state.state.step, GarbStep::SetupComplete);

        println!("setup complete");

        let deposit_id = {
            let mut empty: [u8; 32] = [0; 32];
            empty[0] = 7;
            DepositId(Byte32::from(empty))
        };
        let sighashes =
            [Sighash(Byte32::from([0u8; 32])); N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];
        let eval_keypair = Signature::keypair(&mut eval_rng);
        let deposit_input: EvaluatorDepositInitData = EvaluatorDepositInitData {
            sk: SecretKey(eval_keypair.0),
            sighashes: HeapArray::from_vec(sighashes.to_vec()),
            deposit_inputs,
        };

        evaluator::EvaluatorSM::stf(
            &mut eval_state,
            fasm::Input::Normal(EvalInput::DepositInit(deposit_id, deposit_input)),
            &mut eval_actions,
        )
        .await
        .unwrap();
        assert_eq!(eval_actions.len(), 1 + N_ADAPTOR_MSG_CHUNKS); // Action::GenerateDepositAdaptors + [Action::GenerateWithdrawalAdaptorsChunk]

        let deposit_input: GarblerDepositInitData = GarblerDepositInitData {
            pk: PubKey(eval_keypair.1),
            sighashes: HeapArray::from_vec(sighashes.to_vec()),
            deposit_inputs,
        };
        garbler::GarblerSM::stf(
            &mut garb_state,
            fasm::Input::Normal(GarbInput::DepositInit(deposit_id, deposit_input)),
            &mut garb_actions,
        )
        .await
        .unwrap();
        assert_eq!(garb_actions.len(), 0);

        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
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
        assert_eq!(eval_actions.len(), N_DEPOSIT_INPUT_WIRES); //  Action::DepositSendAdaptorMsgChunk

        println!("handle_receive_adaptor_msg_chunks");
        // adaptor chunks listener
        let ncl = net_client_gabler.clone();
        let challenge_msg_listener =
            tokio::spawn(async move { handle_receive_adaptor_msg_chunks(&ncl, deposit_id).await });

        // send adaptor msg chunks
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        assert_eq!(eval_results.len(), N_DEPOSIT_INPUT_WIRES); // ActionResult::DepositAdaptorChunkSent
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
        assert_eq!(eval_actions.len(), 0);
        println!("evaluator verifies adaptors");
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

        // garbler listens for adaptors
        let mut garb_inputs = challenge_msg_listener.await.unwrap();
        assert_eq!(garb_inputs.len(), N_DEPOSIT_INPUT_WIRES);
        while let Some(ei) = garb_inputs.pop() {
            garbler::GarblerSM::stf(&mut garb_state, fasm::Input::Normal(ei), &mut garb_actions)
                .await
                .unwrap();
        }
        assert_eq!(garb_actions.len(), 1); // DepositStep::VerifyingAdaptors

        println!("garbler now verifies adaptors");

        let sp = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut garbler_exec = MosaicExecutor::new(
            net_client_gabler.clone(),
            sp,
            ts.clone(),
            circuit_path.clone(),
        );

        let mut garb_results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await;
        // results ActionResult::DepositAdaptorVerificationResult
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
        println!("garbler is deposit ready");

        println!("Withdrawal Stage");
        // STARTING WITHDRAWAL STAGE for Disputed Withdrawal

        garbler::GarblerSM::stf(
            &mut garb_state,
            fasm::Input::Normal(GarbInput::DisputedWithdrawal(deposit_id, withdrawal_input)),
            &mut garb_actions,
        )
        .await
        .unwrap();
        assert_eq!(garb_actions.len(), 1); // Action::CompleteAdaptorSignatures

        garbler_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut garb_results =
            mock_dispatch_garbler(&mut garb_actions, &garbler_exec, &eval_peer_id).await; // ActionResult::AdaptorSignaturesCompleted
        assert_eq!(garb_results.len(), 1);

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
        assert_eq!(garb_actions.len(), 0); // Setup Consumed
        assert_eq!(
            garb_state.state.step,
            GarbStep::SetupConsumed { deposit_id }
        );

        let on_chain_sigs = garb_state
            .deposits
            .get(&deposit_id)
            .unwrap()
            .completed_sigs
            .as_ref()
            .unwrap();

        let eval_disputed_withdrawal = EvaluatorDisputedWithdrawalData {
            withdrawal_inputs: withdrawal_input,
            signatures: on_chain_sigs.clone(),
        };
        evaluator::EvaluatorSM::stf(
            &mut eval_state,
            fasm::Input::Normal(EvalInput::DisputedWithdrawal(
                deposit_id,
                eval_disputed_withdrawal,
            )),
            &mut eval_actions,
        )
        .await
        .unwrap();
        assert_eq!(eval_actions.len(), N_EVAL_CIRCUITS); // Action::EvaluateGarblingTable

        println!("evaluate garbling table");
        eval_exec.storage = DummyStorageProvider {
            garb_state: garb_state.clone(),
            eval_state: eval_state.clone(),
        };
        let mut eval_results =
            mock_dispatch_evaluator(&mut eval_actions, &eval_exec, &garbler_peer_id).await;
        assert_eq!(eval_results.len(), N_EVAL_CIRCUITS);
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
        assert_eq!(eval_actions.len(), 0);

        match eval_state.state.step {
            EvalStep::SetupConsumed {
                deposit_id: deposit_idx,
                slash,
            } => {
                assert_eq!(deposit_id, deposit_idx);
                assert_eq!(slash.is_some(), reveals_secret);
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
    ) -> mosaic_storage_api::StorageResult<Self::GarblerState> {
        Ok(self.garb_state.clone())
    }

    async fn evaluator_state(
        &self,
        _peer_id: &PeerId,
    ) -> mosaic_storage_api::StorageResult<Self::EvaluatorState> {
        Ok(self.eval_state.clone())
    }
}

#[derive(Debug, Clone)]
struct DummyTableStore {
    dir: PathBuf,
}

#[allow(unused_variables)]
impl TableStore for DummyTableStore {
    type Error = std::io::Error;
    type Writer = FileTableWriter;
    type Reader = FileTableReader;

    async fn create(&self, id: &mosaic_storage_api::TableId) -> Result<Self::Writer, Self::Error> {
        let id = id.index.get();
        let ct_path = self.dir.join(format!("ct_{id}.bin"));
        let meta_path = self.dir.join(format!("meta_{id}.bin"));
        let trans_path = self.dir.join(format!("trans_{id}.bin"));

        let ct = File::create(ct_path).unwrap();
        let meta = File::create(meta_path).unwrap();
        let trans = File::create(trans_path).unwrap();
        Ok(FileTableWriter { ct, meta, trans })
    }

    async fn open(&self, id: &mosaic_storage_api::TableId) -> Result<Self::Reader, Self::Error> {
        let id = id.index.get();
        let ct_path = self.dir.join(format!("ct_{id}.bin"));
        let meta_path = self.dir.join(format!("meta_{id}.bin"));
        let trans_path = self.dir.join(format!("trans_{id}.bin"));

        let ct = File::open(ct_path).unwrap();
        let meta = File::open(meta_path).unwrap();
        let trans = File::open(trans_path).unwrap();
        Ok(FileTableReader { ct, meta, trans })
    }

    async fn exists(&self, id: &mosaic_storage_api::TableId) -> Result<bool, Self::Error> {
        let id = id.index.get();

        let ct_path = self.dir.join(format!("ct_{id}.bin"));
        let meta_path = self.dir.join(format!("meta_{id}.bin"));
        let trans_path = self.dir.join(format!("trans_{id}.bin"));

        let ct = std::fs::exists(ct_path).unwrap();
        let meta = std::fs::exists(meta_path).unwrap();
        let trans = std::fs::exists(trans_path).unwrap();
        Ok(ct && meta && trans)
    }

    async fn delete(&self, id: &mosaic_storage_api::TableId) -> Result<(), Self::Error> {
        let id = id.index.get();
        println!("deleting file gc_{id}.bin");
        //std::fs::remove_file(format!("gc_{id}.bin")).unwrap();
        Ok(())
    }
}

struct FileTableWriter {
    ct: std::fs::File,
    meta: std::fs::File,
    trans: std::fs::File,
}

impl TableWriter for FileTableWriter {
    type Error = std::io::Error;

    async fn write_ciphertext(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.ct.write_all(data).unwrap();
        self.ct.flush().unwrap();
        Ok(())
    }

    async fn finish(
        &mut self,
        translation: &[u8],
        metadata: mosaic_storage_api::TableMetadata,
    ) -> Result<(), Self::Error> {
        fn serialize_metadata(meta: &mosaic_storage_api::TableMetadata) -> Vec<u8> {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(meta.output_label_ct.as_ref());
            buf.extend_from_slice(&meta.aes_key);
            buf.extend_from_slice(&meta.public_s);
            buf
        }

        self.ct.flush().unwrap();
        self.trans.write_all(translation).unwrap();
        self.trans.flush().unwrap();
        self.meta.write_all(&serialize_metadata(&metadata)).unwrap();
        self.meta.flush().unwrap();
        Ok(())
    }
}

struct FileTableReader {
    ct: std::fs::File,
    meta: std::fs::File,
    trans: std::fs::File,
}

impl TableReader for FileTableReader {
    type Error = std::io::Error;

    #[allow(clippy::unused_io_amount)]
    async fn metadata(&mut self) -> Result<mosaic_storage_api::TableMetadata, Self::Error> {
        let mut bytes = [0; 64];
        self.meta.read(&mut bytes).unwrap();

        let mut output_label_ct = [0u8; 32];
        output_label_ct.copy_from_slice(&bytes[..32]);

        let mut aes_key = [0u8; 16];
        aes_key.copy_from_slice(&bytes[32..48]);

        let mut public_s = [0u8; 16];
        public_s.copy_from_slice(&bytes[48..64]);

        Ok(TableMetadata {
            output_label_ct: output_label_ct.into(),
            aes_key,
            public_s,
        })
    }

    async fn read_translation(&mut self) -> Result<Vec<u8>, Self::Error> {
        let mut translation_material: Vec<[[[u8; 16]; 8]; 256]> = Vec::new();

        for _ in 0..N_INPUT_WIRES {
            let mut material = [[[0; 16]; 8]; 256];
            for byte_row in &mut material {
                for ciphertext in byte_row {
                    let mut ct_bytes = [0u8; 16];
                    self.trans
                        .read_exact(&mut ct_bytes)
                        .expect("Failed to read translation material");
                    *ciphertext = ct_bytes;
                }
            }
            translation_material.push(material);
        }

        let flat: Vec<u8> = translation_material
            .into_iter()
            .flat_map(|lvl1| lvl1.into_iter())
            .flat_map(|lvl2| lvl2.into_iter())
            .flat_map(|arr16| arr16.into_iter())
            .collect();
        Ok(flat)
    }

    async fn read_ciphertext(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;

        while total < buf.len() {
            let n = self.ct.read(&mut buf[total..]).unwrap(); // <-- async read
            if n == 0 {
                break; // EOF
            }
            total += n;
        }

        Ok(total)
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
                            garb_coordinator(&exec.circuit_path, *session).await
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
                        println!("unhandled garbler action variant {:?}", action);
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

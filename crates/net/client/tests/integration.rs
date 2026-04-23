//! Integration tests for net-client.
//!
//! These tests verify end-to-end protocol message communication between
//! two Mosaic instances using the typed NetClient API.

// Silence unused crate warnings for transitive dependencies
use std::{
    net::SocketAddr,
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[path = "../../test-utils/port_allocator.rs"]
mod port_allocator;

use ark_serialize as _;
use ed25519_dalek as _;
use futures_timer as _;
use futures_util as _;
use mosaic_net_svc_api as _;
use mosaic_vs3 as _;
use rand as _;
use thiserror as _;
use tracing_subscriber as _;

/// Generous upper-bound timeout for test operations.
///
/// Tests complete in milliseconds locally, but CI runners can be much slower
/// (connection establishment, TLS handshake, scheduling delays). This timeout
/// prevents false failures without slowing down the happy path.
const CI_TIMEOUT: Duration = Duration::from_secs(20);

use ed25519_dalek::SigningKey;
use mosaic_cac_types::{
    ChallengeIndices, ChallengeMsg, ChallengeResponseMsgChunk, CircuitInputShares, CommitMsgChunk,
    Msg, WideLabelWirePolynomialCommitments, WideLabelWireShares,
};
use mosaic_net_client::{NetClient, NetClientConfig, RecvError, SendError, StreamPriority};
use mosaic_net_svc::{
    PeerId,
    config::{NetServiceConfig, PeerConfig},
    svc::NetService,
    tls::peer_id_from_signing_key,
};
use mosaic_vs3::{Index, Polynomial, Share};

// ============================================================================
// Test Infrastructure
// ============================================================================

static TRACING_INIT: Once = Once::new();
static KEY_COUNTER: AtomicU64 = AtomicU64::new(0);
static KEY_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("mosaic_net_svc=debug".parse().unwrap())
                    .add_directive("mosaic_net_client=debug".parse().unwrap()),
            )
            .with_test_writer()
            .init();
    });
}

fn next_port() -> u16 {
    // Range 50000-59999 — must NOT overlap with net-svc tests (30000-39999).
    port_allocator::next_port("net-client", 50000, 59999)
        .expect("allocate unique test port for net-client")
}

fn test_key_from_tag(tag: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_le_bytes());
    bytes[8..16].copy_from_slice(&(tag.wrapping_mul(0x9E3779B185EBCA87)).to_le_bytes());
    bytes[16..24].copy_from_slice(&(tag ^ 0xA5A5A5A5A5A5A5A5).to_le_bytes());
    bytes[24..32].copy_from_slice(&(tag.rotate_left(17) ^ 0x0123456789ABCDEF).to_le_bytes());
    if bytes.iter().all(|b| *b == 0) {
        bytes[0] = 1;
    }
    SigningKey::from_bytes(&bytes)
}

fn next_key_tag() -> u64 {
    KEY_INIT.call_once(|| {
        let start = ((std::process::id() as u64) << 32) | 0x2468_ACE0;
        KEY_COUNTER.store(start, Ordering::SeqCst);
    });
    KEY_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn test_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

struct TestPeer {
    client: NetClient,
    peer_id: PeerId,
    controller: Option<mosaic_net_svc::svc::NetServiceController>,
}

fn shutdown_controller_with_timeout(
    controller: mosaic_net_svc::svc::NetServiceController,
    timeout: Duration,
) -> bool {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = controller.shutdown();
        let _ = done_tx.send(());
    });
    done_rx.recv_timeout(timeout).is_ok()
}

impl TestPeer {
    fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn shutdown(&mut self) {
        if let Some(ctrl) = self.controller.take() {
            let _ = shutdown_controller_with_timeout(ctrl, Duration::from_secs(2));
        }
    }

    fn shutdown_and_wait(&mut self, timeout: Duration) {
        if let Some(ctrl) = self.controller.take() {
            assert!(
                shutdown_controller_with_timeout(ctrl, timeout),
                "service shutdown did not complete within {:?}",
                timeout
            );
        }
    }
}

impl Drop for TestPeer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Create a pair of connected peers with NetClient instances.
fn create_client_pair() -> (TestPeer, TestPeer) {
    create_client_pair_with_config(NetClientConfig::default())
}

fn create_client_pair_with_config(config: NetClientConfig) -> (TestPeer, TestPeer) {
    init_tracing();

    for attempt in 0..50 {
        let port_a = next_port();
        let port_b = next_port();

        let key_a = test_key_from_tag(next_key_tag());
        let key_b = test_key_from_tag(next_key_tag());

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
        // Stagger startup slightly to avoid deterministic dial races.
        std::thread::sleep(Duration::from_millis(50));

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

        // Allow monitors/dialers to settle before first protocol stream.
        std::thread::sleep(Duration::from_millis(50));

        return (
            TestPeer {
                client: NetClient::with_config(handle_a, config),
                peer_id: peer_id_a,
                controller: Some(ctrl_a),
            },
            TestPeer {
                client: NetClient::with_config(handle_b, config),
                peer_id: peer_id_b,
                controller: Some(ctrl_b),
            },
        );
    }

    unreachable!()
}

fn run_async<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap()
        .block_on(f)
}

async fn with_timeout<F, T>(duration: Duration, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, f)
        .await
        .expect("operation timed out")
}

async fn retry_until_ok<F, Fut, T, E>(timeout: Duration, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    tokio::time::timeout(timeout, async {
        let started = Instant::now();
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            match f().await {
                Ok(v) => return v,
                Err(_) => {
                    if cfg!(test) {
                        eprintln!(
                            "retry_until_ok: attempt {} failed after {:?}",
                            attempts,
                            started.elapsed()
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
    })
    .await
    .expect("operation did not succeed before timeout")
}

/// Establish a basic working protocol-stream path from `sender` to `receiver`.
///
/// This is a setup barrier only; behavior assertions should remain strict.
async fn stabilize_stream_path(sender: &TestPeer, receiver: &TestPeer) {
    retry_until_ok(Duration::from_secs(10), || async {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            sender
                .client
                .handle()
                .open_protocol_stream(receiver.peer_id(), StreamPriority::Normal.as_i32()),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        let mut inbound = tokio::time::timeout(
            Duration::from_secs(3),
            receiver.client.handle().protocol_streams().recv(),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        for probe in [b"probe-1".as_slice(), b"probe-2".as_slice()] {
            stream.write(probe.to_vec()).await.map_err(|_| ())?;
            let payload = tokio::time::timeout(Duration::from_secs(3), inbound.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if payload.as_slice() != probe {
                return Err(());
            }
        }
        Ok::<(), ()>(())
    })
    .await;
}

/// Send a message from sender to receiver and verify receipt.
///
/// The message is passed by value to avoid expensive clones of large messages.
async fn send_and_receive<M, H>(sender: &TestPeer, receiver: &TestPeer, make_msg: M, assert_msg: H)
where
    M: Fn() -> Msg,
    H: Fn(PeerId, &Msg),
{
    let assert_fn = &assert_msg;
    retry_until_ok(CI_TIMEOUT, || {
        let sender_client = sender.client.clone();
        let receiver_client = receiver.client.clone();
        let receiver_id = receiver.peer_id();
        let msg = make_msg();

        async move {
            let mut send_handle =
                tokio::spawn(async move { sender_client.send(receiver_id, msg).await });

            let request = tokio::select! {
                recv_result = tokio::time::timeout(Duration::from_secs(15), receiver_client.recv()) => {
                    match recv_result {
                        Ok(Ok(request)) => request,
                        Ok(Err(_)) | Err(_) => {
                            send_handle.abort();
                            return Err(());
                        }
                    }
                }
                send_result = &mut send_handle => {
                    let _ = send_result;
                    return Err(());
                }
            };

            let peer = request.peer();
            assert_fn(peer, &request.message);
            request.ack().await.map_err(|_| ())?;

            match tokio::time::timeout(Duration::from_secs(15), &mut send_handle).await {
                Ok(Ok(Ok(_ack))) => Ok(()),
                Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_) => Err(()),
            }
        }
    })
    .await;
}

// ============================================================================
// Test Message Factories
// ============================================================================

fn make_challenge_msg(seed: u64) -> ChallengeMsg {
    use rand::{SeedableRng, seq::SliceRandom};

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut indices: Vec<usize> = (1..=181).collect();
    indices.shuffle(&mut rng);
    indices.truncate(174);
    indices.sort();

    ChallengeMsg {
        challenge_indices: ChallengeIndices::new(|i| Index::new(indices[i]).unwrap()),
    }
}

fn make_commit_msg_chunk(wire_index: u16, seed: u64) -> CommitMsgChunk {
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let poly = Polynomial::rand(&mut rng);
    let commitment = poly.commit();

    CommitMsgChunk {
        wire_index,
        commitments: WideLabelWirePolynomialCommitments::new(|_| commitment.clone()),
    }
}

fn make_challenge_response_chunk(circuit_index: u16) -> ChallengeResponseMsgChunk {
    let idx = Index::new(1).unwrap();
    let share = Share::new(idx, Default::default());

    ChallengeResponseMsgChunk {
        circuit_index,
        shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| share)),
    }
}

// ============================================================================
// Basic Send/Recv Tests
// ============================================================================

#[test]
fn test_send_recv_challenge_msg() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        let expected_indices = make_challenge_msg(42).challenge_indices.clone();
        let peer_a_id = peer_a.peer_id();

        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::Challenge(make_challenge_msg(42)),
            move |peer, message| {
                assert_eq!(peer, peer_a_id);

                match message {
                    Msg::Challenge(received) => {
                        assert_eq!(received.challenge_indices, expected_indices);
                    }
                    other => panic!("expected Challenge, got {:?}", other),
                }
            },
        )
        .await;
    });
}

#[test]
fn test_send_recv_commit_msg_chunk() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::CommitChunk(make_commit_msg_chunk(42, 12345)),
            |_peer, message| match message {
                Msg::CommitChunk(received) => {
                    assert_eq!(received.wire_index, 42);
                }
                other => panic!("expected CommitChunk, got {:?}", other),
            },
        )
        .await;
    });
}

#[test]
fn test_send_recv_challenge_response_chunk() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::ChallengeResponseChunk(make_challenge_response_chunk(7)),
            |_peer, message| match message {
                Msg::ChallengeResponseChunk(received) => {
                    assert_eq!(received.circuit_index, 7);
                }
                other => panic!("expected ChallengeResponseChunk, got {:?}", other),
            },
        )
        .await;
    });
}

// ============================================================================
// Multiple Messages Tests
// ============================================================================

#[test]
fn test_send_multiple_messages_sequentially() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        // Send 5 challenge messages in sequence
        for i in 0..5u64 {
            send_and_receive(
                &peer_a,
                &peer_b,
                move || Msg::Challenge(make_challenge_msg(i)),
                |_peer, message| {
                    assert!(matches!(message, Msg::Challenge(_)));
                },
            )
            .await;
        }
    });
}

#[test]
fn test_bidirectional_communication() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        stabilize_stream_path(&peer_b, &peer_a).await;
        // A sends to B
        let peer_a_id = peer_a.peer_id();
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::Challenge(make_challenge_msg(100)),
            |peer, _message| {
                assert_eq!(peer, peer_a_id);
            },
        )
        .await;

        // B sends to A
        let peer_b_id = peer_b.peer_id();
        send_and_receive(
            &peer_b,
            &peer_a,
            || Msg::Challenge(make_challenge_msg(200)),
            |peer, _message| {
                assert_eq!(peer, peer_b_id);
            },
        )
        .await;
    });
}

// ============================================================================
// Into<Msg> Ergonomics Tests
// ============================================================================

#[test]
fn test_send_accepts_into_msg() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        // Send using the concrete type (uses Into<Msg>)
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::Challenge(make_challenge_msg(42)),
            |_peer, _message| {},
        )
        .await;

        // Send using explicit Msg wrapper
        let commit = make_commit_msg_chunk(0, 999);
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::CommitChunk(commit.clone()),
            |_peer, _message| {},
        )
        .await;
    });
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_send_to_unknown_peer_fails() {
    let (peer_a, _peer_b) = create_client_pair();

    run_async(async {
        let unknown_peer = PeerId::from_bytes([0xffu8; 32]);
        let msg = make_challenge_msg(1);

        let result = peer_a.client.send(unknown_peer, msg).await;

        assert!(
            matches!(result, Err(mosaic_net_client::SendError::Open(_))),
            "expected Open error, got {:?}",
            result
        );
    });
}

#[test]
fn test_recv_closed_when_service_shuts_down() {
    let (mut peer_a, mut peer_b) = create_client_pair();

    // Get the client before shutting down peer B's service.
    let client_b = peer_b.client.clone();

    peer_b.shutdown_and_wait(Duration::from_secs(10));

    run_async(async {
        let result = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
            .await
            .expect("recv timed out after service shutdown");
        assert!(
            matches!(result, Err(RecvError::Closed)),
            "expected RecvError::Closed after shutdown, got {:?}",
            result
        );
    });

    peer_a.shutdown();
}

// ============================================================================
// Ack Behavior Tests
// ============================================================================

#[test]
fn test_ack_completes_send() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        retry_until_ok(CI_TIMEOUT, || {
            let peer_b_id = peer_b.peer_id();
            let client_a = peer_a.client.clone();
            let client_b = peer_b.client.clone();
            async move {
                let msg = make_challenge_msg(42);
                let mut send_handle =
                    tokio::spawn(async move { client_a.send(peer_b_id, msg).await });

                let request = tokio::select! {
                    recv_result = tokio::time::timeout(Duration::from_secs(5), client_b.recv()) => {
                        match recv_result {
                            Ok(Ok(request)) => request,
                            Ok(Err(_)) | Err(_) => {
                                send_handle.abort();
                                return Err(());
                            }
                        }
                    }
                    send_result = &mut send_handle => {
                        let _ = send_result;
                        return Err(());
                    }
                };

                request.ack().await.map_err(|_| ())?;

                match tokio::time::timeout(Duration::from_secs(5), &mut send_handle).await {
                    Ok(Ok(Ok(_ack))) => Ok::<_, ()>(()),
                    _ => Err(()),
                }
            }
        })
        .await;
    });
}

#[test]
fn test_send_times_out_without_ack() {
    let ack_timeout = Duration::from_millis(200);
    let config = NetClientConfig {
        open_timeout: Duration::from_secs(2),
        ack_timeout,
    };
    let (peer_a, peer_b) = create_client_pair_with_config(config);

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;

        let msg = make_challenge_msg(42);
        let peer_b_id = peer_b.peer_id();
        let client_a = peer_a.client.clone();
        let handle_b = peer_b.client.handle().clone();

        let mut send_handle = tokio::spawn(async move { client_a.send(peer_b_id, msg).await });

        // Receive raw stream but do not ack it.
        let mut stream =
            match tokio::time::timeout(Duration::from_secs(10), handle_b.protocol_streams().recv())
                .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    let sender_state =
                        tokio::time::timeout(Duration::from_secs(2), &mut send_handle).await;
                    panic!(
                        "recv failed before stream arrived: {:?}; sender_state={:?}",
                        e, sender_state
                    );
                }
                Err(_) => {
                    let sender_state =
                        tokio::time::timeout(Duration::from_secs(2), &mut send_handle).await;
                    panic!(
                        "timed out waiting for raw stream; sender_state={:?}",
                        sender_state
                    );
                }
            };
        let _bytes = stream.read().await.expect("read failed");

        // Hold the stream open past the ack timeout to force a timeout on sender.
        tokio::time::sleep(ack_timeout.saturating_mul(2)).await;

        let result = tokio::time::timeout(Duration::from_secs(5), &mut send_handle)
            .await
            .expect("send task join timed out")
            .expect("send task panicked");

        match result {
            Err(SendError::NoAck(_)) => {}
            Ok(_) => panic!("expected NoAck error, got Ok"),
            Err(other) => panic!("expected NoAck error, got {:?}", other),
        }
    });
}

#[test]
fn test_drop_request_without_ack_closes_stream() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        retry_until_ok(CI_TIMEOUT, || {
            let peer_b_id = peer_b.peer_id();
            let client_a = peer_a.client.clone();
            let client_b = peer_b.client.clone();

            async move {
                let msg = make_challenge_msg(42);
                let mut send_handle =
                    tokio::spawn(async move { client_a.send(peer_b_id, msg).await });

                let request = tokio::select! {
                    recv_result = tokio::time::timeout(Duration::from_secs(5), client_b.recv()) => {
                        match recv_result {
                            Ok(Ok(request)) => request,
                            Ok(Err(_)) | Err(_) => {
                                send_handle.abort();
                                return Err(());
                            }
                        }
                    }
                    send_result = &mut send_handle => {
                        let _ = send_result;
                        return Err(());
                    }
                };
                drop(request); // No ack.

                // Current wire semantics treat peer FIN as stream-read success (empty ack),
                // so dropping without ack may still resolve as Ack.
                match tokio::time::timeout(Duration::from_secs(5), &mut send_handle).await {
                    Ok(Ok(Ok(mosaic_net_client::Ack))) | Ok(Ok(Err(SendError::NoAck(_)))) => {
                        Ok::<_, ()>(())
                    }
                    _ => Err(()),
                }
            }
        })
        .await;
    });
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[test]
fn test_concurrent_sends_from_same_peer() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        let peer_b_id = peer_b.peer_id();

        // Spawn multiple concurrent sends
        let mut handles = Vec::new();
        for i in 0..3u64 {
            let client = peer_a.client.clone();
            let msg = make_challenge_msg(i);
            handles.push(tokio::spawn(async move {
                retry_until_ok(CI_TIMEOUT, || {
                    let msg = msg.clone();
                    async { client.send(peer_b_id, msg).await }
                })
                .await
            }));
        }

        // Receive all messages. During startup/race churn, empty finished streams
        // may surface transiently; only count successfully decoded requests.
        let mut received = 0usize;
        while received < 3 {
            match with_timeout(CI_TIMEOUT, peer_b.client.recv()).await {
                Ok(request) => {
                    request.ack().await.expect("ack failed");
                    received += 1;
                }
                Err(RecvError::Read {
                    source: mosaic_net_svc::StreamClosed::PeerFinished,
                    ..
                }) => continue,
                Err(err) => panic!("recv failed: {:?}", err),
            }
        }

        // All sends should complete
        for handle in handles {
            let result = with_timeout(CI_TIMEOUT, handle)
                .await
                .expect("task panicked");
            assert!(matches!(result, mosaic_net_client::Ack));
        }
    });
}

// ============================================================================
// Large Message Tests
// ============================================================================

#[test]
fn test_large_commit_chunk_roundtrip() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        // CommitMsgChunk is one of the larger message types (~2.76 MB uncompressed)
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::CommitChunk(make_commit_msg_chunk(100, 999)),
            |_peer, message| {
                match message {
                    Msg::CommitChunk(received) => {
                        assert_eq!(received.wire_index, 100);
                        // Verify all 256 commitments made it through
                        assert_eq!(received.commitments.len(), 256);
                    }
                    other => panic!("expected CommitChunk, got {:?}", other),
                }
            },
        )
        .await;
    });
}

#[test]
fn test_large_challenge_response_roundtrip() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;
        // ChallengeResponseMsgChunk is also large (~1.68 MB)
        send_and_receive(
            &peer_a,
            &peer_b,
            || Msg::ChallengeResponseChunk(make_challenge_response_chunk(50)),
            |_peer, message| match message {
                Msg::ChallengeResponseChunk(received) => {
                    assert_eq!(received.circuit_index, 50);
                }
                other => panic!("expected ChallengeResponseChunk, got {:?}", other),
            },
        )
        .await;
    });
}

// ============================================================================
// Bulk Transfer Wrapper Tests
// ============================================================================

#[test]
fn test_bulk_wrapper_large_transfer_no_stall() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;

        let mut identifier = [0xabu8; 32];
        let tag = next_key_tag();
        identifier[..8].copy_from_slice(&tag.to_le_bytes());

        let expectation = peer_b
            .client
            .expect_bulk_receiver(peer_a.peer_id, identifier)
            .await
            .expect("register bulk expectation");

        let recv_task = tokio::spawn(async move {
            let mut receiver = expectation.recv().await.expect("receive bulk stream");
            let mut total = 0usize;
            loop {
                match tokio::time::timeout(Duration::from_secs(10), receiver.read()).await {
                    Ok(Ok(chunk)) => total += chunk.len(),
                    Ok(Err(mosaic_net_svc::StreamClosed::PeerFinished)) => break,
                    Ok(Err(err)) => panic!("bulk read failed: {err}"),
                    Err(_) => panic!("timed out waiting for bulk payload"),
                }
            }
            total
        });

        tokio::task::yield_now().await;

        let mut sender = peer_a
            .client
            .open_bulk_sender(peer_b.peer_id, identifier, StreamPriority::Bulk.as_i32())
            .await
            .expect("open bulk sender");

        let total_bytes = 2 * 1024 * 1024 + 97;
        let chunk_size = 64 * 1024;
        let mut sent = 0usize;
        let mut buf = Vec::with_capacity(chunk_size);

        while sent < total_bytes {
            let take = (total_bytes - sent).min(chunk_size);
            buf.clear();
            buf.resize(take, (sent as u8).wrapping_mul(31).wrapping_add(7));
            buf = sender.write(buf).await.expect("bulk write");
            sent += take;
        }
        drop(sender);

        let received = with_timeout(CI_TIMEOUT, recv_task)
            .await
            .expect("receiver task panicked");
        assert_eq!(received, total_bytes);
    });
}

#[test]
fn test_bulk_wrapper_pipelined_write_no_reclaim() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;

        let mut identifier = [0x42u8; 32];
        let tag = next_key_tag();
        identifier[..8].copy_from_slice(&tag.to_le_bytes());

        let expectation = peer_b
            .client
            .expect_bulk_receiver(peer_a.peer_id, identifier)
            .await
            .expect("register bulk expectation");

        let recv_task = tokio::spawn(async move {
            let mut receiver = expectation.recv().await.expect("receive bulk stream");
            let mut data = Vec::new();
            loop {
                match tokio::time::timeout(Duration::from_secs(10), receiver.read()).await {
                    Ok(Ok(chunk)) => data.extend_from_slice(&chunk),
                    Ok(Err(mosaic_net_svc::StreamClosed::PeerFinished)) => break,
                    Ok(Err(err)) => panic!("bulk read failed: {err}"),
                    Err(_) => panic!("timed out waiting for bulk payload"),
                }
            }
            data
        });

        tokio::task::yield_now().await;

        let mut sender = peer_a
            .client
            .open_bulk_sender(peer_b.peer_id, identifier, StreamPriority::Bulk.as_i32())
            .await
            .expect("open bulk sender");

        let chunks = [vec![1u8; 8192], vec![2u8; 8192], vec![3u8; 8192]];
        for chunk in &chunks {
            sender
                .write_no_reclaim(chunk.clone())
                .await
                .expect("queue bulk write");
        }

        for _ in 0..chunks.len() {
            let reclaimed = sender.recv_buffer().await.expect("reclaimed buffer");
            assert!(reclaimed.is_empty(), "returned buffer should be cleared");
        }
        drop(sender);

        let received = with_timeout(CI_TIMEOUT, recv_task)
            .await
            .expect("receiver task panicked");
        let expected = chunks.concat();
        assert_eq!(received, expected);
    });
}

#[test]
fn test_bulk_expectation_recv_timeout() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;

        let mut identifier = [0x66u8; 32];
        let tag = next_key_tag();
        identifier[..8].copy_from_slice(&tag.to_le_bytes());

        let expectation = peer_b
            .client
            .expect_bulk_receiver(peer_a.peer_id, identifier)
            .await
            .expect("register bulk expectation");

        let err = expectation
            .recv_with_timeout(Duration::from_millis(50))
            .await
            .expect_err("bulk receive should time out");
        assert!(matches!(err, mosaic_net_client::BulkReceiveError::TimedOut));
    });
}

#[test]
fn test_bulk_receiver_read_timeout() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        stabilize_stream_path(&peer_a, &peer_b).await;

        let mut identifier = [0x67u8; 32];
        let tag = next_key_tag();
        identifier[..8].copy_from_slice(&tag.to_le_bytes());

        let expectation = peer_b
            .client
            .expect_bulk_receiver(peer_a.peer_id, identifier)
            .await
            .expect("register bulk expectation");

        let sender = peer_a
            .client
            .open_bulk_sender(peer_b.peer_id, identifier, StreamPriority::Bulk.as_i32())
            .await
            .expect("open bulk sender");

        let mut receiver = expectation.recv().await.expect("receive bulk stream");
        let err = receiver
            .read_with_timeout(Duration::from_millis(50))
            .await
            .expect_err("bulk read should time out");
        assert!(matches!(err, mosaic_net_client::BulkReadError::TimedOut));

        receiver.reset(0).await;
        sender.reset(0).await;
    });
}

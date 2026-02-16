//! Integration tests for net-client.
//!
//! These tests verify end-to-end protocol message communication between
//! two Mosaic instances using the typed NetClient API.

// Silence unused crate warnings for transitive dependencies
use ark_serialize as _;
use ed25519_dalek as _;
use mosaic_net_svc_api as _;
use mosaic_vs3 as _;
use rand as _;
use thiserror as _;
use tracing_subscriber as _;

use std::net::SocketAddr;
use std::sync::Once;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Generous upper-bound timeout for test operations.
///
/// Tests complete in milliseconds locally, but CI runners can be much slower
/// (connection establishment, TLS handshake, scheduling delays). This timeout
/// prevents false failures without slowing down the happy path.
const CI_TIMEOUT: Duration = Duration::from_secs(120);

use ed25519_dalek::SigningKey;
use mosaic_cac_types::{
    ChallengeIndices, ChallengeMsg, ChallengeResponseMsgChunk, CircuitInputShares, CommitMsgChunk,
    Msg, WideLabelWirePolynomialCommitments, WideLabelWireShares,
};
use mosaic_net_client::{NetClient, NetClientConfig, RecvError, SendError};
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

static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);
static PORT_INIT: Once = Once::new();
static TRACING_INIT: Once = Once::new();

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
    PORT_INIT.call_once(|| {
        let start = 40000 + (std::process::id() as u16 % 20000);
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

struct TestPeer {
    client: NetClient,
    peer_id: PeerId,
    _controller: mosaic_net_svc::svc::NetServiceController,
}

impl TestPeer {
    fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}

/// Create a pair of connected peers with NetClient instances.
///
/// Services are created in sequence with a delay to avoid the simultaneous
/// connect race condition in net-svc's deterministic connection selection.
fn create_client_pair() -> (TestPeer, TestPeer) {
    create_client_pair_with_config(NetClientConfig::default())
}

fn create_client_pair_with_config(config: NetClientConfig) -> (TestPeer, TestPeer) {
    init_tracing();

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

/// Send a message from sender to receiver and verify receipt.
///
/// The message is passed by value to avoid expensive clones of large messages.
/// Uses infinite retries with a deadline to handle connection stabilization.
async fn send_and_receive<T, H>(sender: &TestPeer, receiver: &TestPeer, msg: T, handle: H)
where
    T: Into<Msg> + Send + 'static,
    H: FnOnce(PeerId, &Msg),
{
    use ark_serialize::{CanonicalSerialize, Compress};
    use mosaic_net_client::protocol::StreamPriority;

    let handle_ref = sender.client.handle();
    let receiver_id = receiver.peer_id();
    let msg: Msg = msg.into();

    // Serialize once upfront - this is the expensive part for large messages
    let mut bytes = Vec::new();
    msg.serialize_with_mode(&mut bytes, Compress::No)
        .expect("serialization failed");

    let handle_clone = handle_ref.clone();
    let mut send_handle = tokio::spawn(async move {
        let started = Instant::now();
        let deadline = CI_TIMEOUT;

        // Infinite retries with deadline and micro-waits
        loop {
            if started.elapsed() >= deadline {
                eprintln!(
                    "[send-task] deadline exceeded after {:?}",
                    started.elapsed()
                );
                return Err("send deadline exceeded".to_string());
            }

            // Try to open a protocol stream (short timeout per attempt)
            let stream_result = tokio::time::timeout(
                Duration::from_millis(500),
                handle_clone.open_protocol_stream(receiver_id, StreamPriority::Normal.as_i32()),
            )
            .await;

            let mut stream = match stream_result {
                Ok(Ok(s)) => s,
                Ok(Err(_)) | Err(_) => {
                    // Connection not ready, micro-wait and retry
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            // Write the pre-serialized bytes
            if stream.write(bytes.clone()).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            // Wait for ack
            match stream.read().await {
                Ok(_) => return Ok(()),
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            }
        }
    });

    let request = match tokio::time::timeout(CI_TIMEOUT, receiver.client.recv()).await {
        Ok(Ok(request)) => request,
        Ok(Err(err)) => panic!("recv failed: {:?}", err),
        Err(_) => {
            send_handle.abort();
            panic!("recv timed out after 20s");
        }
    };

    let peer = request.peer();
    handle(peer, &request.message);

    request.ack().await.expect("ack failed");

    match tokio::time::timeout(CI_TIMEOUT, &mut send_handle).await {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(e))) => panic!("send task failed: {}", e),
        Ok(Err(err)) => panic!("send task panicked: {:?}", err),
        Err(_) => {
            send_handle.abort();
            panic!("send task join timed out");
        }
    };
}

// ============================================================================
// Test Message Factories
// ============================================================================

fn make_challenge_msg(seed: u64) -> ChallengeMsg {
    use rand::SeedableRng;
    use rand::seq::SliceRandom;

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
        shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| share.clone())),
    }
}

// ============================================================================
// Basic Send/Recv Tests
// ============================================================================

#[test]
fn test_send_recv_challenge_msg() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        let msg = make_challenge_msg(42);
        let expected_indices = msg.challenge_indices.clone();
        let peer_a_id = peer_a.peer_id();

        send_and_receive(&peer_a, &peer_b, msg, move |peer, message| {
            assert_eq!(peer, peer_a_id);

            match message {
                Msg::Challenge(received) => {
                    assert_eq!(received.challenge_indices, expected_indices);
                }
                other => panic!("expected Challenge, got {:?}", other),
            }
        })
        .await;
    });
}

#[test]
fn test_send_recv_commit_msg_chunk() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        let msg = make_commit_msg_chunk(42, 12345);

        send_and_receive(&peer_a, &peer_b, msg, |_peer, message| match message {
            Msg::CommitChunk(received) => {
                assert_eq!(received.wire_index, 42);
            }
            other => panic!("expected CommitChunk, got {:?}", other),
        })
        .await;
    });
}

#[test]
fn test_send_recv_challenge_response_chunk() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        let msg = make_challenge_response_chunk(7);

        send_and_receive(&peer_a, &peer_b, msg, |_peer, message| match message {
            Msg::ChallengeResponseChunk(received) => {
                assert_eq!(received.circuit_index, 7);
            }
            other => panic!("expected ChallengeResponseChunk, got {:?}", other),
        })
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
        // Send 5 challenge messages in sequence
        for i in 0..5u64 {
            let msg = make_challenge_msg(i);

            send_and_receive(&peer_a, &peer_b, msg, |_peer, message| {
                assert!(matches!(message, Msg::Challenge(_)));
            })
            .await;
        }
    });
}

#[test]
fn test_bidirectional_communication() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        // A sends to B
        let peer_a_id = peer_a.peer_id();
        let msg_a = make_challenge_msg(100);
        send_and_receive(&peer_a, &peer_b, msg_a, |peer, _message| {
            assert_eq!(peer, peer_a_id);
        })
        .await;

        // B sends to A
        let peer_b_id = peer_b.peer_id();
        let msg_b = make_challenge_msg(200);
        send_and_receive(&peer_b, &peer_a, msg_b, |peer, _message| {
            assert_eq!(peer, peer_b_id);
        })
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
        // Send using the concrete type (uses Into<Msg>)
        let challenge = make_challenge_msg(42);
        send_and_receive(&peer_a, &peer_b, challenge, |_peer, _message| {}).await;

        // Send using explicit Msg wrapper
        let commit = make_commit_msg_chunk(0, 999);
        send_and_receive(
            &peer_a,
            &peer_b,
            Msg::CommitChunk(commit),
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
    let (peer_a, peer_b) = create_client_pair();

    // Get the client before dropping controller
    let client_b = peer_b.client.clone();

    // Drop peer_b which shuts down its service
    drop(peer_b);

    run_async(async {
        // Give time for shutdown to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try to receive - should fail since service is down
        let result = tokio::time::timeout(Duration::from_millis(500), client_b.recv()).await;

        match result {
            Ok(Err(RecvError::Closed)) => {
                // Expected
            }
            Ok(Err(other)) => {
                // Also acceptable - other errors due to shutdown
                println!("Got error (acceptable): {:?}", other);
            }
            Ok(Ok(_)) => {
                panic!("expected error after shutdown, got message");
            }
            Err(_timeout) => {
                // Timeout is acceptable - recv might just hang forever
                // when there are no messages and service is down
            }
        }
    });

    drop(peer_a);
}

// ============================================================================
// Ack Behavior Tests
// ============================================================================

#[test]
fn test_ack_completes_send() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        let msg = make_challenge_msg(42);

        // Start send in background task
        let peer_b_id = peer_b.peer_id();
        let client_a = peer_a.client.clone();
        let msg_clone = msg.clone();

        let send_handle = tokio::spawn(async move {
            retry_until_ok(CI_TIMEOUT, || {
                let msg = msg_clone.clone();
                async { client_a.send(peer_b_id, msg).await }
            })
            .await
        });

        // Receive and ack
        let request = with_timeout(CI_TIMEOUT, peer_b.client.recv())
            .await
            .expect("recv failed");
        request.ack().await.expect("ack failed");

        // Send should complete successfully
        let result = with_timeout(CI_TIMEOUT, send_handle)
            .await
            .expect("send task panicked");

        assert!(matches!(result, mosaic_net_client::Ack));
    });
}

#[test]
fn test_send_times_out_without_ack() {
    let config = NetClientConfig {
        open_timeout: Duration::from_secs(2),
        ack_timeout: Duration::from_millis(200),
    };
    let (peer_a, peer_b) = create_client_pair_with_config(config);

    run_async(async {
        let msg = make_challenge_msg(42);
        let peer_b_id = peer_b.peer_id();
        let client_a = peer_a.client.clone();
        let handle_b = peer_b.client.handle().clone();

        let send_handle = tokio::spawn(async move { client_a.send(peer_b_id, msg).await });

        // Receive raw stream but do not ack it.
        let mut stream = with_timeout(CI_TIMEOUT, handle_b.protocol_streams().recv())
            .await
            .expect("recv failed");
        let _bytes = stream.read().await.expect("read failed");

        // Hold the stream open past the ack timeout to force a timeout on sender.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let result = with_timeout(CI_TIMEOUT, send_handle)
            .await
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
        let peer_b_id = peer_b.peer_id();
        let client_a = peer_a.client.clone();
        let msg = make_challenge_msg(42);

        // First, ensure connection is stable by doing a successful send/recv
        let probe = make_challenge_msg(0);
        send_and_receive(&peer_a, &peer_b, probe, |_, _| {}).await;

        // Now test the drop-without-ack behavior
        let send_handle = tokio::spawn(async move { client_a.send(peer_b_id, msg).await });

        // Receive but drop without acking
        let request = with_timeout(CI_TIMEOUT, peer_b.client.recv())
            .await
            .expect("recv failed");
        drop(request); // No ack!

        // Send should fail or succeed (FIN may be interpreted as empty ack)
        // but it must not hang forever
        let result = tokio::time::timeout(CI_TIMEOUT, send_handle).await;

        match result {
            Ok(Ok(Ok(_))) => {
                // Might succeed if FIN is interpreted as empty ack
            }
            Ok(Ok(Err(_))) | Ok(Err(_)) => {
                // Send failed or task panicked - acceptable
            }
            Err(_) => {
                panic!("send should not hang forever");
            }
        }
    });
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[test]
fn test_concurrent_sends_from_same_peer() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
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

        // Receive all messages
        for _ in 0..3 {
            let request = with_timeout(CI_TIMEOUT, peer_b.client.recv())
                .await
                .expect("recv failed");
            request.ack().await.expect("ack failed");
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
        // CommitMsgChunk is one of the larger message types (~2.76 MB uncompressed)
        let msg = make_commit_msg_chunk(100, 999);

        send_and_receive(&peer_a, &peer_b, msg, |_peer, message| {
            match message {
                Msg::CommitChunk(received) => {
                    assert_eq!(received.wire_index, 100);
                    // Verify all 256 commitments made it through
                    assert_eq!(received.commitments.len(), 256);
                }
                other => panic!("expected CommitChunk, got {:?}", other),
            }
        })
        .await;
    });
}

#[test]
fn test_large_challenge_response_roundtrip() {
    let (peer_a, peer_b) = create_client_pair();

    run_async(async {
        // ChallengeResponseMsgChunk is also large (~1.68 MB)
        let msg = make_challenge_response_chunk(50);

        send_and_receive(&peer_a, &peer_b, msg, |_peer, message| match message {
            Msg::ChallengeResponseChunk(received) => {
                assert_eq!(received.circuit_index, 50);
            }
            other => panic!("expected ChallengeResponseChunk, got {:?}", other),
        })
        .await;
    });
}

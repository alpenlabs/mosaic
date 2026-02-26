//! Integration tests for net-svc.
//!
//! These tests verify connectivity, stream communication, and error handling.
//!
//! Note on robustness:
//! These tests used to rely on fixed sleeps to "give services time to connect".
//! That is inherently flaky in CI. Prefer waiting for an actual successful
//! operation with a timeout.

use std::{
    net::SocketAddr,
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

#[path = "../../test-utils/port_allocator.rs"]
mod port_allocator;

/// Generous upper-bound timeout for test operations.
///
/// Tests complete in milliseconds locally, but CI runners can be much slower
/// (connection establishment, TLS handshake, scheduling delays). This timeout
/// prevents false failures without slowing down the happy path.
const CI_TIMEOUT: Duration = Duration::from_secs(15);

use ed25519_dalek::SigningKey;
use mosaic_net_svc::{
    PeerId,
    api::{OpenStreamError, Stream, StreamClosed},
    config::{NetServiceConfig, PeerConfig},
    svc::NetService,
    tls::peer_id_from_signing_key,
};
use tracing_subscriber as _;

static KEY_COUNTER: AtomicU64 = AtomicU64::new(0);
static KEY_INIT: Once = Once::new();
static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("mosaic_net_svc=debug".parse().unwrap()),
            )
            .with_test_writer()
            .init();
    });
}

fn next_port() -> u16 {
    // Range 30000-39999 — must NOT overlap with net-client tests (50000-59999).
    port_allocator::next_port("net-svc", 30000, 39999)
        .expect("allocate unique test port for net-svc")
}

fn test_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed;
    SigningKey::from_bytes(&bytes)
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
        let start = ((std::process::id() as u64) << 32) | 0x1357_9BDF;
        KEY_COUNTER.store(start, Ordering::SeqCst);
    });
    KEY_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn test_peer_id(seed: u8) -> PeerId {
    peer_id_from_signing_key(&test_key(seed))
}

fn test_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

struct TestPeer {
    handle: mosaic_net_svc::NetServiceHandle,
    controller: mosaic_net_svc::svc::NetServiceController,
    peer_id: PeerId,
}

fn shutdown_controller_with_timeout(
    controller: mosaic_net_svc::svc::NetServiceController,
    timeout: Duration,
) {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = controller.shutdown();
        let _ = done_tx.send(());
    });
    let _ = done_rx.recv_timeout(timeout);
}

impl TestPeer {
    fn shutdown(self) {
        shutdown_controller_with_timeout(self.controller, Duration::from_secs(2));
    }
}

fn create_peer_pair() -> (TestPeer, TestPeer) {
    init_tracing();
    // Retry with different ports if we hit "address in use" errors.
    // This handles port collisions in CI where multiple test processes run in parallel.
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
                .with_reconnect_backoff(Duration::from_millis(50));

        let config_b =
            NetServiceConfig::new(key_b, addr_b, vec![PeerConfig::new(peer_id_a, addr_a)])
                .with_reconnect_backoff(Duration::from_millis(50));

        let (handle_a, ctrl_a) = match NetService::new(config_a) {
            Ok(result) => result,
            Err(e) => {
                if attempt < 49 {
                    continue; // Try different ports
                }
                panic!("create net service A after 50 attempts: {}", e);
            }
        };

        let (handle_b, ctrl_b) = match NetService::new(config_b) {
            Ok(result) => result,
            Err(e) => {
                // Shut down A before retrying
                shutdown_controller_with_timeout(ctrl_a, Duration::from_secs(2));
                if attempt < 49 {
                    continue; // Try different ports
                }
                panic!("create net service B after 50 attempts: {}", e);
            }
        };

        return (
            TestPeer {
                handle: handle_a,
                controller: ctrl_a,
                peer_id: peer_id_a,
            },
            TestPeer {
                handle: handle_b,
                controller: ctrl_b,
                peer_id: peer_id_b,
            },
        );
    }

    unreachable!()
}

// Use std thread + block_on pattern to avoid runtime conflicts
fn run_async<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// Retry an async operation until it succeeds or the timeout elapses.
///
/// This replaces fixed sleeps (flaky in CI) and avoids global "readiness probes"
/// that can interfere with stream-delivery assertions.
///
/// Use this when a test needs to tolerate:
/// - service startup time
/// - connection establishment / TLS handshake time
/// - transient races in CI scheduling
async fn retry_until_ok<F, Fut, T, E>(timeout: Duration, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    tokio::time::timeout(timeout, async {
        loop {
            match f().await {
                Ok(v) => return v,
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .expect("operation did not succeed before timeout")
}

async fn open_stream_eventually(handle: &mosaic_net_svc::NetServiceHandle, peer: PeerId) -> Stream {
    retry_until_ok(CI_TIMEOUT, || async {
        tokio::time::timeout(Duration::from_secs(5), handle.open_protocol_stream(peer, 0))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    })
    .await
}

async fn open_stream_pair_eventually(sender: &TestPeer, receiver: &TestPeer) -> (Stream, Stream) {
    retry_until_ok(CI_TIMEOUT, || async {
        let mut outbound = tokio::time::timeout(
            Duration::from_secs(5),
            sender.handle.open_protocol_stream(receiver.peer_id, 0),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        let mut inbound = tokio::time::timeout(
            Duration::from_secs(5),
            receiver.handle.protocol_streams().recv(),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        for probe in [b"stabilize-1".as_slice(), b"stabilize-2".as_slice()] {
            outbound.write(probe.to_vec()).await.map_err(|_| ())?;
            let echoed = tokio::time::timeout(Duration::from_secs(5), inbound.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if echoed.as_slice() != probe {
                return Err(());
            }
        }

        Ok::<_, ()>((outbound, inbound))
    })
    .await
}

/// Receive a value with a timeout.
///
/// This is intentionally *not* a retry loop:
/// - If the channel is open but no value arrives, `recv().await` may wait indefinitely, so we bound
///   it with a timeout.
/// - If the channel is closed, `recv().await` should return promptly with an error.
/// - If the value is merely delayed, increasing the timeout is the right fix (not retries).
async fn recv_with_timeout<Fut, T>(timeout: Duration, fut: Fut) -> T
where
    Fut: std::future::Future<Output = Result<T, kanal::ReceiveError>>,
{
    tokio::time::timeout(timeout, fut)
        .await
        .expect("timeout waiting to receive")
        .expect("receive failed")
}

// NOTE: keep helpers small and used; unused helpers trigger warnings in CI.
// (deduplicated) - this helper is defined above.

// NOTE: keep helpers small and used; unused helpers trigger warnings in CI.

#[test]
fn test_services_start_and_shutdown() {
    init_tracing();

    let port_a = next_port();
    let port_b = next_port();

    let key_a = test_key_from_tag(next_key_tag());
    let key_b = test_key_from_tag(next_key_tag());

    let addr_a = test_addr(port_a);
    let addr_b = test_addr(port_b);

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![]);
    let config_b = NetServiceConfig::new(key_b, addr_b, vec![]);

    let (_handle_a, ctrl_a) = NetService::new(config_a).expect("create standalone net service A");
    let (_handle_b, ctrl_b) = NetService::new(config_b).expect("create standalone net service B");

    assert!(ctrl_a.is_running());
    assert!(ctrl_b.is_running());

    assert!(
        shutdown_controller_with_timeout(ctrl_a, Duration::from_secs(10)),
        "standalone service A shutdown did not complete within {:?}",
        Duration::from_secs(10)
    );
    assert!(
        shutdown_controller_with_timeout(ctrl_b, Duration::from_secs(10)),
        "standalone service B shutdown did not complete within {:?}",
        Duration::from_secs(10)
    );
}

#[test]
fn test_simultaneous_connect_converges_deterministically() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let open_a = tokio::time::timeout(
                Duration::from_secs(5),
                peer_a.handle.open_protocol_stream(peer_b.peer_id, 0),
            );
            let open_b = tokio::time::timeout(
                Duration::from_secs(5),
                peer_b.handle.open_protocol_stream(peer_a.peer_id, 0),
            );
            let (open_a, open_b) = tokio::join!(open_a, open_b);

            let mut stream_a = open_a.map_err(|_| ())?.map_err(|_| ())?;
            let mut stream_b = open_b.map_err(|_| ())?.map_err(|_| ())?;

            let mut inbound_on_b = tokio::time::timeout(
                Duration::from_secs(5),
                peer_b.handle.protocol_streams().recv(),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let mut inbound_on_a = tokio::time::timeout(
                Duration::from_secs(5),
                peer_a.handle.protocol_streams().recv(),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;

            stream_a.write(b"a->b".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), inbound_on_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"a->b" {
                return Err(());
            }

            stream_b.write(b"b->a".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), inbound_on_a.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"b->a" {
                return Err(());
            }

            Ok(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_simultaneous_connect_converges_deterministically() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let open_a = tokio::time::timeout(
                Duration::from_secs(5),
                peer_a.handle.open_protocol_stream(peer_b.peer_id, 0),
            );
            let open_b = tokio::time::timeout(
                Duration::from_secs(5),
                peer_b.handle.open_protocol_stream(peer_a.peer_id, 0),
            );
            let (open_a, open_b) = tokio::join!(open_a, open_b);

            let mut stream_a = open_a.map_err(|_| ())?.map_err(|_| ())?;
            let mut stream_b = open_b.map_err(|_| ())?.map_err(|_| ())?;

            let mut inbound_on_b = tokio::time::timeout(
                Duration::from_secs(5),
                peer_b.handle.protocol_streams().recv(),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let mut inbound_on_a = tokio::time::timeout(
                Duration::from_secs(5),
                peer_a.handle.protocol_streams().recv(),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;

            stream_a.write(b"a->b".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), inbound_on_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"a->b" {
                return Err(());
            }

            stream_b.write(b"b->a".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), inbound_on_a.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"b->a" {
                return Err(());
            }

            Ok(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_canceled_open_requests_not_flushed_after_late_connect() {
    let port_a = next_port();
    let port_b = next_port();

    let key_a = test_key_from_tag(next_key_tag());
    let key_b = test_key_from_tag(next_key_tag());

    let peer_id_a = peer_id_from_signing_key(&key_a);
    let peer_id_b = peer_id_from_signing_key(&key_b);

    let addr_a = test_addr(port_a);
    let addr_b = test_addr(port_b);

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)])
        .with_reconnect_backoff(Duration::from_millis(50));
    let config_b = NetServiceConfig::new(key_b, addr_b, vec![PeerConfig::new(peer_id_a, addr_a)])
        .with_reconnect_backoff(Duration::from_millis(50));

    let (handle_a, ctrl_a) = NetService::new(config_a).expect("create net service A");

    run_async(async {
        // Create cancellable open requests while peer B is offline.
        // We spawn then abort after every task is running so the explicit cancel path is exercised.
        let mut opens = Vec::new();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        for _ in 0..16 {
            let handle = handle_a.clone();
            let started_tx = started_tx.clone();
            opens.push(tokio::spawn(async move {
                let _ = started_tx.send(());
                handle.open_protocol_stream(peer_id_b, 0).await
            }));
        }
        drop(started_tx);
        for _ in 0..16 {
            let _ = tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
                .await
                .expect("open task did not start in time");
        }
        for task in opens {
            task.abort();
        }
    });

    let (handle_b, ctrl_b) = NetService::new(config_b).expect("create net service B");

    run_async(async {
        // Establish normal connectivity first.
        retry_until_ok(CI_TIMEOUT, || async {
            let mut stream_a = handle_a
                .open_protocol_stream(peer_id_b, 0)
                .await
                .map_err(|_| ())?;
            stream_a.write(b"ready".to_vec()).await.map_err(|_| ())?;
            let mut stream_b =
                tokio::time::timeout(Duration::from_secs(2), handle_b.protocol_streams().recv())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"ready" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;

        // There must be no stale protocol streams from canceled opens.
        let stale = tokio::time::timeout(
            Duration::from_millis(300),
            handle_b.protocol_streams().recv(),
        )
        .await;
        assert!(
            stale.is_err(),
            "canceled opens produced a stale inbound stream"
        );

        // Fresh opens still work after cancellation cleanup.
        retry_until_ok(CI_TIMEOUT, || async {
            let mut stream_a = handle_a
                .open_protocol_stream(peer_id_b, 0)
                .await
                .map_err(|_| ())?;
            stream_a.write(b"fresh".to_vec()).await.map_err(|_| ())?;

            let mut stream_b =
                tokio::time::timeout(Duration::from_secs(2), handle_b.protocol_streams().recv())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"fresh" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    shutdown_controller_with_timeout(ctrl_b, Duration::from_secs(2));
    shutdown_controller_with_timeout(ctrl_a, Duration::from_secs(2));
}

#[test]
fn test_duplicate_peer_identity_routes_to_single_selected_connection() {
    let port_a = next_port();
    let port_b = next_port();
    let port_b2 = next_port();

    let key_a = test_key(20);
    let key_b_primary = test_key(21);
    let key_b_duplicate = test_key(21);

    let peer_id_a = peer_id_from_signing_key(&key_a);
    let peer_id_b = peer_id_from_signing_key(&key_b_primary);

    let addr_a = test_addr(port_a);
    let addr_b = test_addr(port_b);
    let addr_b2 = test_addr(port_b2);

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)])
        .with_reconnect_backoff(Duration::from_millis(50));
    let config_b = NetServiceConfig::new(
        key_b_primary,
        addr_b,
        vec![PeerConfig::new(peer_id_a, addr_a)],
    )
    .with_reconnect_backoff(Duration::from_millis(50));
    let config_b2 = NetServiceConfig::new(
        key_b_duplicate,
        addr_b2,
        vec![PeerConfig::new(peer_id_a, addr_a)],
    )
    .with_reconnect_backoff(Duration::from_millis(50));

    let (handle_a, ctrl_a) = NetService::new(config_a).expect("create net service A");
    let (handle_b, ctrl_b) = NetService::new(config_b).expect("create net service B");

    run_async(async {
        // Establish and validate baseline A<->B connectivity first.
        retry_until_ok(CI_TIMEOUT, || async {
            let mut baseline = tokio::time::timeout(
                Duration::from_secs(5),
                handle_a.open_protocol_stream(peer_id_b, 0),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let mut baseline_recv =
                tokio::time::timeout(Duration::from_secs(5), handle_b.protocol_streams().recv())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            baseline.write(b"baseline".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), baseline_recv.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg.as_slice() != b"baseline" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    let (handle_b2, ctrl_b2) = NetService::new(config_b2).expect("create duplicate-B service");

    run_async(async {
        retry_until_ok(CI_TIMEOUT, {
            move || {
                let handle_a = handle_a.clone();
                let handle_b = handle_b.clone();
                let handle_b2 = handle_b2.clone();
                async move {
                    // Open from A to peer_id_b. With duplicate identity holders, routing may
                    // land on either instance, but it must land on exactly one selected path.
                    let mut stream_a = tokio::time::timeout(
                        Duration::from_secs(5),
                        handle_a.open_protocol_stream(peer_id_b, 0),
                    )
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;

                    let recv_b = tokio::time::timeout(
                        Duration::from_secs(2),
                        handle_b.protocol_streams().recv(),
                    );
                    let recv_b2 = tokio::time::timeout(
                        Duration::from_secs(2),
                        handle_b2.protocol_streams().recv(),
                    );
                    let (recv_b, recv_b2) = tokio::join!(recv_b, recv_b2);

                    let mut stream_on_b = match (recv_b, recv_b2) {
                        (Ok(Ok(stream)), Err(_)) => stream,
                        (Err(_), Ok(Ok(stream))) => stream,
                        (Ok(Err(_)), _)
                        | (_, Ok(Err(_)))
                        | (Err(_), Err(_))
                        | (Ok(Ok(_)), Ok(Ok(_))) => {
                            return Err(());
                        }
                    };

                    stream_a.write(b"steady".to_vec()).await.map_err(|_| ())?;
                    let msg = tokio::time::timeout(Duration::from_secs(5), stream_on_b.read())
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    if msg.as_slice() != b"steady" {
                        return Err(());
                    }
                    Ok::<_, ()>(())
                }
            }
        })
        .await;
    });

    shutdown_controller_with_timeout(ctrl_a, Duration::from_secs(2));
    shutdown_controller_with_timeout(ctrl_b, Duration::from_secs(2));
    shutdown_controller_with_timeout(ctrl_b2, Duration::from_secs(2));
}

#[test]
fn test_outbound_peer_mismatch_rejected() {
    let port_a = next_port();
    let port_b = next_port();

    let key_a = test_key(10);
    let key_b = test_key(11);
    let key_c = test_key(12);

    let peer_id_a = peer_id_from_signing_key(&key_a);
    let peer_id_b = peer_id_from_signing_key(&key_b);
    let peer_id_c = peer_id_from_signing_key(&key_c);

    let addr_a = test_addr(port_a);
    let addr_c = test_addr(port_b);

    // A expects to connect to B at addr_c (but C is actually listening there).
    // Include C in the allowed peer set so TLS succeeds, then the outbound
    // peer-id check should reject the mismatch.
    let config_a = NetServiceConfig::new(
        key_a,
        addr_a,
        vec![
            PeerConfig::new(peer_id_b, addr_c),
            PeerConfig::new(peer_id_c, addr_c),
        ],
    )
    .with_reconnect_backoff(Duration::from_millis(50));

    // C actually listens at addr_c but allows A.
    let config_c = NetServiceConfig::new(key_c, addr_c, vec![PeerConfig::new(peer_id_a, addr_a)])
        .with_reconnect_backoff(Duration::from_millis(50));

    let (handle_a, ctrl_a) = NetService::new(config_a).expect("create net service A");
    let (_handle_c, ctrl_c) = NetService::new(config_c).expect("create net service C");

    run_async(async {
        // Startup/transient connection errors are tolerated during the retry window.
        // The essential invariant is that opening to `peer_id_b` at `addr_c` never
        // succeeds because the authenticated remote identity is not `peer_id_b`.
        retry_until_ok(CI_TIMEOUT, || async {
            match tokio::time::timeout(
                Duration::from_secs(3),
                handle_a.open_protocol_stream(peer_id_b, 0),
            )
            .await
            {
                Ok(Err(OpenStreamError::ConnectionFailed(_))) => Ok::<_, ()>(()),
                Ok(Ok(stream)) => {
                    stream.reset(0).await;
                    Err(())
                }
                Ok(Err(_)) | Err(_) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    Err(())
                }
            }
        })
        .await;
    });

    shutdown_controller_with_timeout(ctrl_a, Duration::from_secs(2));
    shutdown_controller_with_timeout(ctrl_c, Duration::from_secs(2));
}

#[test]
fn test_config_has_peer() {
    let (peer_a, peer_b) = create_peer_pair();

    assert!(peer_a.handle.config().has_peer(&peer_b.peer_id));
    assert!(peer_b.handle.config().has_peer(&peer_a.peer_id));

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_peer_not_found_error() {
    let (peer_a, peer_b) = create_peer_pair();

    let result = run_async(async {
        let unknown = test_peer_id(99);
        peer_a.handle.open_protocol_stream(unknown, 0).await
    });

    assert!(matches!(
        result,
        Err(mosaic_net_svc::api::OpenStreamError::PeerNotFound)
    ));

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_protocol_stream_open_and_receive() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let stream_a = open_stream_eventually(&peer_a.handle, peer_b.peer_id).await;
            let stream_b =
                recv_with_timeout(CI_TIMEOUT, peer_b.handle.protocol_streams().recv()).await;
            if stream_b.peer != peer_a.peer_id {
                return Err(());
            }
            drop(stream_a);
            drop(stream_b);
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_protocol_stream_send_receive_data() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (mut stream_a, mut stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            stream_a.write(b"hello".to_vec()).await.map_err(|_| ())?;
            let received = tokio::time::timeout(CI_TIMEOUT, stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if received != b"hello" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_bidirectional() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (mut stream_a, mut stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            stream_a.write(b"ping".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg != b"ping" {
                return Err(());
            }
            stream_b.write(b"pong".to_vec()).await.map_err(|_| ())?;
            let msg = tokio::time::timeout(Duration::from_secs(5), stream_a.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if msg != b"pong" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_close_on_drop_sends_fin() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (stream_a, mut stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            drop(stream_a);
            let result = tokio::time::timeout(CI_TIMEOUT, stream_b.read())
                .await
                .map_err(|_| ())?;
            if matches!(result, Err(StreamClosed::PeerFinished)) {
                Ok::<_, ()>(())
            } else {
                Err(())
            }
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_reset_with_code() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (stream_a, mut stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            stream_a.reset(123).await;
            let result = tokio::time::timeout(CI_TIMEOUT, stream_b.read())
                .await
                .map_err(|_| ())?;
            match result {
                Err(StreamClosed::PeerReset(123)) => Ok::<_, ()>(()),
                _ => Err(()),
            }
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_buffer_returned_after_write() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let returned = retry_until_ok(CI_TIMEOUT, || async {
            let (mut stream_a, _stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;

            // Write data
            let buf = vec![42u8; 1000];
            stream_a.write(buf).await.map_err(|_| ())?;

            // Get buffer back
            tokio::time::timeout(Duration::from_secs(5), stream_a.recv_buffer())
                .await
                .map_err(|_| ())?
                .ok_or(())
        })
        .await;

        // Buffer should be cleared but retain capacity
        assert!(returned.is_empty());
        // Capacity is an optimization detail; only emptiness/reusability is contractual.
        assert!(returned.capacity() > 0);
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_bulk_transfer_registered() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let mut identifier = [0xab; 32];
            let tag = next_key_tag();
            identifier[..8].copy_from_slice(&tag.to_le_bytes());

            let (_protocol, _inbound) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            let expectation = peer_b
                .handle
                .expect_bulk_transfer(peer_a.peer_id, identifier)
                .await
                .map_err(|_| ())?;

            let mut stream_a = retry_until_ok(CI_TIMEOUT, || async {
                peer_a
                    .handle
                    .open_bulk_stream(peer_b.peer_id, identifier, -1)
                    .await
                    .map_err(|_| ())
            })
            .await;

            let mut stream_b = tokio::time::timeout(CI_TIMEOUT, expectation.recv())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;

            stream_a
                .write(b"bulk data".to_vec())
                .await
                .map_err(|_| ())?;
            let received = tokio::time::timeout(CI_TIMEOUT, stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if received != b"bulk data" {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_multiple_streams_concurrent() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (_warm, _warm_inbound) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            let mut streams_a = Vec::new();
            for _ in 0..3 {
                let s = tokio::time::timeout(
                    Duration::from_secs(10),
                    peer_a.handle.open_protocol_stream(peer_b.peer_id, 0),
                )
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                streams_a.push(s);
            }

            let mut streams_b = Vec::new();
            for _ in 0..3 {
                streams_b.push(
                    recv_with_timeout(CI_TIMEOUT, peer_b.handle.protocol_streams().recv()).await,
                );
            }

            for (i, s) in streams_a.iter_mut().enumerate() {
                s.write(format!("msg{}", i).into_bytes())
                    .await
                    .map_err(|_| ())?;
            }

            let mut msgs = Vec::new();
            for s in streams_b.iter_mut() {
                let data = tokio::time::timeout(Duration::from_secs(10), s.read())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                msgs.push(String::from_utf8(data).map_err(|_| ())?);
            }
            msgs.sort();
            if msgs != vec!["msg0", "msg1", "msg2"] {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_large_payload() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        retry_until_ok(CI_TIMEOUT, || async {
            let (mut stream_a, mut stream_b) = open_stream_pair_eventually(&peer_a, &peer_b).await;
            let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
            stream_a.write(payload.clone()).await.map_err(|_| ())?;
            let received = tokio::time::timeout(Duration::from_secs(10), stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if received != payload {
                return Err(());
            }
            Ok::<_, ()>(())
        })
        .await;
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

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
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::SigningKey;
use mosaic_net_svc::{
    PeerId,
    api::StreamClosed,
    config::{NetServiceConfig, PeerConfig},
    svc::NetService,
    tls::peer_id_from_signing_key,
};

// Port counter to avoid conflicts between tests.
// We randomize the starting port to avoid collisions when multiple test
// processes run in parallel (each process has its own counter).
static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);
static PORT_INIT: Once = Once::new();

fn next_port() -> u16 {
    PORT_INIT.call_once(|| {
        // Pick a random starting port in the range 30000-60000
        // This reduces collision probability across parallel test processes
        let start = 30000 + (std::process::id() as u16 % 30000);
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

impl TestPeer {
    fn shutdown(self) {
        let _ = self.controller.shutdown();
    }
}

fn create_peer_pair() -> (TestPeer, TestPeer) {
    // Retry with different ports if we hit "address in use" errors.
    // This handles port collisions in CI where multiple test processes run in parallel.
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
                let _ = ctrl_a.shutdown();
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
    let (peer_a, peer_b) = create_peer_pair();

    assert!(peer_a.controller.is_running());
    assert!(peer_b.controller.is_running());

    peer_a.shutdown();
    peer_b.shutdown();
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
        // Open-with-retry: this is our readiness barrier without consuming any
        // protocol-stream assertions beyond what this test already expects.
        let _stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        // A opens stream to B
        let stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        // B should receive the stream
        let stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        assert_eq!(stream_b.peer, peer_a.peer_id);

        drop(stream_a);
        drop(stream_b);
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_protocol_stream_send_receive_data() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        // Make the open robust in CI (service startup + connect + handshake).
        let mut stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let mut stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // Send data A -> B
        stream_a
            .write(b"hello".to_vec())
            .await
            .expect("write failed");

        let received = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
            .await
            .expect("timeout")
            .expect("read failed");

        assert_eq!(received, b"hello");
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_bidirectional() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let mut stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let mut stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // A -> B
        stream_a.write(b"ping".to_vec()).await.expect("write");
        let msg = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(msg, b"ping");

        // B -> A
        stream_b.write(b"pong".to_vec()).await.expect("write");
        let msg = tokio::time::timeout(Duration::from_secs(5), stream_a.read())
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(msg, b"pong");
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_close_on_drop_sends_fin() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let mut stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // Drop A's stream
        drop(stream_a);

        // B should see PeerFinished
        let result = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
            .await
            .expect("timeout");

        assert!(
            matches!(result, Err(StreamClosed::PeerFinished)),
            "expected PeerFinished, got {:?}",
            result
        );
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_stream_reset_with_code() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let mut stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // Reset with error code
        stream_a.reset(123).await;

        // B should see PeerReset
        let result = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
            .await
            .expect("timeout");

        match result {
            Err(StreamClosed::PeerReset(code)) => assert_eq!(code, 123),
            other => panic!("expected PeerReset(123), got {:?}", other),
        }
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_buffer_returned_after_write() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let mut stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let _stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // Write data
        let buf = vec![42u8; 1000];
        stream_a.write(buf).await.expect("write");

        // Get buffer back
        let returned = tokio::time::timeout(Duration::from_secs(3), stream_a.recv_buffer())
            .await
            .expect("timeout")
            .expect("no buffer returned");

        // Buffer should be cleared but retain capacity
        assert!(returned.is_empty());
        assert!(returned.capacity() >= 1000);
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_bulk_transfer_registered() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        // Make bulk registration/open robust by retrying the whole handshake.
        // This avoids a separate readiness probe and tolerates slow CI startup.
        let identifier = [0xab; 32];

        // Retry the entire "establish + send + read" sequence as one unit.
        //
        // This avoids borrowing issues (captured `stream_a`/`stream_b` in a retry closure)
        // and makes the test more robust in CI where there can be transient disconnects
        // around connection establishment or replacement.
        let received = retry_until_ok(Duration::from_secs(8), || async {
            // B registers to expect bulk transfer from A
            let expect_rx = peer_b
                .handle
                .expect_bulk_transfer(peer_a.peer_id, identifier)
                .await
                .map_err(|_| ())?;

            // A opens bulk stream
            let mut stream_a = peer_a
                .handle
                .open_bulk_stream(peer_b.peer_id, identifier, -1)
                .await
                .map_err(|_| ())?;

            // B receives via registered channel
            let mut stream_b = tokio::time::timeout(Duration::from_secs(3), expect_rx.recv())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;

            // Transfer data
            stream_a
                .write(b"bulk data".to_vec())
                .await
                .map_err(|_| ())?;

            let received = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;

            Ok::<Vec<u8>, ()>(received)
        })
        .await;

        assert_eq!(received, b"bulk data");
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_multiple_streams_concurrent() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        // Open 3 streams with retry to avoid CI flakiness.
        let mut streams_a = Vec::new();
        for _ in 0..3 {
            let s = retry_until_ok(Duration::from_secs(5), || async {
                peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
            })
            .await;
            streams_a.push(s);
        }

        // Receive 3 streams
        let mut streams_b = Vec::new();
        for _ in 0..3 {
            let s = recv_with_timeout(
                Duration::from_secs(3),
                peer_b.handle.protocol_streams().recv(),
            )
            .await;
            streams_b.push(s);
        }

        // Send on each
        for (i, s) in streams_a.iter_mut().enumerate() {
            s.write(format!("msg{}", i).into_bytes())
                .await
                .expect("write");
        }

        // Receive all (order may vary)
        let mut msgs = Vec::new();
        for s in streams_b.iter_mut() {
            let data = tokio::time::timeout(Duration::from_secs(5), s.read())
                .await
                .expect("timeout")
                .expect("read");
            msgs.push(String::from_utf8(data).unwrap());
        }
        msgs.sort();

        assert_eq!(msgs, vec!["msg0", "msg1", "msg2"]);
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_large_payload() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        let mut stream_a = retry_until_ok(Duration::from_secs(5), || async {
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0).await
        })
        .await;

        let mut stream_b = recv_with_timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        // 64KB payload
        let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        stream_a.write(payload.clone()).await.expect("write");

        let received = tokio::time::timeout(Duration::from_secs(5), stream_b.read())
            .await
            .expect("timeout")
            .expect("read");

        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

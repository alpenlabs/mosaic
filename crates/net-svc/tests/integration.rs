//! Integration tests for net-svc.
//!
//! These tests verify connectivity, stream communication, and error handling.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use net_svc::{
    PeerId,
    api::StreamClosed,
    config::{NetServiceConfig, PeerConfig},
    svc::NetService,
    tls::peer_id_from_signing_key,
};

// Port counter to avoid conflicts between tests
static PORT_COUNTER: AtomicU16 = AtomicU16::new(19000);

fn next_port() -> u16 {
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
    handle: net_svc::NetServiceHandle,
    controller: net_svc::svc::NetServiceController,
    peer_id: PeerId,
}

impl TestPeer {
    fn shutdown(self) {
        let _ = self.controller.shutdown();
    }
}

fn create_peer_pair() -> (TestPeer, TestPeer) {
    let port_a = next_port();
    let port_b = next_port();

    let key_a = test_key(1);
    let key_b = test_key(2);

    let peer_id_a = peer_id_from_signing_key(&key_a);
    let peer_id_b = peer_id_from_signing_key(&key_b);

    let addr_a = test_addr(port_a);
    let addr_b = test_addr(port_b);

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)])
        .with_reconnect_backoff(Duration::from_millis(50));

    let config_b = NetServiceConfig::new(key_b, addr_b, vec![PeerConfig::new(peer_id_a, addr_a)])
        .with_reconnect_backoff(Duration::from_millis(50));

    let (handle_a, ctrl_a) = NetService::new(config_a);
    let (handle_b, ctrl_b) = NetService::new(config_b);

    (
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
    )
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
        Err(net_svc::api::OpenStreamError::PeerNotFound)
    ));

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_protocol_stream_open_and_receive() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        // Give services time to connect
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A opens stream to B
        let stream_a_result = tokio::time::timeout(
            Duration::from_secs(3),
            peer_a.handle.open_protocol_stream(peer_b.peer_id, 0),
        )
        .await;

        let stream_a = stream_a_result
            .expect("timeout opening stream")
            .expect("failed to open stream");

        // B should receive the stream
        let stream_b_result = tokio::time::timeout(
            Duration::from_secs(3),
            peer_b.handle.protocol_streams().recv(),
        )
        .await;

        let stream_b = stream_b_result
            .expect("timeout receiving stream")
            .expect("failed to receive stream");

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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let mut stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

        // Send data A -> B
        stream_a
            .write(b"hello".to_vec())
            .await
            .expect("write failed");

        let received = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let mut stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

        // A -> B
        stream_a.write(b"ping".to_vec()).await.expect("write");
        let msg = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(msg, b"ping");

        // B -> A
        stream_b.write(b"pong".to_vec()).await.expect("write");
        let msg = tokio::time::timeout(Duration::from_secs(2), stream_a.read())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let mut stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

        // Drop A's stream
        drop(stream_a);

        // B should see PeerFinished
        let result = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let mut stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

        // Reset with error code
        stream_a.reset(123).await;

        // B should see PeerReset
        let result = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let _stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

        // Write data
        let buf = vec![42u8; 1000];
        stream_a.write(buf).await.expect("write");

        // Get buffer back
        let returned = tokio::time::timeout(Duration::from_secs(2), stream_a.recv_buffer())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let identifier = [0xab; 32];

        // B registers to expect bulk transfer from A
        let expect_rx = peer_b
            .handle
            .expect_bulk_transfer(peer_a.peer_id, identifier)
            .await
            .expect("register bulk");

        // A opens bulk stream
        let mut stream_a = peer_a
            .handle
            .open_bulk_stream(peer_b.peer_id, identifier, -1)
            .await
            .expect("open bulk stream");

        // B receives via registered channel
        let mut stream_b = tokio::time::timeout(Duration::from_secs(3), expect_rx.recv())
            .await
            .expect("timeout")
            .expect("recv bulk stream");

        // Transfer data
        stream_a.write(b"bulk data".to_vec()).await.expect("write");

        let received = tokio::time::timeout(Duration::from_secs(2), stream_b.read())
            .await
            .expect("timeout")
            .expect("read");

        assert_eq!(received, b"bulk data");
    });

    peer_a.shutdown();
    peer_b.shutdown();
}

#[test]
fn test_multiple_streams_concurrent() {
    let (peer_a, peer_b) = create_peer_pair();

    run_async(async {
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Open 3 streams
        let mut streams_a = Vec::new();
        for _ in 0..3 {
            let s = peer_a
                .handle
                .open_protocol_stream(peer_b.peer_id, 0)
                .await
                .expect("open stream");
            streams_a.push(s);
        }

        // Receive 3 streams
        let mut streams_b = Vec::new();
        for _ in 0..3 {
            let s = tokio::time::timeout(
                Duration::from_secs(2),
                peer_b.handle.protocol_streams().recv(),
            )
            .await
            .expect("timeout")
            .expect("recv");
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
            let data = tokio::time::timeout(Duration::from_secs(2), s.read())
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut stream_a = peer_a
            .handle
            .open_protocol_stream(peer_b.peer_id, 0)
            .await
            .expect("open stream");

        let mut stream_b = tokio::time::timeout(
            Duration::from_secs(2),
            peer_b.handle.protocol_streams().recv(),
        )
        .await
        .expect("timeout")
        .expect("recv stream");

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

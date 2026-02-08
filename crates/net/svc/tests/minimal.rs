//! Unit tests for core components of net-svc.
//!
//! These tests verify fundamental building blocks work correctly:
//! - Cross-thread channel communication
//! - Tokio runtime in spawned threads
//! - Service creation and shutdown
//! - QUIC endpoint binding

use std::time::Duration;

use mosaic_net_svc::close_codes::CLOSE_NORMAL;

#[test]
fn test_channel_across_threads() {
    // Verify kanal channels work correctly across thread boundaries
    let (tx, rx) = kanal::bounded(1);

    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        tx.send(42).unwrap();
    });

    let received = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(received, 42);
    handle.join().unwrap();
}

#[test]
fn test_tokio_runtime_in_thread() {
    // Verify we can create a tokio runtime in a spawned thread
    // This is the pattern used by NetService
    let (tx, rx) = kanal::bounded(1);

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.send(42).unwrap();
        });
    });

    let received = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(received, 42);
    handle.join().unwrap();
}

#[test]
fn test_service_creation_and_shutdown() {
    // Test creating a service with a peer configured and shutting it down
    use ed25519_dalek::SigningKey;
    use mosaic_net_svc::{
        config::{NetServiceConfig, PeerConfig},
        svc::NetService,
        tls::peer_id_from_signing_key,
    };

    let key_a = SigningKey::from_bytes(&[1u8; 32]);
    let key_b = SigningKey::from_bytes(&[2u8; 32]);

    let peer_id_b = peer_id_from_signing_key(&key_b);

    let addr_a: std::net::SocketAddr = "127.0.0.1:29000".parse().unwrap();
    let addr_b: std::net::SocketAddr = "127.0.0.1:29001".parse().unwrap();

    let config_a = NetServiceConfig::new(key_a, addr_a, vec![PeerConfig::new(peer_id_b, addr_b)]);

    let (handle_a, ctrl_a) = NetService::new(config_a).expect("create net service A");
    assert!(ctrl_a.is_running());

    // Give service time to start
    std::thread::sleep(Duration::from_millis(500));
    assert!(ctrl_a.is_running());

    // Verify config access works
    assert!(handle_a.config().has_peer(&peer_id_b));

    // Shutdown should complete promptly
    let result = ctrl_a.shutdown();
    assert!(result.is_ok());
}

#[test]
fn test_service_no_peers() {
    // Test service with no peers - verifies basic lifecycle works
    use ed25519_dalek::SigningKey;
    use mosaic_net_svc::{config::NetServiceConfig, svc::NetService};

    let key = SigningKey::from_bytes(&[1u8; 32]);
    let addr: std::net::SocketAddr = "127.0.0.1:29050".parse().unwrap();

    let config = NetServiceConfig::new(key, addr, vec![]);

    let (_handle, ctrl) = NetService::new(config).expect("create net service");
    assert!(ctrl.is_running());

    std::thread::sleep(Duration::from_millis(500));
    assert!(ctrl.is_running());

    let result = ctrl.shutdown();
    assert!(result.is_ok());
}

#[test]
fn test_endpoint_bind() {
    // Test that we can bind a QUIC endpoint directly
    use ed25519_dalek::SigningKey;
    use mosaic_net_svc::tls;

    let key = SigningKey::from_bytes(&[1u8; 32]);
    let peer_id = tls::peer_id_from_signing_key(&key);

    let server_config = tls::make_server_config(&key, vec![peer_id]).unwrap();

    let addr: std::net::SocketAddr = "127.0.0.1:29010".parse().unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let endpoint = quinn::Endpoint::server(server_config, addr).expect("bind endpoint");
        endpoint.close(CLOSE_NORMAL, b"test");
        endpoint.wait_idle().await;
    });
}

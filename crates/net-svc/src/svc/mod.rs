//! Network service implementation.
//!
//! This module contains the core network service that manages QUIC connections
//! and streams. It runs on a dedicated thread with its own tokio runtime.
//!
//! # Design Principles
//!
//! The main event loop NEVER blocks on I/O. It only:
//! - Receives from channels (instant)
//! - Updates in-memory state (instant)
//! - Spawns tasks (instant)
//!
//! All network I/O and potentially-blocking channel sends happen in spawned tasks.

mod conn;
mod handlers;
mod state;
mod stream;
mod tasks;

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ahash::{HashMap, HashMapExt};
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use quinn::{Endpoint, ServerConfig};
use tokio::runtime::Builder;

use crate::api::{NetCommand, NetServiceHandle, Stream};
use crate::config::NetServiceConfig;
use crate::tls::{self, PeerId};

use state::{ServiceEvent, ServiceState};

/// Handle to control the network service.
pub struct NetServiceController {
    /// Thread handle for joining.
    thread_handle: Option<JoinHandle<Result<(), ServiceError>>>,
    /// Shutdown signal sender.
    shutdown_tx: AsyncSender<()>,
}

impl NetServiceController {
    /// Signal the service to shut down and wait for it to finish.
    pub fn shutdown(mut self) -> Result<(), ServiceError> {
        // Send shutdown signal using blocking send (ignore error if already closed)
        let _ = self.shutdown_tx.clone().to_sync().send(());

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            handle.join().map_err(|_| ServiceError::ThreadPanicked)?
        } else {
            Ok(())
        }
    }

    /// Check if the service thread is still running.
    pub fn is_running(&self) -> bool {
        self.thread_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for NetServiceController {
    fn drop(&mut self) {
        // Signal shutdown on drop using blocking send
        let _ = self.shutdown_tx.clone().to_sync().try_send(());
    }
}

/// Error from the network service.
#[derive(Debug)]
pub enum ServiceError {
    /// Failed to create QUIC endpoint.
    EndpointCreation(String),
    /// Failed to create TLS config.
    TlsConfig(String),
    /// Service thread panicked.
    ThreadPanicked,
    /// Runtime creation failed.
    RuntimeCreation(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointCreation(e) => write!(f, "failed to create endpoint: {}", e),
            Self::TlsConfig(e) => write!(f, "failed to create TLS config: {}", e),
            Self::ThreadPanicked => write!(f, "service thread panicked"),
            Self::RuntimeCreation(e) => write!(f, "failed to create runtime: {}", e),
        }
    }
}

impl std::error::Error for ServiceError {}

/// The network service.
///
/// Manages QUIC connections to peers and provides stream-based communication.
/// Runs on a dedicated thread with its own tokio runtime.
pub struct NetService;

impl NetService {
    /// Create and start the network service.
    ///
    /// Returns a handle for interacting with the service and a controller for shutdown.
    /// This intentionally doesn't return `Self` since `NetService` is a namespace struct.
    #[allow(clippy::new_ret_no_self)]
    ///
    /// Spawns a background thread running a tokio runtime. Returns a handle
    /// to interact with the service and a controller to shut it down.
    ///
    /// Connections to all configured peers are attempted immediately and
    /// maintained continuously with automatic reconnection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (handle, controller) = NetService::new(config);
    ///
    /// // Use handle from any thread
    /// let stream = handle.open_protocol_stream(peer_id, 0).await?;
    ///
    /// // Later, shut down gracefully
    /// controller.shutdown()?;
    /// ```
    pub fn new(config: NetServiceConfig) -> (NetServiceHandle, NetServiceController) {
        let config = Arc::new(config);

        // Command channel (handles -> service)
        let (command_tx, command_rx) = bounded_async(64);

        // Protocol stream channel (service -> handles)
        let (protocol_stream_tx, protocol_stream_rx) = bounded_async(64);

        // Shutdown channel
        let (shutdown_tx, shutdown_rx) = bounded_async(1);

        let handle = NetServiceHandle::new(config.clone(), command_tx, protocol_stream_rx);

        // Clone for the thread
        let shutdown_tx_clone = shutdown_tx.clone();

        let thread_handle = thread::Builder::new()
            .name("net-svc".to_string())
            .spawn(move || run_service(config, command_rx, protocol_stream_tx, shutdown_rx))
            .expect("failed to spawn net-svc thread");

        let controller = NetServiceController {
            thread_handle: Some(thread_handle),
            shutdown_tx: shutdown_tx_clone,
        };

        (handle, controller)
    }
}

/// Run the network service (called on the spawned thread).
fn run_service(
    config: Arc<NetServiceConfig>,
    command_rx: AsyncReceiver<NetCommand>,
    protocol_stream_tx: AsyncSender<Stream>,
    shutdown_rx: AsyncReceiver<()>,
) -> Result<(), ServiceError> {
    // Create single-threaded tokio runtime
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ServiceError::RuntimeCreation(e.to_string()))?;

    runtime.block_on(run_service_async(
        config,
        command_rx,
        protocol_stream_tx,
        shutdown_rx,
    ))
}

/// Async main loop.
async fn run_service_async(
    config: Arc<NetServiceConfig>,
    command_rx: AsyncReceiver<NetCommand>,
    protocol_stream_tx: AsyncSender<Stream>,
    shutdown_rx: AsyncReceiver<()>,
) -> Result<(), ServiceError> {
    // Create TLS configs
    let peer_ids: Vec<PeerId> = config.peer_ids().copied().collect();
    let server_config = tls::make_server_config(&config.signing_key, peer_ids.clone())
        .map_err(|e| ServiceError::TlsConfig(e.to_string()))?;

    // Apply transport config (keep-alive)
    let server_config = apply_transport_config(server_config, &config);

    // Create QUIC endpoint
    let endpoint = Endpoint::server(server_config, config.bind_addr)
        .map_err(|e| ServiceError::EndpointCreation(e.to_string()))?;

    // Create client config for outbound connections
    let client_config = tls::make_client_config(&config.signing_key, peer_ids)
        .map_err(|e| ServiceError::TlsConfig(e.to_string()))?;

    // Internal event channel for tasks to communicate back to main loop
    let (event_tx, event_rx) = bounded_async::<ServiceEvent>(256);

    // Main service state (owned by this task, no mutex needed)
    let mut state = ServiceState {
        config: config.clone(),
        endpoint: endpoint.clone(),
        client_config,
        connections: HashMap::new(),
        bulk_expectations: HashMap::new(),
        protocol_stream_tx,
        pending_reconnects: Vec::new(),
        connecting: hashbrown::HashSet::new(),
        pending_stream_requests: HashMap::new(),
        event_tx: event_tx.clone(),
    };

    // Schedule initial connections to all peers
    let now = tokio::time::Instant::now();
    for peer_config in config.peers.iter() {
        state.pending_reconnects.push((peer_config.peer_id, now));
    }

    // Reconnect ticker (check every second)
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
    reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(
        bind_addr = %config.bind_addr,
        peer_count = state.config.peers.len(),
        "network service started"
    );

    // Main event loop - NEVER blocks on I/O, only receives and dispatches
    loop {
        tokio::select! {
            biased;  // Always check shutdown first

            // Handle shutdown signal - highest priority
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown signal received");
                break;
            }

            // Accept incoming connections - just spawns task, doesn't await handshake
            Some(incoming) = endpoint.accept() => {
                tasks::spawn_incoming_connection_handler(
                    incoming,
                    state.config.peer_ids().copied().collect(),
                    event_tx.clone(),
                );
            }

            // Handle commands from handles - dispatches to tasks, never blocks
            Ok(cmd) = command_rx.recv() => {
                handlers::handle_command(cmd, &mut state);
            }

            // Handle events from spawned tasks - just updates state, never blocks
            Ok(event) = event_rx.recv() => {
                handlers::handle_event(event, &mut state);
            }

            // Periodic reconnection attempts - spawns tasks, doesn't await
            _ = reconnect_interval.tick() => {
                handlers::process_pending_reconnects(&mut state);
            }
        }
    }

    // Graceful shutdown
    tracing::info!("shutting down network service");

    // Close all active connections - this will cause connection monitors to exit
    for (_peer, conn) in state.connections.drain() {
        conn.close(0u32.into(), b"shutdown");
    }

    // Clear pending state
    state.pending_reconnects.clear();
    state.connecting.clear();
    state.pending_stream_requests.clear();

    // Close endpoint
    endpoint.close(0u32.into(), b"shutdown");

    // Brief wait for cleanup
    let _ = tokio::time::timeout(Duration::from_millis(100), endpoint.wait_idle()).await;

    tracing::info!("network service shut down");
    Ok(())
}

/// Apply transport configuration (keep-alive, etc.) to server config.
fn apply_transport_config(
    mut server_config: ServerConfig,
    config: &NetServiceConfig,
) -> ServerConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(config.keep_alive_interval));
    server_config.transport_config(Arc::new(transport));
    server_config
}

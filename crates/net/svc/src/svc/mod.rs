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
//!
//! # Startup semantics
//!
//! `NetService::new` returns `Result` and uses a startup handshake so callers
//! can fail fast on endpoint/TLS/runtime errors instead of later seeing
//! `ServiceDown` when issuing commands.

mod conn;
mod handlers;
mod state;
mod stream;
mod tasks;

use std::{
    collections::HashSet,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use ahash::{HashMap, HashMapExt};
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use quinn::{Endpoint, ServerConfig};
use state::{ServiceEvent, ServiceState, TrackedConnection};
use tokio::runtime::Builder;

use crate::{
    api::{NetCommand, NetServiceHandle, Stream},
    config::NetServiceConfig,
    tls::{self, PeerId},
};

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
    /// Startup handshake channel failed (unexpected internal error).
    ///
    /// This generally indicates the service thread panicked or exited before it
    /// could report startup success/failure back to the constructor.
    StartupHandshakeFailed,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointCreation(e) => write!(f, "failed to create endpoint: {}", e),
            Self::TlsConfig(e) => write!(f, "failed to create TLS config: {}", e),
            Self::ThreadPanicked => write!(f, "service thread panicked"),
            Self::RuntimeCreation(e) => write!(f, "failed to create runtime: {}", e),
            Self::StartupHandshakeFailed => write!(f, "startup handshake failed"),
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
    /// let (handle, controller) = NetService::new(config)?;
    ///
    /// // Use handle from any thread
    /// let stream = handle.open_protocol_stream(peer_id, 0).await?;
    ///
    /// // Later, shut down gracefully
    /// controller.shutdown()?;
    /// ```
    pub fn new(
        config: NetServiceConfig,
    ) -> Result<(NetServiceHandle, NetServiceController), ServiceError> {
        let config = Arc::new(config);

        // Precompute allowed peers set once (avoid per-accept allocation).
        let allowed_peers: Arc<HashSet<PeerId>> = Arc::new(config.peer_ids().copied().collect());

        // Command channel (handles -> service)
        let (command_tx, command_rx) = bounded_async(64);

        // Protocol stream channel (service -> handles)
        let (protocol_stream_tx, protocol_stream_rx) = bounded_async(64);

        // Shutdown channel
        let (shutdown_tx, shutdown_rx) = bounded_async(1);

        // Startup handshake: service thread reports readiness or startup error.
        // Bounded(1) so send is infallible unless receiver is dropped.
        let (startup_tx, startup_rx) = bounded_async::<Result<(), ServiceError>>(1);

        let handle = NetServiceHandle::new(config.clone(), command_tx, protocol_stream_rx);

        // Clone for the thread
        let shutdown_tx_clone = shutdown_tx.clone();

        let thread_handle = thread::Builder::new()
            .name("net-svc".to_string())
            .spawn(move || {
                run_service(
                    config,
                    allowed_peers,
                    command_rx,
                    protocol_stream_tx,
                    shutdown_rx,
                    startup_tx,
                )
            })
            .expect("failed to spawn net-svc thread");

        // Wait for startup handshake.
        //
        // This makes endpoint/TLS/runtime failures deterministic and immediate
        // for callers of `NetService::new`.
        match startup_rx.to_sync().recv() {
            Ok(Ok(())) => {
                let controller = NetServiceController {
                    thread_handle: Some(thread_handle),
                    shutdown_tx: shutdown_tx_clone,
                };
                Ok((handle, controller))
            }
            Ok(Err(e)) => {
                // Thread may have already exited; ensure we join to avoid leaks.
                let _ = thread_handle.join();
                Err(e)
            }
            Err(_) => {
                // Startup channel closed before we got a result.
                // Join the thread and, if it returned an error, surface it instead
                // of a generic handshake failure.
                match thread_handle.join() {
                    Ok(Ok(())) => Err(ServiceError::StartupHandshakeFailed),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(ServiceError::ThreadPanicked),
                }
            }
        }
    }
}

/// Run the network service (called on the spawned thread).
fn run_service(
    config: Arc<NetServiceConfig>,
    allowed_peers: Arc<HashSet<PeerId>>,
    command_rx: AsyncReceiver<NetCommand>,
    protocol_stream_tx: AsyncSender<Stream>,
    shutdown_rx: AsyncReceiver<()>,
    startup_tx: AsyncSender<Result<(), ServiceError>>,
) -> Result<(), ServiceError> {
    // Create single-threaded tokio runtime
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = startup_tx
                .to_sync()
                .send(Err(ServiceError::RuntimeCreation(e.to_string())));
            return Err(ServiceError::RuntimeCreation(e.to_string()));
        }
    };

    runtime.block_on(run_service_async(
        config,
        allowed_peers,
        command_rx,
        protocol_stream_tx,
        shutdown_rx,
        startup_tx,
    ))
}

/// Async main loop.
async fn run_service_async(
    config: Arc<NetServiceConfig>,
    allowed_peers: Arc<HashSet<PeerId>>,
    command_rx: AsyncReceiver<NetCommand>,
    protocol_stream_tx: AsyncSender<Stream>,
    shutdown_rx: AsyncReceiver<()>,
    startup_tx: AsyncSender<Result<(), ServiceError>>,
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

    // Signal successful startup now that endpoint + TLS config are created.
    let _ = startup_tx.send(Ok(())).await;

    // Internal event channel for tasks to communicate back to main loop
    let (event_tx, event_rx) = bounded_async::<ServiceEvent>(256);

    // Main service state (owned by this task, no mutex needed)
    let mut state = ServiceState {
        config: config.clone(),
        endpoint: endpoint.clone(),
        client_config,
        connections: HashMap::<PeerId, TrackedConnection>::new(),
        bulk_expectations: HashMap::new(),
        protocol_stream_tx,
        pending_reconnects: Vec::new(),
        connecting: hashbrown::HashSet::new(),
        pending_stream_requests: HashMap::new(),
        event_tx: event_tx.clone(),
    };

    // Schedule initial connections to all peers.
    //
    // NOTE: We also need to arm the reconnect timer based on the earliest deadline.
    let now = tokio::time::Instant::now();
    for peer_config in config.peers.iter() {
        state.pending_reconnects.push((peer_config.peer_id, now));
    }

    // Reconnect timer (deadline-driven).
    //
    // Using a fixed 1s ticker makes reconnection effectively quantized to 1s even if
    // `reconnect_backoff` is much smaller. Instead, drive reconnect attempts off the
    // earliest pending reconnect deadline.
    let reconnect_sleep = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(reconnect_sleep);

    // Arm reconnect timer for the first time.
    if let Some((_peer, next)) = state.pending_reconnects.iter().min_by_key(|(_p, t)| *t) {
        reconnect_sleep.as_mut().reset(*next);
    } else {
        // No reconnects pending; sleep far in the future.
        reconnect_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(3600));
    }

    tracing::info!(
        bind_addr = %config.bind_addr,
        peer_count = state.config.peers.len(),
        "network service started"
    );

    // Main event loop - NEVER blocks on I/O, only receives and dispatches
    loop {
        // Re-arm reconnect timer each iteration based on the earliest pending deadline.
        // (Cheap: peer counts are small; if this grows, we can switch to a binary heap.)
        if let Some((_peer, next)) = state.pending_reconnects.iter().min_by_key(|(_p, t)| *t) {
            reconnect_sleep.as_mut().reset(*next);
        } else {
            // No reconnects pending; sleep far in the future.
            reconnect_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(3600));
        }

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
                    allowed_peers.clone(),
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

            // Deadline-driven reconnection attempts - spawns tasks, doesn't await.
            _ = &mut reconnect_sleep => {
                handlers::process_pending_reconnects(&mut state);
            }
        }
    }

    // Graceful shutdown
    tracing::info!("shutting down network service");

    // Close all active connections - this will cause connection monitors to exit
    for (_peer, conn) in state.connections.drain() {
        conn.connection.close(0u32.into(), b"shutdown");
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

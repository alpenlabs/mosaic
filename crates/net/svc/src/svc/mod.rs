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
use state::{OpenRequestCancelRegistry, PeerConnectionState, ServiceEvent, ServiceState};
use tokio::runtime::Builder;

use crate::{
    api::{InboundProtocolStream, NetCommand, NetServiceHandle},
    close_codes::CLOSE_NORMAL,
    config::NetServiceConfig,
    tls::{self, PeerId},
};

/// Transport-level limits and timeouts.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 100;
const MAX_CONCURRENT_UNI_STREAMS: u32 = 0;

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
    protocol_stream_tx: AsyncSender<InboundProtocolStream>,
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
    protocol_stream_tx: AsyncSender<InboundProtocolStream>,
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
    let client_config = apply_client_transport_config(client_config, &config);

    // Signal successful startup now that endpoint + TLS config are created.
    let _ = startup_tx.send(Ok(())).await;

    // Internal event channel for spawned tasks to communicate back to main loop.
    // Unbounded is used to prevent race-resolution liveness from depending on
    // bounded internal backpressure.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<ServiceEvent>();

    // Main service state (owned by this task, no mutex needed)
    let mut state = ServiceState {
        config: config.clone(),
        endpoint: endpoint.clone(),
        client_config,
        peer_states: HashMap::<PeerId, PeerConnectionState>::new(),
        bulk_expectations: HashMap::new(),
        protocol_stream_tx,
        pending_reconnects: Vec::new(),
        pending_stream_requests: HashMap::new(),
        open_request_states: HashMap::new(),
        in_flight_open_responders: HashMap::new(),
        open_request_cancels: Arc::new(OpenRequestCancelRegistry::new()),
        pending_incoming_by_id: HashMap::new(),
        pending_incoming_by_peer: HashMap::new(),
        resolved_incoming_candidate_ids: ahash::HashSet::default(),
        event_tx: event_tx.clone(),
        next_outbound_attempt_id: 1,
        next_overlap_key: 1,
        next_connection_generation: 1,
        resolved_outbound_attempt_by_peer: HashMap::new(),
    };

    // Schedule initial connections to all peers.
    let now = tokio::time::Instant::now();
    for peer_config in config.peers.iter() {
        state
            .peer_states
            .entry(peer_config.peer_id)
            .or_insert(PeerConnectionState::Idle);
        state.pending_reconnects.push((peer_config.peer_id, now));
    }

    // Reconnect timer (deadline-driven).
    //
    // Using a fixed 1s ticker makes reconnection effectively quantized to 1s even if
    // `reconnect_backoff` is much smaller. Instead, drive reconnect attempts off the
    // earliest pending reconnect deadline.
    let reconnect_sleep = tokio::time::sleep(handlers::idle_housekeeping_sleep());
    tokio::pin!(reconnect_sleep);

    // Arm housekeeping timer for the first time.
    if let Some(next) = handlers::next_wakeup_deadline(&state) {
        reconnect_sleep.as_mut().reset(next);
    } else {
        reconnect_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + handlers::idle_housekeeping_sleep());
    }

    tracing::info!(
        bind_addr = %config.bind_addr,
        peer_count = state.config.peers.len(),
        "network service started"
    );

    let mut addr_candidates = HashMap::<std::net::SocketAddr, Option<PeerId>>::new();
    let mut port_candidates = HashMap::<u16, Option<PeerId>>::new();
    let mut ip_candidates = HashMap::<std::net::IpAddr, Option<PeerId>>::new();
    for peer in state.config.peers.iter() {
        let normalized = tasks::normalize_socket_addr(peer.addr);
        addr_candidates
            .entry(normalized)
            .and_modify(|slot| *slot = None)
            .or_insert(Some(peer.peer_id));
        port_candidates
            .entry(normalized.port())
            .and_modify(|slot| *slot = None)
            .or_insert(Some(peer.peer_id));
        ip_candidates
            .entry(normalized.ip())
            .and_modify(|slot| *slot = None)
            .or_insert(Some(peer.peer_id));
    }
    let peer_by_addr = Arc::new(
        addr_candidates
            .into_iter()
            .filter_map(|(addr, maybe_peer)| maybe_peer.map(|peer| (addr, peer)))
            .collect::<HashMap<_, _>>(),
    );
    let peer_by_port = Arc::new(
        port_candidates
            .into_iter()
            .filter_map(|(port, maybe_peer)| maybe_peer.map(|peer| (port, peer)))
            .collect::<HashMap<_, _>>(),
    );
    let peer_by_ip = Arc::new(
        ip_candidates
            .into_iter()
            .filter_map(|(ip, maybe_peer)| maybe_peer.map(|peer| (ip, peer)))
            .collect::<HashMap<_, _>>(),
    );

    // Dedicated accept loop so accept timestamps are captured at source.
    tasks::spawn_accept_loop(
        endpoint.clone(),
        allowed_peers.clone(),
        peer_by_addr,
        peer_by_port,
        peer_by_ip,
        event_tx.clone(),
    );

    // Main event loop - NEVER blocks on I/O, only receives and dispatches
    loop {
        // Re-arm timer from the earliest reconnect deadline.
        if let Some(next) = handlers::next_wakeup_deadline(&state) {
            reconnect_sleep.as_mut().reset(next);
        } else {
            reconnect_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + handlers::idle_housekeeping_sleep());
        }

        // Fair select for command/event processing to avoid starvation.
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown signal received");
                break;
            }

            // Deadline-driven reconnect housekeeping.
            _ = &mut reconnect_sleep => {
                tracing::trace!(
                    pending_reconnects = state.pending_reconnects.len(),
                    "running reconnect housekeeping"
                );
                handlers::process_pending_reconnects(&mut state);
            }

            // Handle commands from handles - dispatches to tasks, never blocks
            Ok(cmd) = command_rx.recv() => {
                tracing::trace!("received network service command");
                handlers::handle_command(cmd, &mut state);
            }

            // Handle events from spawned tasks - just updates state, never blocks
            Some(event) = event_rx.recv() => {
                tracing::trace!("received network service task event");
                handlers::handle_event(event, &mut state);
            }
        }
    }

    // Graceful shutdown
    tracing::info!("shutting down network service");

    // Close active/provisional connections - this will cause monitors to exit.
    for (_peer, conn_state) in state.peer_states.drain() {
        match conn_state {
            PeerConnectionState::ActiveStable { connection } => {
                if connection.connection.close_reason().is_none() {
                    connection.connection.close(CLOSE_NORMAL, b"shutdown");
                }
            }
            PeerConnectionState::Race { provisional, .. } => {
                if provisional.connection.close_reason().is_none() {
                    provisional.connection.close(CLOSE_NORMAL, b"shutdown");
                }
            }
            PeerConnectionState::Idle | PeerConnectionState::ConnectingOutbound { .. } => {}
        }
    }

    // Clear pending state
    state.pending_reconnects.clear();
    state.pending_stream_requests.clear();
    state.open_request_states.clear();

    // Close endpoint
    endpoint.close(CLOSE_NORMAL, b"shutdown");

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
    let transport = build_transport_config(config);
    server_config.transport_config(Arc::new(transport));
    server_config
}

/// Apply transport configuration to a client config.
fn apply_client_transport_config(
    mut client_config: quinn::ClientConfig,
    config: &NetServiceConfig,
) -> quinn::ClientConfig {
    let transport = build_transport_config(config);
    client_config.transport_config(Arc::new(transport));
    client_config
}

/// Build shared transport configuration (server + client).
fn build_transport_config(config: &NetServiceConfig) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(config.keep_alive_interval));
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(config.idle_timeout)
            .expect("validated net service idle timeout must fit within quinn idle-timeout bounds"),
    ));
    transport
}

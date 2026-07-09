//! JSON-RPC server lifecycle management.
//!
//! The RPC server runs on a dedicated thread with its own tokio runtime because
//! jsonrpsee requires tokio while the rest of the binary uses monoio.
//!
//! # Security
//!
//! The server is **unauthenticated** by design. Its intended reader is the
//! operator's own bridge node on a trusted internal network — not remote
//! peers, and not the public internet. The RPC methods can drive setup,
//! deposits, adaptor-sig completion, and fault-secret signing, so exposing
//! this port beyond the operator's own infrastructure is a full compromise
//! of the mosaic instance.
//!
//! Operators are responsible for firewalling the bind address. As a
//! reminder, [`start_rpc_server`] emits a `WARN` on startup whenever
//! `bind_addr` is not a loopback address, and a louder one when it's a
//! wildcard address (`0.0.0.0` / `::`) — a wildcard bind exposes the
//! unauthenticated API on every interface the host has, so it's called
//! out separately.

use std::{net::SocketAddr, thread::JoinHandle};

use anyhow::{Context, Result};
use jsonrpsee::server::ServerHandle;
use mosaic_rpc_api::MosaicRpcServer;
use mosaic_rpc_server::RpcServerImpl;
use mosaic_rpc_service::MosaicApi;
use mosaic_rpc_types::RpcCircuitInfoEntry;

/// Controller for a running RPC server.
#[derive(Debug)]
pub(crate) struct RpcController {
    server_handle: ServerHandle,
    thread_handle: Option<JoinHandle<()>>,
}

impl RpcController {
    /// Gracefully stop the RPC server and join its thread.
    pub(crate) fn shutdown(mut self) -> Result<()> {
        self.server_handle
            .stop()
            .context("RPC server already stopped")?;
        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("RPC server thread panicked"))?;
        }
        tracing::info!("RPC server shut down");
        Ok(())
    }

    /// Check whether the RPC server thread is still running.
    pub(crate) fn is_running(&self) -> bool {
        self.thread_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

/// Start the RPC server on a dedicated tokio thread.
///
/// The server is unauthenticated; see the module-level docs for the trust
/// model. Emits a `WARN` when `bind_addr` is not a loopback address as a
/// reminder that the port must be firewalled off from anything other than
/// the operator's own bridge node.
pub(crate) fn start_rpc_server(
    bind_addr: SocketAddr,
    service: impl MosaicApi,
    circuit_info: RpcCircuitInfoEntry,
) -> Result<RpcController> {
    let ip = bind_addr.ip();
    if ip.is_unspecified() {
        // 0.0.0.0 / :: — the API is now reachable on every interface the host
        // has, including any public ones. This is almost never what an
        // operator wants; call it out louder than the general non-loopback
        // case, since the surface is strictly worse.
        tracing::warn!(
            %bind_addr,
            "RPC server binding to a wildcard address — the unauthenticated RPC is now \
             reachable on every interface this host has, including any public ones. \
             Bind to a specific internal address the operator's own bridge node reaches, \
             and firewall the port off from peers and the public internet."
        );
    } else if !ip.is_loopback() {
        // Any other non-loopback bind (typically a private-subnet or
        // container-network address). The docs bless these as valid
        // deployments; the warn is a reminder that the firewall assumption
        // is on the operator.
        tracing::warn!(
            %bind_addr,
            "RPC server binding to a non-loopback address — the RPC is unauthenticated \
             and must only be reachable by this operator's own bridge node. Ensure the \
             port is firewalled off from peers and the public internet."
        );
    }

    let rpc_impl = RpcServerImpl::new(service, circuit_info);

    let (handle_tx, handle_rx) = std::sync::mpsc::sync_channel(1);

    let thread_handle = std::thread::Builder::new()
        .name("rpc-server".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("rpc-tokio")
                .build()
                .expect("failed to build tokio runtime for RPC server");

            runtime.block_on(async move {
                // Log every RPC request and response (method + payload) at TRACE
                // level under the `jsonrpsee` target. Payloads are truncated to
                // `max_log_len` chars. Enable with e.g. `RUST_LOG=jsonrpsee=trace`.
                let rpc_middleware =
                    jsonrpsee::server::middleware::rpc::RpcServiceBuilder::new().rpc_logger(4096);

                let server = jsonrpsee::server::ServerBuilder::default()
                    .set_rpc_middleware(rpc_middleware)
                    .build(bind_addr)
                    .await
                    .expect("failed to build RPC server");

                let handle = server.start(rpc_impl.into_rpc());
                let _ = handle_tx.send(handle.clone());

                handle.stopped().await;
            });
        })
        .context("failed to spawn RPC server thread")?;

    let server_handle = handle_rx
        .recv()
        .context("failed to receive RPC server handle")?;

    tracing::info!(%bind_addr, "RPC server started");

    Ok(RpcController {
        server_handle,
        thread_handle: Some(thread_handle),
    })
}

//! JSON-RPC server lifecycle management.
//!
//! The RPC server runs on a dedicated thread with its own tokio runtime because
//! jsonrpsee requires tokio while the rest of the binary uses monoio.

use std::{net::SocketAddr, thread::JoinHandle};

use anyhow::{Context, Result};
use jsonrpsee::server::ServerHandle;
use mosaic_rpc_api::MosaicRpcServer;
use mosaic_rpc_server::RpcServerImpl;
use mosaic_rpc_service::MosaicApi;

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
pub(crate) fn start_rpc_server(
    bind_addr: SocketAddr,
    service: impl MosaicApi,
) -> Result<RpcController> {
    let rpc_impl = RpcServerImpl::new(service);

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
                let server = jsonrpsee::server::ServerBuilder::default()
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

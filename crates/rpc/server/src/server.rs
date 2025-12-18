#![allow(unused, reason = "not yet implemented")]

use mosaic_rpc_api::MosaicRpcServer;
use mosaic_rpc_provider::RpcContextProvider;
use mosaic_rpc_types::*;

/// Mosaic RPC server impl.
#[derive(Debug)]
pub struct RpcServerImpl<P: RpcContextProvider> {
    #[allow(unused)]
    provider: P,
}

impl<P: RpcContextProvider> RpcServerImpl<P> {
    /// Constructs a new instance.
    ///
    /// Accepts a RPC context provider for access to the client functionality we
    /// expose.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: RpcContextProvider> MosaicRpcServer for RpcServerImpl<P> {
    fn get_circuit_defs(&self) -> RpcResult<Vec<RpcCircuitInfoEntry>> {
        todo!()
    }

    fn get_peer_id(&self) -> RpcResult<PeerId> {
        todo!()
    }

    fn setup_tableset(&self, config: RpcSetupConfig) -> RpcResult<TablesetId> {
        todo!()
    }

    fn get_tableset_info(&self, tsid: TablesetId) -> RpcResult<TablesetSetupInfo> {
        todo!()
    }

    fn get_tableset_setup_status(&self, tsid: TablesetId) -> RpcResult<RpcTablesetSetupStatus> {
        todo!()
    }

    fn cleanup_tableset(&self, tsid: TablesetId) -> RpcResult<()> {
        todo!()
    }
}

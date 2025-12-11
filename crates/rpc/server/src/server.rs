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

    fn get_job_status(&self, jid: JobId) -> RpcResult<RpcJobStatus> {
        todo!()
    }

    fn wait_for_job(&self, jid: JobId, timeout_ms: u32) -> RpcResult<bool> {
        todo!()
    }

    fn create_game_instance(&self, config: RpcGameInstanceConfig) -> RpcResult<TablesetId> {
        todo!()
    }

    fn get_game_info(&self, tsid: TablesetId) -> RpcResult<GameInfo> {
        todo!()
    }

    fn get_export_data(&self, tsid: TablesetId) -> RpcResult<TableExportMeta> {
        todo!()
    }

    fn start_eval_tableset(&self, tsid: TablesetId, inputs: TableEvalInputs) -> RpcResult<JobId> {
        todo!()
    }

    fn get_eval_outputs(&self, tsid: TablesetId) -> RpcResult<TableEvalOutputs> {
        todo!()
    }

    fn cleanup_game(&self, tsid: TablesetId) -> RpcResult<()> {
        todo!()
    }
}

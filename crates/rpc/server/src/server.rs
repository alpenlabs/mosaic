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

    fn get_job_status(&self, jid: JobId) -> RpcResult<RpcJobState> {
        todo!()
    }

    fn wait_for_job(&self, jid: JobId, timeout_ms: u32) -> RpcResult<bool> {
        todo!()
    }

    fn create_tableset_instance(&self, config: RpcTablesetConfig) -> RpcResult<TablesetId> {
        todo!()
    }

    fn get_game_info(&self, tsid: TablesetId) -> RpcResult<String> {
        todo!()
    }

    fn start_generate_game_tableset(&self, tsid: TablesetId) -> RpcResult<JobId> {
        todo!()
    }

    fn get_garb_commitments(&self, tsid: TablesetId) -> RpcResult<TablesetCommitments> {
        todo!()
    }

    fn provide_garb_commitments(
        &self,
        tsid: TablesetId,
        commitments: TablesetCommitments,
    ) -> RpcResult<CacChoices> {
        todo!()
    }

    fn provide_eval_cac_choices(&self, tsid: TablesetId, choices: CacChoices) -> RpcResult<()> {
        todo!()
    }

    fn get_cac_seeds(&self, tsid: TablesetId) -> RpcResult<CacSeeds> {
        todo!()
    }

    fn start_verify_garb_cac_seeds(&self, tsid: TablesetId, seeds: CacSeeds) -> RpcResult<JobId> {
        todo!()
    }

    fn check_verify_cac_commitments(&self, tsid: TablesetId) -> RpcResult<bool> {
        todo!()
    }

    fn start_export_unopened_tables(&self, tsid: TablesetId) -> RpcResult<JobId> {
        todo!()
    }

    fn get_export_data(&self, tsid: TablesetId) -> RpcResult<TableExportMeta> {
        todo!()
    }

    fn start_download_table_export(
        &self,
        tsid: TablesetId,
        export_meta: TableExportMeta,
    ) -> RpcResult<JobId> {
        todo!()
    }

    fn start_eval_tableset(&self, tsid: TablesetId, inputs: TableEvalInputs) -> RpcResult<JobId> {
        todo!()
    }

    fn get_eval_outputs(&self, tsid: TablesetId) -> RpcResult<TableEvalOutputs> {
        todo!()
    }
}

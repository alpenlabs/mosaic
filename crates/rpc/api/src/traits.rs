use jsonrpsee::proc_macros::rpc;
use mosaic_rpc_types::*;

// TODO figure this out
/*#[cfg_attr(
    and(feature = "gen-client", not(feature = "gen-server")),
    rpc(client, namespace = "mosaic")
)]
#[cfg_attr(
    and(not(feature = "gen-client"), feature = "gen-server"),
    rpc(server, namespace = "mosaic")
)]
#[cfg_attr(
    and(feature = "gen-client", feature = "gen-server"),
    rpc(client, server, namespace = "mosaic")
)]*/

#[rpc(client, server, namespace = "mosaic")]
pub trait MosaicRpc {
    /// Gets the circuits that this client has been configured with, so we know
    /// if we can use it for our protocol purposes.
    #[method(name = "mosaic_getCircuitDefs")]
    fn get_circuit_defs(&self) -> RpcResult<Vec<RpcCircuitInfoEntry>>;

    // ==== Job control

    /// Gets current info about a job.
    #[method(name = "mosaic_getJobStatus")]
    fn get_job_status(&self, jid: JobId) -> RpcResult<RpcJobStatus>;

    /// Waits for a job to complete, or until a timeout.
    #[method(name = "mosaic_waitForJob")]
    fn wait_for_job(&self, jid: JobId, timeout_ms: u32) -> RpcResult<bool>;

    // ==== Protocol flow.

    /// Creates an instance of a tableset game.
    #[method(name = "mosaic_createGame")]
    fn create_game_instance(&self, config: RpcGameInstanceConfig) -> RpcResult<TablesetId>;

    /// Gets current info about about a game.
    #[method(name = "mosaic_getGameInfo")]
    fn get_game_info(&self, tsid: TablesetId) -> RpcResult<GameInfo>;

    /// Gets the data for exchanging exported tables.
    #[method(name = "mosaic_getTableExportData")]
    fn get_export_data(&self, tsid: TablesetId) -> RpcResult<TableExportMeta>;

    // TODO more methods for dealing with exports here?

    /// Starts evaluating the tables in the set using the provided inputs.
    #[method(name = "mosaic_startEvalTableset")]
    fn start_eval_tableset(&self, tsid: TablesetId, inputs: TableEvalInputs) -> RpcResult<JobId>;

    /// Gets the output from a successful evaluation of a table using the
    /// provided inputs.
    #[method(name = "mosaic_getEvalOutputs")]
    fn get_eval_outputs(&self, tsid: TablesetId) -> RpcResult<TableEvalOutputs>;

    /// Cleans up a completed game, regardless of its state.
    #[method(name = "mosaic_cleanupGame")]
    fn cleanup_game(&self, tsid: TablesetId) -> RpcResult<()>;
}

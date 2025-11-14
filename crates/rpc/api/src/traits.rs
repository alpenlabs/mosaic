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
    #[method(name = "mosaic_createTablesetGame")]
    fn create_tableset_instance(&self, config: RpcTablesetConfig) -> RpcResult<TablesetId>;

    /// Gets current info about about a game.
    #[method(name = "mosaic_getGameInfo")]
    fn get_game_info(&self, tsid: TablesetId) -> RpcResult<GameInfo>;

    /// Starts generating the garbler side's commitments.
    #[method(name = "mosaic_startGenGarbCommitments")]
    fn start_generate_game_tableset(&self, tsid: TablesetId) -> RpcResult<JobId>;

    /// Gets the garbler commitments to send to the verifier.
    #[method(name = "mosaic_getGarbCommitments")]
    fn get_garb_commitments(&self, tsid: TablesetId) -> RpcResult<TablesetCommitments>;

    /// Provides the tableset commitments from the garbler.  Returns the table
    /// ID's we're choosing to open.
    #[method(name = "mosaic_provideGarbTablesetCommitments")]
    fn provide_garb_commitments(
        &self,
        tsid: TablesetId,
        commitments: TablesetCommitments,
    ) -> RpcResult<CacChoices>;

    /// Provides the CaC choices from the evaluator.
    #[method(name = "mosaic_provideEvalCacChoices")]
    fn provide_eval_cac_choices(&self, tsid: TablesetId, choices: CacChoices) -> RpcResult<()>;

    /// Gets the tableset seeds for each table according to the previously-
    /// provided CaC choices.
    #[method(name = "mosaic_getCacSeeds")]
    fn get_cac_seeds(&self, tsid: TablesetId) -> RpcResult<CacSeeds>;

    /// Provides the evaluator with the garbler's seeds for each table that we
    /// can verify.
    #[method(name = "mosaic_startVerifyGarbCacSeeds")]
    fn start_verify_garb_cac_seeds(&self, tsid: TablesetId, seeds: CacSeeds) -> RpcResult<JobId>;

    /// Checks if the we've successfully verified the seeds for the tables we
    /// opened from the garbler.  This means the other tables in the tableset
    /// are probably okay.
    #[method(name = "mosaic_checkVerifyGarbCacSeeds")]
    fn check_verify_cac_commitments(&self, tsid: TablesetId) -> RpcResult<bool>;

    /// Starts exporting the unopened tables so that we can provide them to the
    /// evaluator.
    #[method(name = "mosaic_startExportUnopenedTables")]
    fn start_export_unopened_tables(&self, tsid: TablesetId) -> RpcResult<JobId>;

    /// Gets the data for exchanging exported tables.
    #[method(name = "mosaic_getTableExportData")]
    fn get_export_data(&self, tsid: TablesetId) -> RpcResult<TableExportMeta>;

    // TODO more methods for dealing with exports here?

    /// Starts downloading exported tables from the provided metadata.
    #[method(name = "mosaic_startDownloadTableExport")]
    fn start_download_table_export(
        &self,
        tsid: TablesetId,
        export_meta: TableExportMeta,
    ) -> RpcResult<JobId>;

    /// Starts evaluating the tables in the set using the provided inputs.
    #[method(name = "mosaic_startEvalTableset")]
    fn start_eval_tableset(&self, tsid: TablesetId, inputs: TableEvalInputs) -> RpcResult<JobId>;

    /// Gets the output from a successful evaluation of a table using the
    /// provided inputs.
    #[method(name = "mosaic_getEvalOutputs")]
    fn get_eval_outputs(&self, tsid: TablesetId) -> RpcResult<TableEvalOutputs>;
}

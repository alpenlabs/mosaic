use jsonrpsee::proc_macros::rpc;
use mosaic_net_svc_api::PeerId;
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

    /// Get p2p [`PeerId`] for this mosaic client.
    #[method(name = "mosaic_getPeerId")]
    fn get_peer_id(&self) -> RpcResult<PeerId>;

    // ==== Protocol flow.

    /// Creates an instance of a tableset.
    /// Initiates setup flow for a pair of mosaic clients, with chosen role.
    /// Returned TablesetId uniquely identifies a combination of (garbler, evaluator, circuit,
    /// instance).
    #[method(name = "mosaic_setupTableset")]
    fn setup_tableset(&self, config: RpcSetupConfig) -> RpcResult<TablesetId>;

    /// Gets info about about a tableset.
    #[method(name = "mosaic_getTablesetInfo")]
    fn get_tableset_info(&self, tsid: TablesetId) -> RpcResult<TablesetSetupInfo>;

    /// Gets current setup status of a tableset.
    /// This should be polled to check when the setup is complete.
    #[method(name = "mosaic_getTablesetSetupStatus")]
    fn get_tableset_setup_status(&self, tsid: TablesetId) -> RpcResult<RpcTablesetSetupStatus>;

    // fn

    /// Cleans up a tableset, regardless of its state.
    #[method(name = "mosaic_cleanupTableset")]
    fn cleanup_tableset(&self, tsid: TablesetId) -> RpcResult<()>;
}

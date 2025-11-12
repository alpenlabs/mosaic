use jsonrpsee::proc_macros::rpc;
use mosaic_rpc_types::RpcResult;

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
    /// Says hello.
    #[method(name = "hello")]
    fn hello(&self) -> RpcResult<i32>;
}

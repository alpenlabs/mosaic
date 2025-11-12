use mosaic_rpc_api::MosaicRpcServer;
use mosaic_rpc_provider::RpcContextProvider;
use mosaic_rpc_types::RpcResult;

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
    fn hello(&self) -> RpcResult<i32> {
        Ok(42)
    }
}

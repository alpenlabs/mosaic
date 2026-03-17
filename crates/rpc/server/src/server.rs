#![allow(unused, reason = "not yet implemented")]

use jsonrpsee::core::async_trait;
use mosaic_net_svc_api::PeerId;
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

#[async_trait]
impl<P: RpcContextProvider> MosaicRpcServer for RpcServerImpl<P> {
    fn get_circuit_defs(&self) -> RpcResult<Vec<RpcCircuitInfoEntry>> {
        todo!()
    }

    fn get_peer_id(&self) -> RpcResult<RpcPeerId> {
        todo!()
    }

    fn get_tableset_id(
        &self,
        role: CacRole,
        peer_id: RpcPeerId,
        instance: RpcInstanceId,
    ) -> RpcResult<RpcTablesetId> {
        todo!()
    }

    async fn list_tableset_ids(&self) -> RpcResult<Vec<RpcTablesetId>> {
        todo!()
    }

    async fn setup_tableset(&self, config: RpcSetupConfig) -> RpcResult<RpcTablesetId> {
        todo!()
    }

    async fn get_tableset_status(&self, tsid: RpcTablesetId) -> RpcResult<RpcTablesetStatus> {
        todo!()
    }

    async fn get_fault_secret_pubkey(&self, tsid: RpcTablesetId) -> RpcResult<Option<RpcPubKey>> {
        todo!()
    }

    async fn evaluator_get_adaptor_pubkey(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<Option<RpcPubKey>> {
        todo!()
    }

    async fn list_deposits(&self, tsid: RpcTablesetId) -> RpcResult<Vec<DepositIdStatus>> {
        todo!()
    }

    async fn init_garbler_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: GarblerDepositConfig,
    ) -> RpcResult<()> {
        todo!()
    }

    async fn init_evaluator_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: EvaluatorDepositConfig,
    ) -> RpcResult<()> {
        todo!()
    }

    async fn get_deposit_status(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<DepositStatus> {
        todo!()
    }

    async fn mark_deposit_withdrawn(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<()> {
        todo!()
    }

    async fn complete_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: RpcWithdrawalInputs,
    ) -> RpcResult<()> {
        todo!()
    }

    async fn get_completed_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<RpcCompletedSignatures> {
        todo!()
    }

    async fn evaluate_tableset(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: EvaluatorWithdrawalConfig,
    ) -> RpcResult<()> {
        todo!()
    }

    async fn sign_with_fault_secret(
        &self,
        tsid: RpcTablesetId,
        digest: RpcByte32,
        tweak: Option<RpcByte32>,
    ) -> RpcResult<Option<RpcSignatureBytes>> {
        todo!()
    }

    async fn cleanup_tableset(&self, tsid: RpcTablesetId) -> RpcResult<()> {
        todo!()
    }
}

use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use jsonrpsee::core::async_trait;
use mosaic_cac_types::{DepositId, Sighashes, state_machine::StateMachineId};
use mosaic_common::Byte32;
use mosaic_net_svc_api::PeerId;
use mosaic_rpc_api::MosaicRpcServer;
use mosaic_rpc_service::{
    EvaluatorDepositInit, EvaluatorWithdrawalData, GarblerDepositInit, MosaicApi, SetupConfig,
};
use mosaic_rpc_types::*;

use crate::conversions::{
    cac_role_to_domain, deposit_status_to_rpc, service_err, tableset_status_to_rpc,
};

/// Mosaic RPC server impl.
///
/// Thin adapter that translates between RPC types and domain types, delegating
/// all business logic to the [`MosaicApi`] service.
#[derive(Debug)]
pub struct RpcServerImpl<Svc: MosaicApi> {
    service: Svc,
}

impl<Svc: MosaicApi> RpcServerImpl<Svc> {
    /// Constructs a new instance with the given service implementation.
    pub fn new(service: Svc) -> Self {
        Self { service }
    }
}

/// Parses an [`RpcTablesetId`] into a [`StateMachineId`].
fn parse_sm_id(tsid: RpcTablesetId) -> RpcResult<StateMachineId> {
    StateMachineId::try_from(tsid).map_err(|_| RpcError::InvalidStateMachineId)
}

#[async_trait]
impl<Svc: MosaicApi> MosaicRpcServer for RpcServerImpl<Svc> {
    fn get_circuit_defs(&self) -> RpcResult<Vec<RpcCircuitInfoEntry>> {
        Ok(vec![RpcCircuitInfoEntry::from_config()])
    }

    fn get_peer_id(&self) -> RpcResult<RpcPeerId> {
        Ok(RpcPeerId::new(*self.service.get_peer_id().as_bytes()))
    }

    fn get_tableset_id(
        &self,
        role: CacRole,
        peer_id: RpcPeerId,
        instance: RpcInstanceId,
    ) -> RpcResult<RpcTablesetId> {
        let peer_id = PeerId::from_bytes(*peer_id.inner());
        let sm_id = self.service.get_tableset_id(
            cac_role_to_domain(role),
            &peer_id,
            &Byte32::from(instance.into_inner()),
        );
        Ok(sm_id.into())
    }

    async fn setup_tableset(&self, config: RpcSetupConfig) -> RpcResult<RpcTablesetId> {
        let domain_config = SetupConfig {
            role: cac_role_to_domain(config.role),
            peer_id: PeerId::from_bytes(*config.peer_info.peer_id.inner()),
            setup_inputs: config.setup_inputs.into_inner(),
            instance: Byte32::from(config.instance_id.into_inner()),
        };
        let sm_id = self
            .service
            .setup_tableset(domain_config)
            .await
            .map_err(service_err)?;
        Ok(sm_id.into())
    }

    async fn list_tableset_ids(&self) -> RpcResult<Vec<RpcTablesetId>> {
        Ok(self
            .service
            .list_tableset_ids()
            .await
            .map_err(service_err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn get_tableset_status(&self, tsid: RpcTablesetId) -> RpcResult<RpcTablesetStatus> {
        let sm_id = parse_sm_id(tsid)?;
        let status = self
            .service
            .get_tableset_status(&sm_id)
            .await
            .map_err(service_err)?;
        Ok(tableset_status_to_rpc(status))
    }

    async fn get_fault_secret_pubkey(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<Option<XOnlyPublicKey>> {
        let sm_id = parse_sm_id(tsid)?;
        self.service
            .get_fault_secret_pubkey(&sm_id)
            .await
            .map_err(service_err)
    }

    async fn evaluator_get_adaptor_pubkey(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<Option<XOnlyPublicKey>> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(deposit_id);
        self.service
            .get_adaptor_pubkey(&sm_id, &deposit_id)
            .await
            .map_err(service_err)
    }

    async fn init_garbler_deposit(
        &self,
        tsid: RpcTablesetId,
        rpc_deposit_id: RpcDepositId,
        deposit: GarblerDepositConfig,
    ) -> RpcResult<()> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(rpc_deposit_id);
        let init = GarblerDepositInit {
            adaptor_pk: deposit.adaptor_pk,
            sighashes: Sighashes::from_vec(
                deposit
                    .sighashes
                    .into_inner()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            deposit_inputs: deposit.deposit_inputs.into(),
        };
        self.service
            .init_garbler_deposit(&sm_id, &deposit_id, init)
            .await
            .map_err(service_err)
    }

    async fn init_evaluator_deposit(
        &self,
        tsid: RpcTablesetId,
        rpc_deposit_id: RpcDepositId,
        deposit: EvaluatorDepositConfig,
    ) -> RpcResult<()> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(rpc_deposit_id);
        let init = EvaluatorDepositInit {
            sighashes: Sighashes::try_from_vec(
                deposit
                    .sighashes
                    .into_inner()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
            .ok_or_else(|| RpcError::InvalidArgument("invalid sighash length".into()))?,
            deposit_inputs: deposit.deposit_inputs.into(),
        };
        self.service
            .init_evaluator_deposit(&sm_id, &deposit_id, init)
            .await
            .map_err(service_err)
    }

    async fn list_deposits(&self, tsid: RpcTablesetId) -> RpcResult<Vec<DepositIdStatus>> {
        let sm_id = parse_sm_id(tsid)?;
        Ok(self
            .service
            .list_deposits(&sm_id)
            .await
            .map_err(service_err)?
            .into_iter()
            .map(|d| DepositIdStatus {
                deposit_id: d.deposit_id.into(),
                status: deposit_status_to_rpc(d.status),
            })
            .collect())
    }

    async fn get_deposit_status(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<DepositStatus> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(deposit_id);
        let status = self
            .service
            .get_deposit_status(&sm_id, &deposit_id)
            .await
            .map_err(service_err)?;
        Ok(deposit_status_to_rpc(status))
    }

    async fn mark_deposit_withdrawn(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<()> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(deposit_id);
        self.service
            .mark_deposit_withdrawn(&sm_id, &deposit_id)
            .await
            .map_err(service_err)
    }

    async fn complete_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: RpcWithdrawalInputs,
    ) -> RpcResult<()> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(deposit_id);
        self.service
            .complete_adaptor_sigs(&sm_id, &deposit_id, inputs.into_inner())
            .await
            .map_err(service_err)
    }

    async fn get_completed_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<RpcCompletedSignatures> {
        let sm_id = parse_sm_id(tsid)?;
        let adaptor_sigs = self
            .service
            .get_completed_adaptor_sigs(&sm_id)
            .await
            .map_err(service_err)?;

        let mut adaptor_sigs = adaptor_sigs.into_iter();
        Ok(RpcCompletedSignatures::new(std::array::from_fn(|_| {
            adaptor_sigs.next().unwrap()
        })))
    }

    async fn evaluate_tableset(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        withdrawal_data: EvaluatorWithdrawalConfig,
    ) -> RpcResult<()> {
        let sm_id = parse_sm_id(tsid)?;
        let deposit_id = DepositId::from(deposit_id);

        let data = EvaluatorWithdrawalData {
            withdrawal_inputs: withdrawal_data.withdrawal_inputs.into_inner(),
            signatures: withdrawal_data.completed_signatures.into_inner().to_vec(),
        };

        self.service
            .evaluate_tableset(&sm_id, &deposit_id, data)
            .await
            .map_err(service_err)
    }

    async fn sign_with_fault_secret(
        &self,
        tsid: RpcTablesetId,
        digest: RpcByte32,
        tweak: Option<RpcByte32>,
    ) -> RpcResult<Option<SchnorrSignature>> {
        let sm_id = parse_sm_id(tsid)?;
        Ok(self
            .service
            .sign_with_fault_secret(&sm_id, digest.into(), tweak.map(Into::into))
            .await
            .map_err(service_err)?)
    }

    async fn cleanup_tableset(&self, _tsid: RpcTablesetId) -> RpcResult<()> {
        // This isnt needed for immediate integration. Will be implemented later.
        return Err(RpcError::Unimplemented);
    }
}

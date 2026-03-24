use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
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
    #[method(name = "getCircuitDefs")]
    fn get_circuit_defs(&self) -> RpcResult<Vec<RpcCircuitInfoEntry>>;

    /// Get p2p [`RpcPeerId`] for this mosaic client.
    #[method(name = "getRpcPeerId")]
    fn get_peer_id(&self) -> RpcResult<RpcPeerId>;

    /// Helper to get deterministic [`RpcTablesetId`].
    #[method(name = "getRpcTablesetId")]
    fn get_tableset_id(
        &self,
        role: CacRole,
        peer_id: RpcPeerId,
        instance: RpcInstanceId,
    ) -> RpcResult<RpcTablesetId>;

    // ==== Protocol flow.

    /// Lists ids for all available tablesets.
    #[method(name = "listTablesets")]
    async fn list_tableset_ids(&self) -> RpcResult<Vec<RpcTablesetId>>;

    /// Creates an instance of a tableset.
    /// Initiates setup flow for a pair of mosaic clients, with chosen role.
    /// Caller should then poll `get_tableset_status` with the returned `RpcTablesetId` and wait for
    /// status `Incomplete` -> `SetupComplete`.
    #[method(name = "setupTableset")]
    async fn setup_tableset(&self, config: RpcSetupConfig) -> RpcResult<RpcTablesetId>;

    /// Gets current setup status of a tableset.
    /// Returns None if the tableset does not exist.
    /// This should be polled to check when the setup is complete.
    #[method(name = "getTablesetStatus")]
    async fn get_tableset_status(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<Option<RpcTablesetStatus>>;

    /// Gets pubkey for the fault secret encoded in the garbling tables.
    /// Returns None if the tableset does not exist.
    /// Only valid for a garbler tableset.
    #[method(name = "getFaultSecretPubkey")]
    async fn get_fault_secret_pubkey(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<Option<XOnlyPublicKey>>;

    /// Get pubkey corresponding to secret key used to generate adaptors.
    /// Returns None if the tableset does not exist.
    /// Only valid for evaluator tableset.
    #[method(name = "getAdaptorPubkey")]
    async fn evaluator_get_adaptor_pubkey(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<Option<XOnlyPublicKey>>;

    /// List all deposit ids with their status on a given tableset.
    #[method(name = "getDeposits")]
    async fn list_deposits(&self, tsid: RpcTablesetId) -> RpcResult<Vec<DepositIdStatus>>;

    /// Create a deposit instance on a given garbler tableset.
    #[method(name = "initGarblerDeposit")]
    async fn init_garbler_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: GarblerDepositConfig,
    ) -> RpcResult<()>;

    /// Create a deposit instance on a given evaluator tableset.
    #[method(name = "initEvaluatorDeposit")]
    async fn init_evaluator_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: EvaluatorDepositConfig,
    ) -> RpcResult<()>;

    /// Gets a deposit instance on a given tableset.
    /// This should be polled to check if the deposit is ready to be used.
    #[method(name = "getDepositStatus")]
    async fn get_deposit_status(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<DepositStatus>;

    /// Marks that a deposit was succesfully withdrawn without contest. This deposit cannot be
    /// used afterwards and will be hidden from `getDeposits`.
    #[method(name = "markDepositWithdrawn")]
    async fn mark_deposit_withdrawn(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> RpcResult<()>;

    /// Marks that a withdrawal has been contested and its corresponding adaptor signatures should
    /// be computed. The tableset can no longer be used after this.
    /// Only valid on a garbler tableset.
    #[method(name = "completeAdaptorSigs")]
    async fn complete_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: RpcWithdrawalInputs,
    ) -> RpcResult<()>;

    /// Gets adaptor signatures computed after a contested withdrawal.
    /// Only valid on a garbler tableset.
    #[method(name = "getCompletedAdaptorSigs")]
    async fn get_completed_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
    ) -> RpcResult<RpcCompletedSignatures>;

    /// Uses completed adaptor signatures to initiate tableset evaluation.
    /// The tableset can no longer be used after this.
    /// Only valid on an evaluator tableset.
    #[method(name = "evaluate_tableset")]
    async fn evaluate_tableset(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: EvaluatorWithdrawalConfig,
    ) -> RpcResult<()>;

    /// After tableset evaluation is completed, sign given data using the extracted fault secret.
    /// Only valid on an evaluator tableset.
    #[method(name = "signWithFaultSecret")]
    async fn sign_with_fault_secret(
        &self,
        tsid: RpcTablesetId,
        digest: RpcByte32,
        tweak: Option<RpcByte32>,
    ) -> RpcResult<Option<SchnorrSignature>>;

    /// Cleans up a tableset, regardless of its state.
    /// After calling this, the tableset can never be used again and is also removed from
    /// `listTablesets`.
    #[method(name = "cleanupTableset")]
    async fn cleanup_tableset(&self, tsid: RpcTablesetId) -> RpcResult<()>;
}

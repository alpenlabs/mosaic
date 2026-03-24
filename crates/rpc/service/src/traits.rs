//! The [`MosaicApi`] trait — transport-agnostic service interface.

use async_trait::async_trait;
use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use mosaic_cac_types::{
    DepositId, WithdrawalInputs,
    state_machine::{Role, StateMachineId},
};
use mosaic_common::Byte32;
use mosaic_net_svc_api::PeerId;

use crate::{
    DepositStatus, DepositWithStatus, EvaluatorDepositInit, EvaluatorWithdrawalData,
    GarblerDepositInit, ServiceResult, SetupConfig, TablesetStatus,
};

/// Main programmatic interface for controlling Mosaic.
///
/// This is the service layer that the bridge (and any other consumer) uses.
/// The RPC server is one thin frontend for this API.
#[async_trait]
pub trait MosaicApi: Send + Sync + 'static {
    /// Returns this node's peer ID.
    fn get_peer_id(&self) -> PeerId;

    /// Computes the deterministic tableset (state machine) ID for a given
    /// role, peer, and instance.
    fn get_tableset_id(&self, role: Role, peer_id: &PeerId, instance: &Byte32) -> StateMachineId;

    /// Lists all known tableset IDs.
    async fn list_tableset_ids(&self) -> ServiceResult<Vec<StateMachineId>>;

    /// Sets up a new tableset. Idempotent — returns the existing ID if already
    /// set up for the given peer + role.
    async fn setup_tableset(&self, config: SetupConfig) -> ServiceResult<StateMachineId>;

    /// Gets the current status of a tableset.
    async fn get_tableset_status(
        &self,
        sm_id: &StateMachineId,
    ) -> ServiceResult<Option<TablesetStatus>>;

    /// Gets the fault secret public key for a tableset.
    /// Dispatches internally based on the role encoded in `sm_id`.
    async fn get_fault_secret_pubkey(
        &self,
        sm_id: &StateMachineId,
    ) -> ServiceResult<Option<XOnlyPublicKey>>;

    /// Gets the adaptor public key for an evaluator deposit.
    async fn get_adaptor_pubkey(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<Option<XOnlyPublicKey>>;

    /// Initializes a garbler deposit.
    ///
    /// Validates that the state machine exists, is in `SetupComplete`, and the
    /// deposit does not already exist.
    async fn init_garbler_deposit(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        init: GarblerDepositInit,
    ) -> ServiceResult<()>;

    /// Initializes an evaluator deposit.
    ///
    /// Validates that the state machine exists, is in `SetupComplete`, and the
    /// deposit does not already exist. Derives the adaptor secret key
    /// deterministically.
    async fn init_evaluator_deposit(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        init: EvaluatorDepositInit,
    ) -> ServiceResult<()>;

    /// Lists all deposits for a tableset. Dispatches by role.
    async fn list_deposits(&self, sm_id: &StateMachineId) -> ServiceResult<Vec<DepositWithStatus>>;

    /// Gets the status of a specific deposit. Dispatches by role.
    async fn get_deposit_status(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<DepositStatus>;

    /// Marks a deposit as withdrawn without contest.
    ///
    /// Validates state machine and deposit step preconditions.
    async fn mark_deposit_withdrawn(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<()>;

    /// Garbler only: initiates adaptor signature completion for a contested
    /// withdrawal.
    ///
    /// Validates state machine and deposit step preconditions.
    async fn complete_adaptor_sigs(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        withdrawal_inputs: WithdrawalInputs,
    ) -> ServiceResult<()>;

    /// Garbler only: retrieves completed adaptor signatures after a contested
    /// withdrawal.
    async fn get_completed_adaptor_sigs(
        &self,
        sm_id: &StateMachineId,
    ) -> ServiceResult<Vec<SchnorrSignature>>;

    /// Evaluator only: evaluates the tableset using completed adaptor
    /// signatures.
    async fn evaluate_tableset(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        data: EvaluatorWithdrawalData,
    ) -> ServiceResult<()>;

    /// Evaluator only: signs a digest using the extracted fault secret.
    ///
    /// Returns `None` if the fault secret could not be extracted (evaluation
    /// unsuccessful).
    async fn sign_with_fault_secret(
        &self,
        sm_id: &StateMachineId,
        digest: [u8; 32],
        tweak: Option<[u8; 32]>,
    ) -> ServiceResult<Option<SchnorrSignature>>;
}

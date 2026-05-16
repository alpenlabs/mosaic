use bitcoin::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    RpcCompletedSignatures, RpcDepositId, RpcDepositInputs, RpcInputSighashes, RpcTablesetId,
};

/// Configuration provided as part of deposit setup for garbler.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GarblerDepositConfig {
    /// Deposit wire values
    pub deposit_inputs: RpcDepositInputs,
    /// Deposit and withdrawal input wire sighashes
    pub sighashes: RpcInputSighashes,
    /// Adaptor pubkey
    pub adaptor_pk: XOnlyPublicKey,
}

/// Configuration provided as part of deposit setup
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositInfo {
    /// which tableset this belongs to
    pub tableset_id: RpcTablesetId,
    /// Deposit wire values
    pub deposit_inputs: RpcDepositInputs,
    /// Deposit and input wire sighashes
    pub sighashes: RpcInputSighashes,
}

/// Configuration provided as part of deposit setup for evaluator.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluatorDepositConfig {
    /// Deposit wire values
    pub deposit_inputs: RpcDepositInputs,
    /// Deposit and input wire sighashes
    pub sighashes: RpcInputSighashes,
}

/// Configuration provided as part of contested withdrawal for evaluator.
///
/// The evaluator recovers the withdrawal input wire values from the completed adaptor
/// signatures using locally stored adaptor state, so callers no longer need to supply
/// withdrawal-input hints.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluatorWithdrawalConfig {
    /// Completed adaptor signatures.
    pub completed_signatures: RpcCompletedSignatures,
}

/// Current status of a deposit
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DepositStatus {
    /// Deposit Setup is incomplete.
    /// Wait for this to complete.
    Incomplete {
        /// Additional info like which step its in, or its specific status, etc.
        /// This is mainly for debugging
        details: String,
    },

    /// Deposit setup is complete.
    Ready,

    /// Deposit has been withdrawn without dispute.
    UncontestedWithdrawal,

    /// Another deposit on this tableset has been used for contested withdrawal and this deposit on
    /// this setup cannot be used again.
    Consumed {
        /// Deposit that entered withdrawal dispute.
        by: RpcDepositId,
    },

    /// Deposit process was aborted due to a protocol violation.
    /// NEW DEPOSIT PROCESS REQUIRED.
    Aborted {
        /// Reason for aborting.
        /// This is mainly for debugging.
        reason: String,
    },
}

/// Deposit id with status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIdStatus {
    /// deposit id
    pub deposit_id: RpcDepositId,
    /// deposit status
    pub status: DepositStatus,
}

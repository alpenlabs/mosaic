//! Conversions between service domain types and RPC types.

use mosaic_cac_types::state_machine::Role;
use mosaic_rpc_service::ServiceError;
use mosaic_rpc_types::{CacRole, DepositStatus, RpcDepositId, RpcError, RpcTablesetStatus};

/// Converts [`CacRole`] to the domain [`Role`].
pub(crate) fn cac_role_to_domain(role: CacRole) -> Role {
    match role {
        CacRole::Garbler => Role::Garbler,
        CacRole::Evaluator => Role::Evaluator,
    }
}

/// Converts a [`ServiceError`] to an [`RpcError`].
///
/// This is a free function rather than a `From` impl because the server crate
/// owns neither type (orphan rule).
pub(crate) fn service_err(err: ServiceError) -> RpcError {
    match err {
        ServiceError::StateMachineNotFound(_) => RpcError::StateMachineNotFound,
        ServiceError::InvalidInputForState(s) => RpcError::InvalidInputForState(s),
        ServiceError::DuplicateDeposit(id) => RpcError::DuplicateDeposit(RpcDepositId::from(id)),
        ServiceError::DepositNotFound => RpcError::DepositNotFound,
        ServiceError::CompletedSigsNotFound => RpcError::CompletedSigsNotFound,
        ServiceError::UnparsableAdaptorSigs(s) => RpcError::UnparsableAdaptorSigs(s),
        ServiceError::InvalidArgument(s) => RpcError::InvalidArgument(s),
        ServiceError::RoleMismatch(s) => RpcError::InvalidInputForState(s),
        ServiceError::UnexpectedState(s) => RpcError::Other(s),
        ServiceError::Storage(e) => RpcError::Storage(e),
        ServiceError::Executor(e) => RpcError::SMExecutor(e),
    }
}

/// Converts a service [`TablesetStatus`] to an [`RpcTablesetStatus`].
pub(crate) fn tableset_status_to_rpc(
    status: mosaic_rpc_service::TablesetStatus,
) -> RpcTablesetStatus {
    match status {
        mosaic_rpc_service::TablesetStatus::Incomplete { details } => {
            RpcTablesetStatus::Incomplete { details }
        }
        mosaic_rpc_service::TablesetStatus::SetupComplete => RpcTablesetStatus::SetupComplete,
        mosaic_rpc_service::TablesetStatus::Contest { deposit_id } => RpcTablesetStatus::Contest {
            deposit: deposit_id.into(),
        },
        mosaic_rpc_service::TablesetStatus::Consumed {
            deposit_id,
            success,
        } => RpcTablesetStatus::Consumed {
            deposit: deposit_id.into(),
            success,
        },
        mosaic_rpc_service::TablesetStatus::Aborted { reason } => {
            RpcTablesetStatus::Aborted { reason }
        }
    }
}

/// Converts a service [`DepositStatus`] to an RPC [`DepositStatus`].
pub(crate) fn deposit_status_to_rpc(status: mosaic_rpc_service::DepositStatus) -> DepositStatus {
    match status {
        mosaic_rpc_service::DepositStatus::Incomplete { details } => {
            DepositStatus::Incomplete { details }
        }
        mosaic_rpc_service::DepositStatus::Ready => DepositStatus::Ready,
        mosaic_rpc_service::DepositStatus::UncontestedWithdrawal => {
            DepositStatus::UncontestedWithdrawal
        }
        mosaic_rpc_service::DepositStatus::Consumed { by } => {
            DepositStatus::Consumed { by: by.into() }
        }
        mosaic_rpc_service::DepositStatus::Aborted { reason } => DepositStatus::Aborted { reason },
    }
}

//! Identifiers.

use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use mosaic_cac_types::{DepositId, state_machine::StateMachineId};
use mosaic_common::constants::{N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES};
use mosaic_net_svc_api::PeerId;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

macro_rules! gen_bytearray_newtypes {
    (
        $docstring:literal
        $name:ident => $inner:ty
    ) => {
        #[serde_as]
        #[derive(
            Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize,
        )]
        #[doc = $docstring]
        pub struct $name(#[serde_as(as = "Hex")] $inner);

        impl $name {
            /// Constructs a new instance.
            pub fn new(v: $inner) -> Self {
                Self::from(v)
            }

            /// Gets a ref to the inner value.
            pub fn inner(&self) -> &$inner {
                &self.0
            }

            /// Gets the inner value.
            pub fn into_inner(self) -> $inner {
                self.0
            }
        }

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl From<$name> for $inner {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
    };
}

macro_rules! gen_array_wrapper_newtypes {
    (
        $docstring:literal
        $name:ident => $inner:ty
    ) => {
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[doc = $docstring]
        pub struct $name(#[serde_as(as = "[_; _]")] $inner);

        impl $name {
            /// Constructs a new instance.
            pub fn new(v: $inner) -> Self {
                Self::from(v)
            }

            /// Gets a ref to the inner value.
            pub fn inner(&self) -> &$inner {
                &self.0
            }

            /// Gets inner value
            pub fn into_inner(self) -> $inner {
                self.0
            }
        }

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl From<$name> for $inner {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}

gen_bytearray_newtypes!(
    "Tableset identifier"
    RpcTablesetId => [u8; 33]
);

impl From<StateMachineId> for RpcTablesetId {
    fn from(sm_id: StateMachineId) -> Self {
        RpcTablesetId(sm_id.to_bytes())
    }
}

impl TryFrom<RpcTablesetId> for StateMachineId {
    type Error = &'static str;

    fn try_from(tsid: RpcTablesetId) -> Result<Self, Self::Error> {
        StateMachineId::from_bytes(tsid.0)
    }
}

gen_bytearray_newtypes!(
    "Distinguishes between multiple instances of Tablesets setup between same pair of (garbler, evaluator)"
    RpcInstanceId => [u8; 32]
);

gen_bytearray_newtypes!(
    "Deposit identifier"
    RpcDepositId => [u8; 32]
);

impl From<DepositId> for RpcDepositId {
    fn from(value: DepositId) -> Self {
        RpcDepositId::new(value.0.into())
    }
}

impl From<RpcDepositId> for DepositId {
    fn from(value: RpcDepositId) -> Self {
        DepositId(value.0.into())
    }
}

gen_bytearray_newtypes!(
    "Peer identifier"
    RpcPeerId => [u8; 32]
);

impl From<RpcPeerId> for PeerId {
    fn from(value: RpcPeerId) -> Self {
        PeerId::from_bytes(value.into())
    }
}

impl From<PeerId> for RpcPeerId {
    fn from(value: PeerId) -> Self {
        RpcPeerId::new(value.to_bytes())
    }
}

gen_bytearray_newtypes!(
    "Generic 32 byte data"
    RpcByte32 => [u8; 32]
);

gen_bytearray_newtypes!(
    "Txn sighashes as raw bytes"
    RpcSighashBytes => [u8; 32]
);

gen_bytearray_newtypes!(
    "Setup input wire values"
    RpcSetupInputs => [u8; 32]
);

/// Txn sighash as raw bytes
pub type SighashBytes = [u8; 32];

gen_array_wrapper_newtypes!(
    "Input sighashes"
    RpcInputSighashes => [SighashBytes; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES]
);

/// Wire values for withdrawal input wires.
pub type WithdrawalInputs = [u8; N_WITHDRAWAL_INPUT_WIRES];

gen_bytearray_newtypes!(
    "Wire values for withdrawal input wires"
    RpcWithdrawalInputs => [u8; N_WITHDRAWAL_INPUT_WIRES]
);

gen_array_wrapper_newtypes!(
    "Complete adaptor signatures for all deposit and withdrawal input wires"
    RpcCompletedSignatures => [SchnorrSignature; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES]
);

gen_bytearray_newtypes!(
    "Deposit inputs"
    RpcDepositInputs => [u8; N_DEPOSIT_INPUT_WIRES]
);

//! Shared state machine specific types.

pub mod evaluator;
pub mod garbler;

use std::fmt::Display;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use mosaic_net_svc_api::PeerId;

/// State machine role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Garbler
    Garbler = 0,
    /// Evaluator
    Evaluator = 1,
}

impl TryFrom<u8> for Role {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Role::Garbler),
            1 => Ok(Role::Evaluator),
            _ => Err("invalid role byte"),
        }
    }
}

/// Deterministic id for a state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateMachineId {
    role: Role,
    peer_id: PeerId,
}

impl StateMachineId {
    /// Create new statemachine id
    pub fn new(role: Role, peer_id: PeerId) -> Self {
        Self { role, peer_id }
    }

    /// Create state machine id for garbler
    pub fn garbler(peer_id: PeerId) -> Self {
        Self::new(Role::Garbler, peer_id)
    }

    /// Create state machine id for evaluator
    pub fn evaluator(peer_id: PeerId) -> Self {
        Self::new(Role::Evaluator, peer_id)
    }

    /// Return the raw 33-byte array by value.
    pub fn to_bytes(&self) -> [u8; 33] {
        // layout:
        // [0]      = role (u8)
        // [1..33]  = peer_id

        let mut out = [0u8; 33];
        out[0] = self.role as u8;
        out[1..33].copy_from_slice(self.peer_id.as_bytes());
        out
    }

    /// Create a [`StateMachineId`] from raw bytes.
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, &'static str> {
        let role = Role::try_from(bytes[0])?;

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(&bytes[1..33]);
        let peer_id = PeerId::from_bytes(peer_bytes);

        Ok(Self { role, peer_id })
    }

    /// Return the [`PeerId`] of opposite mosaic instance.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Return role
    pub fn role(&self) -> Role {
        self.role
    }
}

impl Display for StateMachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_bytes()))
    }
}

impl CanonicalSerialize for StateMachineId {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.to_bytes().serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.to_bytes().serialized_size(compress)
    }
}

impl CanonicalDeserialize for StateMachineId {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let bytes = <[u8; 33]>::deserialize_with_mode(reader, compress, validate)?;
        Self::from_bytes(bytes).map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

impl Valid for StateMachineId {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

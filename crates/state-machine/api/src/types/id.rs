use mosaic_common::{Byte32, PeerId};

/// Setup phase or Deposit phase state machine
#[derive(Debug)]
pub enum StateMachinePhase {
    /// Setup phase
    Setup,
    /// Deposit phase
    Deposit,
}

/// Uniquely identifies a state machine pair run between 2 parties (type, garbler_peer,
/// evaluator_peer, instance).
/// As a single mosaic instance only holds one side of the pair, this id also uniquely identifies a
/// state machine inside one mosaic client.
#[derive(Debug)]
pub struct StateMachinePairInfo {
    /// type of state machine
    pub phase: StateMachinePhase,
    /// identifier of the garbler
    pub garbler: PeerId,
    /// identifier of the evaluator
    pub evaluator: PeerId,
    /// instance counter for same type of state machine between pair
    pub instance: u64,
}

impl StateMachinePairInfo {
    /// Get deterministic id
    pub fn id(&self) -> StateMachinePairId {
        todo!()
    }
}

/// Unique commitment derived from [`StateMachinePairInfo`].
pub type StateMachinePairId = Byte32;

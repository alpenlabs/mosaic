//! Shared state machine specific types.

pub mod evaluator;
pub mod garbler;
mod info;

pub use info::StateMachineInfo;
use mosaic_common::Byte32;

/// Deterministic id for a state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateMachineId(Byte32);

/// Input required by either garbler or evaluator.
#[derive(Debug)]
pub enum Input {
    /// Garbler Input
    Garbler(garbler::Input),
    /// Evaluator Input
    Evaluator(evaluator::Input),
}

/// Action send by either garbler or evaluator.
#[derive(Debug)]
pub enum ActionContainer {
    /// Garbler Action
    Garbler(garbler::ActionContainer),
    /// Evaluator Action
    Evaluator(evaluator::ActionContainer),
}

/// Input with target state machine id
#[derive(Debug)]
pub struct StateMachineInput {
    /// Id of state machine this input is for
    pub sm_id: StateMachineId,
    /// The input
    pub input: Input,
}

/// ActionContainer with dispatching state machine id
#[derive(Debug)]
pub struct StateMachineActionContainer {
    /// Id of state machine that dispatched this action
    pub sm_id: StateMachineId,
    /// The action
    pub action: ActionContainer,
}

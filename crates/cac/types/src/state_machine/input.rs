use crate::state_machine::{StateMachineId, evaluator, garbler};

/// Input to either garbler or evaluator state machine
#[derive(Debug)]
pub enum StateMachineInput {
    /// input to garbler state machine
    Garbler(garbler::Input),
    /// input to evaluator state machine
    Evaluator(evaluator::Input),
}

/// Input to State machine executor, consisting of id of target statemachine and the state machine
/// input.
#[derive(Debug)]
pub struct StateMachineExecutorInput {
    /// Id of state machine
    sm_id: StateMachineId,
    /// Input ot statemachine
    input: StateMachineInput,
}

impl StateMachineExecutorInput {
    /// Create new executor input.
    pub fn new(sm_id: StateMachineId, input: StateMachineInput) -> Self {
        Self { sm_id, input }
    }

    /// Returns target statemachine.
    pub fn statemachine_id(&self) -> &StateMachineId {
        &self.sm_id
    }

    /// Returns input to statemachine.
    pub fn input(&self) -> &StateMachineInput {
        &self.input
    }
}

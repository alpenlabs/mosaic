use mosaic_cac_proto_types::CacRole;

use crate::{
    StateMachineInitData, StateMachinePhase,
    types::{ExecutorInputMsgType, ExecutorOutputMsgType},
};

/// A state machine.
pub trait StateMachineSpec {
    /// The mutable state that evolves with each input.
    /// State is expected to be small to be kept in-memory.
    type State: Default + Clone + Eq;
    /// Configuration that remains constant throughout the state machine's lifetime.
    /// This will also contain
    type Config: Clone;
    /// The input event type that drives state transitions.
    type Input;
    /// Emittable actions to trigger external operations.
    /// Actions MUST be replay safe.
    type Action;

    /// The state transition function. Takes config, mutable state, and input, updating the mutable
    /// state. Should return true if there was a state change, false if no change
    fn stf(config: &Self::Config, state: Self::State, input: Self::Input) -> Self::State;

    /// Emit actions based on current state.
    fn emit_actions(config: &Self::Config, state: &Self::State) -> Vec<Self::Action>;
}

/// Glue between state machine and external executor.
/// This component understands the state machine and translates between protocol and implementation
/// messages.
pub trait StateMachineAdaptorSpec: StateMachineSpec {
    /// Additional adaptor specific state
    /// This should contain state needed for the glue logic.
    /// This should NOT contain any state relevant to the protocol.
    /// eg. to auto ack messages that have already been ack'd by the statemachine if received again.
    type AdaptorState: Default + Clone + Eq;

    /// Is this state machine is for Garbler or Evaluator.
    const ROLE: CacRole;

    /// Setup or deposit phase.
    const PHASE: StateMachinePhase;

    /// Try to initialize state machine from init data. Return None if the init data is invalid.
    fn process_init(
        init: StateMachineInitData,
    ) -> Option<(Self::Config, Self::State, Self::AdaptorState)>;

    /// Filters invalid messages and translates valid messages to state machine inputs.
    /// Msg ack caching and reply are also implemented here.
    // Note: 1 input msg should almost always map to 0 or 1 state machine inputs, but keeping it
    // flexible.
    fn process_input(
        ws: &Self::AdaptorState,
        input: ExecutorInputMsgType,
    ) -> (Vec<Self::Input>, Vec<ExecutorOutputMsgType>);

    /// Translates state machine action into output message(s).
    // Note: 1 action should almost always map to 1 output msg, but keeping it flexible.
    fn process_action(
        ws: Self::AdaptorState,
        action: Self::Action,
    ) -> (Self::AdaptorState, Vec<ExecutorOutputMsgType>);
}

/// Human readable state machine type.
pub const fn state_machine_type<Spec: StateMachineAdaptorSpec>() -> &'static str {
    use CacRole::*;
    use StateMachinePhase::*;
    match (Spec::ROLE, Spec::PHASE) {
        (Garbler, Setup) => "GARB_SETUP",
        (Garbler, Deposit) => "GARB_DEPOSIT",
        (Evaluator, Setup) => "EVAL_SETUP",
        (Evaluator, Deposit) => "EVAL_DEPOSIT",
    }
}

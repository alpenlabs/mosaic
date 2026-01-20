use fasm::actions::TrackedActionTypes;

/// Actions emitted by the evaluator state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {}

/// Placeholder for untracked actions (currently unused).
#[derive(Debug)]
pub enum UntrackedAction {}

/// Type marker for evaluator tracked action types.
#[derive(Debug)]
pub struct EvaluatorTrackedActionTypes;

impl TrackedActionTypes for EvaluatorTrackedActionTypes {
    type Id = ();

    type Action = Action;

    type Result = ();
}

/// Container for evaluator actions.
pub type ActionContainer = Vec<fasm::actions::Action<UntrackedAction, EvaluatorTrackedActionTypes>>;

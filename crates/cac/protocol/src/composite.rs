//! Combined inputs and actions of all state machines.

use crate::{
    evaluator::{ActionContainer as EvaluatorActionContainer, input::Input as EvaluatorInput},
    garbler::{ActionContainer as GarblerActionContainer, input::Input as GarblerInput},
};

/// All possible state machine inputs
#[derive(Debug)]
pub enum Input {
    /// Garbler SM inputs
    Garbler(GarblerInput),
    /// Evaluator SM inputs
    Evaluator(EvaluatorInput),
}

/// All possible action container outputs
#[derive(Debug)]
pub enum ActionContainer {
    /// Garbler action container
    Garbler(GarblerActionContainer),
    /// Evaluator action container
    Evaluator(EvaluatorActionContainer),
}

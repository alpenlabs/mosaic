//! state machine executor implementation.

mod db;
mod error;
mod evaluator;
mod garbler;

use std::sync::Arc;

use db::Db;
pub use error::{ExecutorError, ExecutorResult};
use mosaic_cac_types::state_machine::{
    StateMachineId,
    evaluator::{ActionContainer as EvaluatorActionContainer, Input as EvaluatorInput},
    garbler::{ActionContainer as GarblerActionContainer, Input as GarblerInput},
};

use crate::{evaluator::handle_evaluator_input, garbler::handle_garbler_input};

/// All possible state machine inputs
#[derive(Debug)]
pub enum Input {
    /// Garbler SM inputs
    Garbler(GarblerInput),
    /// Evaluator SM inputs
    Evaluator(EvaluatorInput),
}

/// Input to state machine executor, consisiting of state machine id and input to state machine.
#[derive(Debug)]
pub struct ExecutorInput {
    /// Id of state machine to run.
    pub sm_id: StateMachineId,
    /// Input to the state machine.
    pub sm_input: Input,
}

/// All possible action container outputs
#[derive(Debug)]
pub enum ActionContainer {
    /// Garbler action container
    Garbler(GarblerActionContainer),
    /// Evaluator action container
    Evaluator(EvaluatorActionContainer),
}

/// State machien action with additional metadata sent to action runner.
#[derive(Debug)]
pub struct ExecutorAction {
    /// Id of statemachine that dispatched this action.
    pub sm_id: StateMachineId,
    /// Actions dispatched by the state machine.
    pub actions: ActionContainer,
    // TODO: identifier for paired mosaic node.
}

/// Load and execute a state machine using provided input.
pub async fn sm_executor<D: Db>(
    ex_input: ExecutorInput,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    let actions = match ex_input.sm_input {
        Input::Garbler(input) => {
            let actions = handle_garbler_input(ex_input.sm_id, input, db.clone()).await?;

            ActionContainer::Garbler(actions)
        }
        Input::Evaluator(input) => {
            let actions = handle_evaluator_input(ex_input.sm_id, input, db.clone()).await?;

            ActionContainer::Evaluator(actions)
        }
    };

    Ok(actions)
}

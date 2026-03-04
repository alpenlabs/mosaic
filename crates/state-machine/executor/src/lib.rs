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
    evaluator::{
        ActionContainer as EvaluatorActionContainer, EvaluatorInitData, Input as EvaluatorInput,
    },
    garbler::{ActionContainer as GarblerActionContainer, GarblerInitData, Input as GarblerInput},
};

use crate::{
    evaluator::{handle_evaluator_init, handle_evaluator_input, handle_evaluator_restore},
    garbler::{handle_garbler_init, handle_garbler_input, handle_garbler_restore},
};

/// All possible state machine inputs
#[derive(Debug)]
pub enum Input {
    /// Garbler SM inputs
    Garbler(GarblerInput),
    /// Special case to initialize garbler state machine
    GarblerInit(GarblerInitData),
    /// Restore state machine and re-dispatch actions.
    GarblerRestore,
    /// Evaluator SM inputs
    Evaluator(EvaluatorInput),
    /// Special case to initialize evaluator state machine
    EvaluatorInit(EvaluatorInitData),
    /// Restore state machine and re-dispatch actions.
    EvaluatorRestore,
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

/// State machine action with additional metadata sent to action runner.
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
    let sm_id = ex_input.sm_id;
    let actions = match ex_input.sm_input {
        Input::Garbler(input) => {
            let actions = handle_garbler_input(sm_id, input, db).await?;

            ActionContainer::Garbler(actions)
        }
        Input::GarblerInit(init_data) => {
            let actions = handle_garbler_init(sm_id, init_data, db).await?;

            ActionContainer::Garbler(actions)
        }
        Input::GarblerRestore => {
            let actions = handle_garbler_restore(sm_id, db).await?;

            ActionContainer::Garbler(actions)
        }
        Input::Evaluator(input) => {
            let actions = handle_evaluator_input(sm_id, input, db).await?;

            ActionContainer::Evaluator(actions)
        }
        Input::EvaluatorInit(init_data) => {
            let actions = handle_evaluator_init(sm_id, init_data, db).await?;

            ActionContainer::Evaluator(actions)
        }
        Input::EvaluatorRestore => {
            let actions = handle_evaluator_restore(sm_id, db).await?;

            ActionContainer::Evaluator(actions)
        }
    };

    Ok(actions)
}

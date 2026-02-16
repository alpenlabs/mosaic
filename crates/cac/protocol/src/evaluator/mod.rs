#![allow(missing_docs)]
use std::marker::PhantomData;

use fasm::{
    StateMachine,
    actions::{Action as FasmAction, TrackedAction},
};
use mosaic_cac_types::state_machine::evaluator::{
    Action, ActionContainer, EvaluatorTrackedActionTypes, Input, UntrackedAction,
};

pub mod artifact;
pub mod deposit;
pub mod state;
mod stf;

use artifact::EvaluatorArtifactStore;
use state::State;

use crate::{SMError, SMResult};

#[derive(Debug)]
pub struct EvaluatorSM<S: EvaluatorArtifactStore> {
    _s: PhantomData<S>,
}

/// Push a single action into the FASM actions container with proper tracking ID.
pub(crate) fn emit(actions: &mut ActionContainer, action: Action) {
    let id = action.id();
    actions.push(FasmAction::Tracked(TrackedAction::new(id, action)));
}

impl<S: EvaluatorArtifactStore> StateMachine for EvaluatorSM<S> {
    type State = State<S>;

    type Input = Input;

    type TrackedAction = EvaluatorTrackedActionTypes;

    type UntrackedAction = UntrackedAction;

    type Actions = ActionContainer;

    type TransitionError = SMError;

    type RestoreError = SMError;

    async fn stf(
        state: &mut Self::State,
        input: fasm::Input<Self::TrackedAction, Self::Input>,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::TransitionError> {
        use fasm::Input::*;
        match input {
            Normal(input) => {
                stf::handle_event(state, input, actions).await?;
            }
            TrackedActionCompleted { id, result } => {
                stf::handle_action_result(state, id, result, actions).await?;
            }
        };

        Ok(())
    }

    async fn restore(
        state: &Self::State,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::RestoreError> {
        stf::restore(state, actions).await?;

        Ok(())
    }
}

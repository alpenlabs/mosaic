#![allow(missing_docs)]
use std::marker::PhantomData;

use fasm::{StateMachine, actions::Action as FasmAction};
use mosaic_cac_types::state_machine::evaluator::{
    Action, ActionContainer, EvaluatorTrackedActionTypes, Input, StateMut, UntrackedAction,
};

mod stf;
#[cfg(test)]
mod tests;

use crate::SMError;

#[derive(Debug)]
pub struct EvaluatorSM<S: StateMut> {
    _s: PhantomData<S>,
}

/// Push a single action into the FASM actions container with proper tracking ID.
pub(crate) fn emit(actions: &mut ActionContainer, action: Action) {
    let id = action.id();
    actions.push(FasmAction::new_tracked(id, action));
}

impl<S: StateMut> StateMachine for EvaluatorSM<S> {
    type State = S;
    type RestoreState = S;

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
        state: &Self::RestoreState,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::RestoreError> {
        stf::restore(state, actions).await?;

        Ok(())
    }
}

#![allow(missing_docs)]
use std::marker::PhantomData;

use fasm::{
    StateMachine,
    actions::{Action as FasmAction, TrackedAction},
};
use mosaic_cac_types::state_machine::garbler::{
    ActionContainer, GarblerTrackedActionTypes, Input, UntrackedAction,
};

pub mod artifact;
pub mod deposit;
pub mod state;
mod stf;

use artifact::GarblerArtifactStore;
use state::State;

use crate::SMError;

#[derive(Debug)]
pub struct GarblerSM<S: GarblerArtifactStore> {
    _s: PhantomData<S>,
}

impl<S: GarblerArtifactStore> StateMachine for GarblerSM<S> {
    type State = State<S>;

    type Input = Input;

    type TrackedAction = GarblerTrackedActionTypes;

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
                let emitted_actions = stf::stf(state, input).await?;
                let mut tracked_actions = emitted_actions
                    .into_iter()
                    .map(|action| FasmAction::Tracked(TrackedAction::new((), action)))
                    .collect();
                actions.append(&mut tracked_actions);
            }
            TrackedActionCompleted { .. } => unreachable!(),
        };

        Ok(())
    }

    async fn restore(
        state: &Self::State,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::RestoreError> {
        let emitted_actions = stf::restore(state).await?;
        let mut tracked_actions = emitted_actions
            .into_iter()
            .map(|action| FasmAction::Tracked(TrackedAction::new((), action)))
            .collect();
        actions.append(&mut tracked_actions);

        Ok(())
    }
}

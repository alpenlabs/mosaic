#![allow(missing_docs)]
use std::marker::PhantomData;

use fasm::{
    StateMachine,
    actions::{Action, TrackedAction, TrackedActionTypes},
};

pub mod action;
pub mod deposit;
mod error;
pub mod input;
pub mod state;
mod stf;

pub use error::{GarblerError, GarblerResult};

use crate::garbler::{
    input::Input,
    state::{GarblerArtifactStore, State},
};

#[derive(Debug)]
pub struct GarblerSM<S: GarblerArtifactStore> {
    _s: PhantomData<S>,
}

impl<S: GarblerArtifactStore> StateMachine for GarblerSM<S> {
    type State = State<S>;

    type Input = Input;

    type TrackedAction = GarblerTrackedActionTypes;

    type UntrackedAction = GarblerUntrackedAction;

    type Actions = Vec<Action<GarblerUntrackedAction, GarblerTrackedActionTypes>>;

    type TransitionError = GarblerError;

    type RestoreError = GarblerError;

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
                    .map(|action| Action::Tracked(TrackedAction::new((), action)))
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
            .map(|action| Action::Tracked(TrackedAction::new((), action)))
            .collect();
        actions.append(&mut tracked_actions);

        Ok(())
    }
}

#[derive(Debug)]
pub enum GarblerUntrackedAction {}

#[derive(Debug)]
pub struct GarblerTrackedActionTypes;

impl TrackedActionTypes for GarblerTrackedActionTypes {
    type Id = ();

    type Action = action::Action;

    type Result = ();
}

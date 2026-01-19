#![allow(missing_docs)]
use std::marker::PhantomData;

use fasm::{
    StateMachine,
    actions::{Action, TrackedAction, TrackedActionTypes},
};

pub mod action;
pub mod deposit;
pub mod input;
pub mod state;
mod stf;

use crate::{
    SMError, SMResult,
    evaluator::{
        input::Input,
        state::{EvaluatorArtifactStore, State},
    },
};

#[derive(Debug)]
pub struct EvaluatorSM<S: EvaluatorArtifactStore> {
    _s: PhantomData<S>,
}

impl<S: EvaluatorArtifactStore> StateMachine for EvaluatorSM<S> {
    type State = State<S>;

    type Input = Input;

    type TrackedAction = EvaluatorTrackedActionTypes;

    type UntrackedAction = EvaluatorUntrackedAction;

    type Actions = Vec<Action<EvaluatorUntrackedAction, EvaluatorTrackedActionTypes>>;

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
pub enum EvaluatorUntrackedAction {}

#[derive(Debug)]
pub struct EvaluatorTrackedActionTypes;

impl TrackedActionTypes for EvaluatorTrackedActionTypes {
    type Id = ();

    type Action = action::Action;

    type Result = ();
}

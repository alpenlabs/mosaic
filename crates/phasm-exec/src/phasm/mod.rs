//! Core phasm types and traits.
//!
//! This module contains the core state machine abstractions from the phasm
//! framework, with modifications to support the executor's needs (e.g., field
//! accessors on `TrackedAction`).

mod actions;

use std::future::Future;

pub use actions::{Action, ActionsContainer, TrackedAction, TrackedActionTypes};

/// Input to a state machine's STF.
///
/// # Variants
///
/// - [`Input::Normal`]: Regular input from users or external systems
/// - [`Input::TrackedActionCompleted`]: Result of a tracked action that was previously emitted
#[allow(missing_debug_implementations)]
pub enum Input<TA: TrackedActionTypes, T> {
    /// A normal input from users or external systems.
    Normal(T),
    /// The result of a tracked action that was previously emitted.
    TrackedActionCompleted {
        /// The ID of the completed action.
        id: TA::Id,
        /// The result of the action.
        res: TA::Result,
    },
}

/// A trait for describing a fallible, asynchronous state machine.
///
/// See the phasm documentation for detailed usage and invariants.
pub trait StateMachine {
    /// Type group for Tracked Action - actions that are retryable, restorable
    /// and whose result is given to the state machine after completion.
    type TrackedAction: TrackedActionTypes;
    /// Type for untracked actions - actions that are "fire and forget".
    type UntrackedAction;

    /// Type for a collection of which actions produced by a state transition
    /// can be placed.
    type Actions: ActionsContainer<Self::UntrackedAction, Self::TrackedAction>;

    /// State/data of the state machine.
    type State;
    /// Input type for a single STF invocation
    type Input;

    /// An error that can occur during STF
    type TransitionError;
    /// An error that can occur during state machine restoration
    type RestoreError;

    /// The future type for the State Transition Function.
    type StfFuture<'state, 'actions>: Future<Output = Result<(), Self::TransitionError>>
    where
        'state: 'actions;
    /// The future type for the State Machine Restoration.
    type RestoreFuture<'state, 'actions>: Future<Output = Result<(), Self::RestoreError>>
    where
        'state: 'actions;

    /// The core State Transition Function.
    ///
    /// STF is a pure, deterministic, atomic function:
    /// - **Input**: Current state + input
    /// - **Output**: Updated state + actions to execute
    /// - **Atomicity**: If returns `Err`, state MUST be unchanged
    /// - **Determinism**: Same state + input always produces same output
    fn stf<'state, 'actions>(
        state: &'state mut Self::State,
        input: Input<Self::TrackedAction, Self::Input>,
        actions: &'actions mut Self::Actions,
    ) -> Self::StfFuture<'state, 'actions>
    where
        'state: 'actions;

    /// Restore tracked actions from state after crash/restart.
    ///
    /// After a system crash, `restore()` rebuilds the list of pending tracked
    /// actions that need to be retried or checked for completion.
    fn restore<'state, 'actions>(
        state: &'state Self::State,
        actions: &'actions mut Self::Actions,
    ) -> Self::RestoreFuture<'state, 'actions>
    where
        'state: 'actions;
}

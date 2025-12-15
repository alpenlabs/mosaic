//! Action types and containers for phasm state machines.

use std::fmt::Debug;

/// Trait defining the types associated with tracked actions.
pub trait TrackedActionTypes {
    /// A type used to identify a tracked action within a given state machine.
    type Id: Debug + PartialEq + Eq + PartialOrd;
    /// A type used to represent the action to be performed.
    type Action: Debug + PartialEq + Eq;
    /// A type used to represent the result of the action.
    type Result: Debug;
}

/// A tracked action with its ID.
///
/// Tracked actions are stored in state before emission and can be
/// restored after crashes.
#[derive(Debug, PartialEq, Eq)]
pub struct TrackedAction<Types: TrackedActionTypes> {
    action_id: Types::Id,
    action: Types::Action,
}

impl<Types: TrackedActionTypes> TrackedAction<Types> {
    /// Creates a new tracked action.
    pub fn new(action_id: Types::Id, action: Types::Action) -> Self {
        Self { action_id, action }
    }

    /// Returns a reference to the action ID.
    pub fn id(&self) -> &Types::Id {
        &self.action_id
    }

    /// Returns a reference to the action.
    pub fn action(&self) -> &Types::Action {
        &self.action
    }

    /// Consumes the tracked action and returns its components.
    pub fn into_parts(self) -> (Types::Id, Types::Action) {
        (self.action_id, self.action)
    }
}

/// An action emitted by the state transition function.
#[derive(Debug, PartialEq, Eq)]
pub enum Action<UA, TATypes: TrackedActionTypes> {
    /// A tracked action that requires execution and result feedback.
    Tracked(TrackedAction<TATypes>),
    /// An untracked fire-and-forget action.
    Untracked(UA),
}

/// A trait for describing a fallible container for a set of [`Action`]s.
pub trait ActionsContainer<UA, TA: TrackedActionTypes> {
    /// Error type for container operations.
    type Error;

    /// Creates a new instance of the container.
    fn new() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Creates a new instance of the container with a capacity hint.
    fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Clears the container.
    fn clear(&mut self) -> Result<(), Self::Error>;

    /// Adds an action to the container.
    fn add(&mut self, action: Action<UA, TA>) -> Result<(), Self::Error>;

    /// Returns true if the container is empty.
    fn is_empty(&self) -> bool;

    /// Removes and returns the last action, if any.
    fn pop(&mut self) -> Option<Action<UA, TA>>;
}

impl<UA, TA: TrackedActionTypes> ActionsContainer<UA, TA> for Vec<Action<UA, TA>> {
    type Error = ();

    fn new() -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Vec::new())
    }

    fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Vec::with_capacity(capacity))
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        Vec::clear(self);
        Ok(())
    }

    fn add(&mut self, action: Action<UA, TA>) -> Result<(), Self::Error> {
        self.push(action);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }

    fn pop(&mut self) -> Option<Action<UA, TA>> {
        Vec::pop(self)
    }
}

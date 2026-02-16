//! protocol state machines

mod error;
pub mod evaluator;
pub mod garbler;

pub use error::{SMError, SMResult};

/// Container holding a state and an artifact store.
#[derive(Debug)]
pub struct StateContainer<S, A> {
    state: S,
    artifact_store: A,
}

impl<S, A> StateContainer<S, A> {
    pub(crate) fn state(&self) -> &S {
        &self.state
    }

    pub(crate) fn artifact_store(&self) -> &A {
        &self.artifact_store
    }

    pub(crate) fn state_and_artifact_store_mut(&mut self) -> (&mut S, &mut A) {
        (&mut self.state, &mut self.artifact_store)
    }

    /// Create a [`StateContainer`] from its parts.
    pub fn from_parts(state: S, artifact_store: A) -> Self {
        Self {
            state,
            artifact_store,
        }
    }

    /// Split a [`StateContainer`] into its parts.
    pub fn into_parts(self) -> (S, A) {
        (self.state, self.artifact_store)
    }
}

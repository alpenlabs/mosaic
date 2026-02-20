//! Job submission and completion types.
//!
//! These types define the interface between the SM Scheduler and the Job
//! Scheduler. The SM Scheduler submits batches of actions (one batch per STF
//! call) and receives individual completed results routed by peer ID and role.
//!
//! Action containers are passed through directly from the FASM state machines
//! — no type transformation is needed at the submission boundary.
//!
//! Jobs always retry internally until they succeed — the SM Scheduler never
//! sees failures. Every submitted action eventually produces exactly one
//! [`ActionCompletion`].

use mosaic_cac_types::state_machine::{
    evaluator::{
        ActionContainer as EvaluatorActionContainer, ActionId as EvaluatorActionId,
        ActionResult as EvaluatorActionResult,
    },
    garbler::{
        ActionContainer as GarblerActionContainer, ActionId as GarblerActionId,
        ActionResult as GarblerActionResult,
    },
};
use mosaic_net_svc_api::PeerId;

/// A batch of actions submitted to the scheduler for execution.
///
/// Produced by one STF call on a single state machine. The SM executor submits
/// this directly — the action container is the same type that FASM produces.
///
/// The peer ID plus the [`JobActions`] variant (garbler vs evaluator)
/// uniquely identifies the originating state machine.
#[derive(Debug)]
pub struct JobBatch {
    /// The peer this state machine is paired with.
    pub peer_id: PeerId,
    /// The actions to execute, typed by role.
    pub actions: JobActions,
}

impl JobBatch {
    /// Returns `true` if this batch is from a garbler SM.
    pub fn is_garbler(&self) -> bool {
        self.actions.is_garbler()
    }

    /// Returns `true` if this batch is from an evaluator SM.
    pub fn is_evaluator(&self) -> bool {
        self.actions.is_evaluator()
    }

    /// Number of actions in this batch.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Returns `true` if the batch contains no actions.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Actions from a single STF call, typed by the SM role.
///
/// Uses the FASM `ActionContainer` types directly so no transformation is
/// needed between the SM executor and the job scheduler.
#[derive(Debug)]
pub enum JobActions {
    /// Actions from a garbler state machine.
    Garbler(GarblerActionContainer),
    /// Actions from an evaluator state machine.
    Evaluator(EvaluatorActionContainer),
}

impl JobActions {
    /// Returns `true` if these are garbler actions.
    pub fn is_garbler(&self) -> bool {
        matches!(self, Self::Garbler(_))
    }

    /// Returns `true` if these are evaluator actions.
    pub fn is_evaluator(&self) -> bool {
        matches!(self, Self::Evaluator(_))
    }

    /// Number of actions in the container.
    pub fn len(&self) -> usize {
        match self {
            Self::Garbler(c) => c.len(),
            Self::Evaluator(c) => c.len(),
        }
    }

    /// Returns `true` if the container is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Completed action result, ready to be routed back to the originating SM
/// as a `TrackedActionCompleted { id, result }` input via FASM.
///
/// The peer ID on [`JobCompletion`] plus the variant here (garbler vs
/// evaluator) identifies which SM to deliver to.
#[derive(Debug)]
pub enum ActionCompletion {
    /// Garbler tracked action completed.
    Garbler {
        /// Correlates with the action that was submitted.
        id: GarblerActionId,
        /// Result data produced by executing the action.
        result: GarblerActionResult,
    },
    /// Evaluator tracked action completed.
    Evaluator {
        /// Correlates with the action that was submitted.
        id: EvaluatorActionId,
        /// Result data produced by executing the action.
        result: EvaluatorActionResult,
    },
}

impl ActionCompletion {
    /// Returns `true` if this is a garbler action completion.
    pub fn is_garbler(&self) -> bool {
        matches!(self, Self::Garbler { .. })
    }

    /// Returns `true` if this is an evaluator action completion.
    pub fn is_evaluator(&self) -> bool {
        matches!(self, Self::Evaluator { .. })
    }

    /// Returns the garbler action ID and result, if this is a garbler completion.
    pub fn as_garbler(&self) -> Option<(&GarblerActionId, &GarblerActionResult)> {
        match self {
            Self::Garbler { id, result } => Some((id, result)),
            Self::Evaluator { .. } => None,
        }
    }

    /// Returns the evaluator action ID and result, if this is an evaluator completion.
    pub fn as_evaluator(&self) -> Option<(&EvaluatorActionId, &EvaluatorActionResult)> {
        match self {
            Self::Evaluator { id, result } => Some((id, result)),
            Self::Garbler { .. } => None,
        }
    }

    /// Consume into garbler action ID and result.
    ///
    /// Returns `Err(self)` if this is an evaluator completion, preserving
    /// the value for further handling.
    pub fn into_garbler(self) -> Result<(GarblerActionId, GarblerActionResult), Self> {
        match self {
            Self::Garbler { id, result } => Ok((id, result)),
            other => Err(other),
        }
    }

    /// Consume into evaluator action ID and result.
    ///
    /// Returns `Err(self)` if this is a garbler completion, preserving
    /// the value for further handling.
    pub fn into_evaluator(self) -> Result<(EvaluatorActionId, EvaluatorActionResult), Self> {
        match self {
            Self::Evaluator { id, result } => Ok((id, result)),
            other => Err(other),
        }
    }
}

/// The outcome of a single completed job, routed back to the originating SM
/// as a `TrackedActionCompleted { id, result }` input via FASM.
///
/// The peer ID plus the [`ActionCompletion`] variant (garbler vs evaluator)
/// identifies which SM to deliver to.
///
/// Jobs always retry internally until they succeed — every submitted action
/// eventually produces exactly one completion. There is no failure variant.
#[derive(Debug)]
pub struct JobCompletion {
    /// The peer whose SM this result should be routed to.
    pub peer_id: PeerId,
    /// The completed action, ready to feed into the SM.
    pub completion: ActionCompletion,
}

impl JobCompletion {
    /// Returns `true` if this completion is for a garbler SM.
    pub fn is_garbler(&self) -> bool {
        self.completion.is_garbler()
    }

    /// Returns `true` if this completion is for an evaluator SM.
    pub fn is_evaluator(&self) -> bool {
        self.completion.is_evaluator()
    }
}

use bytes::Bytes;

/// Describes how we should proceed from a step.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StepResult {
    /// The computation is still in progress and should be repeated.
    Next,

    /// The computation is complete.
    Complete,

    /// The computation failed for some reason and no amount of retrying will
    /// make it succeed.
    Failed,

    /// We tried to resume or repeat a computation that already finished.
    AlreadyExited,
}

impl StepResult {
    /// Returns if we should keep calling the state.
    pub fn should_execute_next(&self) -> bool {
        matches!(self, Self::Next)
    }

    pub fn is_already_stopped(&self) -> bool {
        matches!(self, Self::AlreadyExited)
    }

    pub fn did_change_state(&self) -> bool {
        !self.is_already_stopped()
    }
}

/// Snapshot of executor state.
///
/// The state produced by the input step index 0.  The state after calling
/// `execute_step` is step 1.  Each call after that is each subsequent step.
#[derive(Clone, Debug)]
pub struct Snapshot {
    step_idx: u64,
    exited: bool,
    data: Bytes,
}

impl Snapshot {
    pub fn new(step_idx: u64, exited: bool, data: Bytes) -> Self {
        Self {
            step_idx,
            exited,
            data,
        }
    }

    pub fn step_idx(&self) -> u64 {
        self.step_idx
    }

    pub fn exited(&self) -> bool {
        self.exited
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}

/// Describes how we should proceed from a step.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StepResult {
    /// The computation is still in progress and should be repeated.
    Next,

    /// The computation is complete.
    Complete,

    /// The computation failed for some reason.
    Failed,

    /// We tried to resume or repeat a computation that already finished.
    AlreadyExited,
}

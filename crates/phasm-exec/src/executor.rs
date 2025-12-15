//! Action executor trait for dispatching state machine actions.

use std::future::Future;

use crate::error::Result;

/// Executor for actions emitted by the state machine.
///
/// Handles both tracked (recoverable) and untracked (fire-and-forget) actions.
/// The executor is responsible for actually performing side effects like:
///
/// - Triggering compute jobs
/// - Making external API calls
/// - Sending notifications
///
/// # Idempotency
///
/// Tracked action implementations **must be idempotent**. The same action may
/// be executed multiple times during crash recovery. Use the action ID as a
/// deduplication key where needed.
pub trait ActionExecutor: Send + Sync + 'static {
    /// The tracked action ID type.
    type ActionId: Clone + Send + Sync;

    /// The tracked action descriptor type.
    type TrackedAction: Clone + Send + Sync;

    /// The result type returned by tracked actions.
    type ActionResult: Clone + Send + Sync;

    /// The untracked action type.
    type UntrackedAction: Clone + Send + Sync;

    /// Executes a tracked action and returns its result.
    ///
    /// This may be called multiple times for the same action during recovery.
    /// Implementations must be idempotent - executing the same action multiple
    /// times should produce the same result and not cause duplicate side
    /// effects.
    ///
    /// The result will be fed back to the state machine as a
    /// `TrackedActionCompleted` input.
    fn execute_tracked(
        &self,
        id: Self::ActionId,
        action: Self::TrackedAction,
    ) -> impl Future<Output = Result<Self::ActionResult>> + Send;

    /// Executes an untracked fire-and-forget action.
    ///
    /// Failures are logged but do not stop the state machine. These are
    /// suitable for notifications, logging, metrics, etc. where duplicates
    /// or missed executions are acceptable.
    fn execute_untracked(&self, action: Self::UntrackedAction) -> impl Future<Output = ()> + Send;
}

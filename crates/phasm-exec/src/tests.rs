//! Tests for the phasm executor.

use std::{
    collections::HashMap,
    future::{Future, Ready},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::{
    ActionExecutor,
    error::Result,
    notify::*,
    phasm::{Action, ActionsContainer, Input, StateMachine, TrackedAction, TrackedActionTypes},
    provider::PhasmProvider,
    run_worker,
    types::{InputSeqNo, PersistedInput, WorkerConfig},
};

// ============================================================================
// Test State Machine: Counter with tracked "double" action
// ============================================================================

/// Tracked action types for the counter state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CounterActionTypes;

impl TrackedActionTypes for CounterActionTypes {
    type Id = u64;
    type Action = CounterTrackedAction;
    type Result = CounterActionResult;
}

/// Tracked actions the counter can emit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CounterTrackedAction {
    /// Double the current value (simulates external computation).
    Double { current_value: u64 },
}

/// Results from tracked actions.
#[derive(Debug, Clone)]
enum CounterActionResult {
    /// Result of doubling.
    Doubled { new_value: u64 },
}

/// Untracked actions (notifications).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CounterUntrackedAction {
    /// Log a message.
    Log(String),
}

/// Input to the counter state machine.
#[derive(Debug, Clone)]
enum CounterInput {
    /// Increment the counter.
    Increment,
    /// Request doubling (triggers tracked action).
    RequestDouble,
}

/// State of the counter.
#[derive(Debug, Clone, Default)]
struct CounterState {
    value: u64,
    next_action_id: u64,
    /// Pending tracked actions (for restore).
    pending_doubles: HashMap<u64, u64>, // action_id -> value at time of request
}

/// Errors from the counter STF.
#[derive(Debug)]
struct CounterError;

impl std::fmt::Display for CounterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "counter error")
    }
}

impl std::error::Error for CounterError {}

/// The counter state machine.
struct CounterStateMachine;

impl StateMachine for CounterStateMachine {
    type TrackedAction = CounterActionTypes;
    type UntrackedAction = CounterUntrackedAction;
    type Actions = Vec<Action<Self::UntrackedAction, Self::TrackedAction>>;
    type State = CounterState;
    type Input = CounterInput;
    type TransitionError = CounterError;
    type RestoreError = CounterError;
    type StfFuture<'state, 'actions>
        = Ready<std::result::Result<(), Self::TransitionError>>
    where
        'state: 'actions;
    type RestoreFuture<'state, 'actions>
        = Ready<std::result::Result<(), Self::RestoreError>>
    where
        'state: 'actions;

    fn stf<'state, 'actions>(
        state: &'state mut Self::State,
        input: Input<Self::TrackedAction, Self::Input>,
        actions: &'actions mut Self::Actions,
    ) -> Self::StfFuture<'state, 'actions>
    where
        'state: 'actions,
    {
        // This is some ridiculous Claude invention.
        let result = (|| {
            match input {
                Input::Normal(CounterInput::Increment) => {
                    state.value += 1;
                    actions
                        .add(Action::Untracked(CounterUntrackedAction::Log(format!(
                            "incremented to {}",
                            state.value
                        ))))
                        .map_err(|_| CounterError)?;
                }
                Input::Normal(CounterInput::RequestDouble) => {
                    // Store in state for restore
                    let action_id = state.next_action_id;
                    state.next_action_id += 1;
                    state.pending_doubles.insert(action_id, state.value);

                    // Emit tracked action
                    actions
                        .add(Action::Tracked(TrackedAction::new(
                            action_id,
                            CounterTrackedAction::Double {
                                current_value: state.value,
                            },
                        )))
                        .map_err(|_| CounterError)?;
                }
                Input::TrackedActionCompleted { id, res } => {
                    // Remove from pending
                    state.pending_doubles.remove(&id);

                    // Apply result
                    match res {
                        CounterActionResult::Doubled { new_value } => {
                            state.value = new_value;
                            actions
                                .add(Action::Untracked(CounterUntrackedAction::Log(format!(
                                    "doubled to {}",
                                    new_value
                                ))))
                                .map_err(|_| CounterError)?;
                        }
                    }
                }
            }
            Ok(())
        })();
        std::future::ready(result)
    }

    fn restore<'state, 'actions>(
        state: &'state Self::State,
        actions: &'actions mut Self::Actions,
    ) -> Self::RestoreFuture<'state, 'actions>
    where
        'state: 'actions,
    {
        // This is some ridiculous Claude invention.
        let result = (|| {
            actions.clear();

            for (&action_id, &value) in &state.pending_doubles {
                actions
                    .add(Action::Tracked(TrackedAction::new(
                        action_id,
                        CounterTrackedAction::Double {
                            current_value: value,
                        },
                    )))
                    .map_err(|_| CounterError)?;
            }

            Ok(())
        })();
        std::future::ready(result)
    }
}

// ============================================================================
// Mock Provider
// ============================================================================

/// In-memory provider for testing.
#[derive(Debug)]
struct MockProvider {
    state: Arc<Mutex<Option<CounterState>>>,
    inputs: Arc<Mutex<Vec<PersistedInput<CounterInput>>>>,
    last_processed: Arc<Mutex<Option<InputSeqNo>>>,
    next_seq: Arc<AtomicU64>,
}

impl MockProvider {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            inputs: Arc::new(Mutex::new(Vec::new())),
            last_processed: Arc::new(Mutex::new(None)),
            next_seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Add an input to the queue (simulates external code persisting input).
    fn add_input(&self, input: CounterInput) -> InputSeqNo {
        let seq = InputSeqNo::new(self.next_seq.fetch_add(1, Ordering::SeqCst));
        let mut inputs = self.inputs.lock().unwrap();
        inputs.push(PersistedInput::new(seq, input));
        seq
    }

    /// Get the current state (for assertions).
    fn get_state(&self) -> Option<CounterState> {
        self.state.lock().unwrap().clone()
    }

    /// Clone the provider (shares underlying storage).
    fn clone_ref(&self) -> Self {
        Self {
            state: self.state.clone(),
            inputs: self.inputs.clone(),
            last_processed: self.last_processed.clone(),
            next_seq: self.next_seq.clone(),
        }
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PhasmProvider for MockProvider {
    type State = CounterState;
    type NormalInput = CounterInput;

    fn load_state(&self) -> impl Future<Output = Result<Option<Self::State>>> + Send {
        let state = self.state.clone();
        async move { Ok(state.lock().unwrap().clone()) }
    }

    fn save_state(&self, new_state: &Self::State) -> impl Future<Output = Result<()>> + Send {
        let state = self.state.clone();
        let new_state = new_state.clone();
        async move {
            *state.lock().unwrap() = Some(new_state);
            Ok(())
        }
    }

    fn last_processed_seq_no(&self) -> impl Future<Output = Result<Option<InputSeqNo>>> + Send {
        let last = self.last_processed.clone();
        async move { Ok(*last.lock().unwrap()) }
    }

    fn load_pending_inputs(
        &self,
    ) -> impl Future<Output = Result<Vec<PersistedInput<Self::NormalInput>>>> + Send {
        let inputs = self.inputs.clone();
        let last = self.last_processed.clone();
        async move {
            let inputs = inputs.lock().unwrap();
            let last = last.lock().unwrap();
            let pending: Vec<_> = inputs
                .iter()
                .filter(|i| match *last {
                    Some(seq) => i.seq_no > seq,
                    None => true,
                })
                .cloned()
                .collect();
            Ok(pending)
        }
    }

    fn mark_input_processed(&self, seq_no: InputSeqNo) -> impl Future<Output = Result<()>> + Send {
        let last = self.last_processed.clone();
        async move {
            *last.lock().unwrap() = Some(seq_no);
            Ok(())
        }
    }
}

// ============================================================================
// Mock Action Executor
// ============================================================================

/// Mock executor that records actions and produces results.
#[derive(Debug)]
struct MockExecutor {
    /// Tracked actions that were executed.
    tracked_executions: Arc<Mutex<Vec<(u64, CounterTrackedAction)>>>,
    /// Untracked actions that were executed.
    untracked_executions: Arc<Mutex<Vec<CounterUntrackedAction>>>,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            tracked_executions: Arc::new(Mutex::new(Vec::new())),
            untracked_executions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn tracked_count(&self) -> usize {
        self.tracked_executions.lock().unwrap().len()
    }

    fn untracked_count(&self) -> usize {
        self.untracked_executions.lock().unwrap().len()
    }

    /// Clone the executor (shares underlying storage).
    fn clone_ref(&self) -> Self {
        Self {
            tracked_executions: self.tracked_executions.clone(),
            untracked_executions: self.untracked_executions.clone(),
        }
    }
}

impl Default for MockExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor for MockExecutor {
    type ActionId = u64;
    type TrackedAction = CounterTrackedAction;
    type ActionResult = CounterActionResult;
    type UntrackedAction = CounterUntrackedAction;

    fn execute_tracked(
        &self,
        id: Self::ActionId,
        action: Self::TrackedAction,
    ) -> impl Future<Output = Result<Self::ActionResult>> + Send {
        let executions = self.tracked_executions.clone();
        async move {
            executions.lock().unwrap().push((id, action.clone()));

            // Produce result
            match action {
                CounterTrackedAction::Double { current_value } => {
                    Ok(CounterActionResult::Doubled {
                        new_value: current_value * 2,
                    })
                }
            }
        }
    }

    fn execute_untracked(&self, action: Self::UntrackedAction) -> impl Future<Output = ()> + Send {
        let executions = self.untracked_executions.clone();
        async move {
            executions.lock().unwrap().push(action);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Helper to run worker with auto-shutdown after inputs are processed.
/// Uses select! to avoid tokio::spawn lifetime issues with GATs.
async fn run_worker_until_idle<P, E>(
    provider: P,
    executor: E,
    notifier: InputNotifier,
    shutdown_rx: ShutdownReceiver,
    shutdown_handle: ShutdownHandle,
    idle_delay: Duration,
) -> Result<()>
where
    P: PhasmProvider<State = CounterState, NormalInput = CounterInput>,
    E: ActionExecutor<
            ActionId = u64,
            TrackedAction = CounterTrackedAction,
            ActionResult = CounterActionResult,
            UntrackedAction = CounterUntrackedAction,
        >,
{
    // Run the worker with a timeout that triggers shutdown after idle
    let worker_fut = run_worker::<CounterStateMachine, _, _>(
        WorkerConfig::default(),
        CounterState::default(),
        provider,
        executor,
        notifier,
        shutdown_rx,
    );

    tokio::select! {
        result = worker_fut => result,
        _ = async {
            tokio::time::sleep(idle_delay).await;
            shutdown_handle.shutdown();
            // Keep this branch alive until worker finishes
            std::future::pending::<()>().await
        } => unreachable!(),
    }
}

#[tokio::test]
async fn test_simple_increment() {
    let provider = MockProvider::new();
    let executor = MockExecutor::new();

    // Add some inputs
    provider.add_input(CounterInput::Increment);
    provider.add_input(CounterInput::Increment);
    provider.add_input(CounterInput::Increment);

    let (notifier, _sender) = create_input_channel();
    let (shutdown_handle, shutdown_rx) = create_shutdown_channel();

    let provider_clone = provider.clone_ref();
    let executor_clone = executor.clone_ref();

    run_worker_until_idle(
        provider_clone,
        executor_clone,
        notifier,
        shutdown_rx,
        shutdown_handle,
        Duration::from_millis(50),
    )
    .await
    .unwrap();

    // Verify state
    let state = provider.get_state().unwrap();
    assert_eq!(state.value, 3, "counter should be 3 after 3 increments");

    // Verify untracked actions (log messages)
    assert_eq!(executor.untracked_count(), 3, "should have 3 log actions");
}

#[tokio::test]
async fn test_tracked_action_double() {
    let provider = MockProvider::new();
    let executor = MockExecutor::new();

    // Start with value 5, then double
    provider.add_input(CounterInput::Increment); // 1
    provider.add_input(CounterInput::Increment); // 2
    provider.add_input(CounterInput::Increment); // 3
    provider.add_input(CounterInput::Increment); // 4
    provider.add_input(CounterInput::Increment); // 5
    provider.add_input(CounterInput::RequestDouble); // 5 * 2 = 10

    let (notifier, _sender) = create_input_channel();
    let (shutdown_handle, shutdown_rx) = create_shutdown_channel();

    let provider_clone = provider.clone_ref();
    let executor_clone = executor.clone_ref();

    run_worker_until_idle(
        provider_clone,
        executor_clone,
        notifier,
        shutdown_rx,
        shutdown_handle,
        Duration::from_millis(50),
    )
    .await
    .unwrap();

    let state = provider.get_state().unwrap();
    assert_eq!(
        state.value, 10,
        "counter should be 10 after 5 increments and double"
    );
    assert!(
        state.pending_doubles.is_empty(),
        "no pending doubles after completion"
    );

    // Should have 1 tracked execution
    assert_eq!(executor.tracked_count(), 1, "should have 1 tracked action");
    // 5 increment logs + 1 doubled log = 6
    assert_eq!(executor.untracked_count(), 6, "should have 6 log actions");
}

#[tokio::test]
async fn test_recovery_with_pending_action() {
    // Simulate a crash scenario: state has a pending tracked action
    let provider = MockProvider::new();
    let executor = MockExecutor::new();

    // Pre-populate state with a pending double (simulating crash after emitting action)
    {
        let mut state = provider.state.lock().unwrap();
        *state = Some(CounterState {
            value: 7,
            next_action_id: 1,
            pending_doubles: {
                let mut m = HashMap::new();
                m.insert(0, 7); // action 0 was doubling value 7
                m
            },
        });
    }

    let (notifier, _sender) = create_input_channel();
    let (shutdown_handle, shutdown_rx) = create_shutdown_channel();

    let provider_clone = provider.clone_ref();
    let executor_clone = executor.clone_ref();

    run_worker_until_idle(
        provider_clone,
        executor_clone,
        notifier,
        shutdown_rx,
        shutdown_handle,
        Duration::from_millis(50),
    )
    .await
    .unwrap();

    let state = provider.get_state().unwrap();
    // Should have restored and completed the double: 7 * 2 = 14
    assert_eq!(state.value, 14, "counter should be 14 after recovery");
    assert!(
        state.pending_doubles.is_empty(),
        "pending action should be cleared"
    );
    assert_eq!(
        executor.tracked_count(),
        1,
        "should have re-executed the tracked action"
    );
}

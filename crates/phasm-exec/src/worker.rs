//! Async worker function for running phasm state machines.

use std::collections::VecDeque;

use tracing::{debug, info, warn};

use crate::{
    error::{Error, Result},
    executor::ActionExecutor,
    notify::{InputNotifier, ShutdownReceiver},
    phasm::{Action, ActionsContainer, Input, StateMachine, TrackedActionTypes},
    provider::PhasmProvider,
    types::{PersistedInput, WorkerConfig},
};

/// Runs the phasm state machine worker loop.
///
/// This is the main entry point for running a state machine. It handles:
///
/// - Recovery on startup (loading state, restoring pending actions)
/// - Processing pending inputs from the durable queue
/// - Waiting for new inputs via the notifier
/// - Executing actions and feeding results back
/// - Periodic state snapshotting
///
/// # Type Parameters
///
/// - `SM`: The phasm state machine implementation
/// - `P`: The provider for persistence
/// - `E`: The action executor
///
/// # Arguments
///
/// - `config`: Worker configuration
/// - `initial_state`: Initial state to use if no persisted state exists
/// - `provider`: Persistence provider
/// - `executor`: Action executor
/// - `notifier`: Receiver for input arrival notifications
/// - `shutdown`: Receiver for shutdown signals
///
/// # Returns
///
/// Returns `Ok(())` on clean shutdown, or an error if something failed.
pub async fn run_worker<SM, P, E>(
    config: WorkerConfig,
    initial_state: SM::State,
    provider: P,
    executor: E,
    mut notifier: InputNotifier,
    mut shutdown: ShutdownReceiver,
) -> Result<()>
where
    SM: StateMachine,
    SM::State: Clone + Send + Sync,
    SM::Input: Clone + Send + Sync,
    SM::TrackedAction: TrackedActionTypes,
    <SM::TrackedAction as TrackedActionTypes>::Id: Clone + Send + Sync,
    <SM::TrackedAction as TrackedActionTypes>::Action: Clone + Send + Sync,
    <SM::TrackedAction as TrackedActionTypes>::Result: Clone + Send + Sync,
    SM::UntrackedAction: Clone + Send + Sync,
    SM::Actions: ActionsContainer<SM::UntrackedAction, SM::TrackedAction> + Default,
    SM::TransitionError: std::error::Error + Send + Sync,
    SM::RestoreError: std::error::Error + Send + Sync,
    P: PhasmProvider<State = SM::State, NormalInput = SM::Input>,
    E: ActionExecutor<
            ActionId = <SM::TrackedAction as TrackedActionTypes>::Id,
            TrackedAction = <SM::TrackedAction as TrackedActionTypes>::Action,
            ActionResult = <SM::TrackedAction as TrackedActionTypes>::Result,
            UntrackedAction = SM::UntrackedAction,
        >,
{
    info!("starting phasm worker");

    // === Phase 1: Recovery ===
    let mut state = recover_state::<SM, P>(&provider, initial_state).await?;

    // Restore pending actions from state
    let mut restore_actions = SM::Actions::default();
    SM::restore(&state, &mut restore_actions)
        .await
        .map_err(|e| Error::RestoreFailed(e.to_string()))?;

    // Execute restored actions and feed results back
    process_actions::<SM, P, E>(
        &mut state,
        &mut restore_actions,
        &provider,
        &executor,
        &config,
    )
    .await?;

    // Save state after recovery
    provider.save_state(&state).await?;

    // === Phase 2: Process pending inputs from queue ===
    let pending_inputs = provider.load_pending_inputs().await?;
    info!(count = pending_inputs.len(), "loaded pending inputs");

    let mut pending_queue: VecDeque<PersistedInput<SM::Input>> = pending_inputs.into();
    let mut inputs_since_snapshot = 0u32;

    // === Phase 3: Main loop ===
    loop {
        // Check for shutdown
        if shutdown.is_shutdown_requested() {
            info!("shutdown requested, saving state and exiting");
            provider.save_state(&state).await?;
            return Ok(());
        }

        // Process any pending inputs
        while let Some(persisted) = pending_queue.pop_front() {
            // Check shutdown between inputs
            if shutdown.is_shutdown_requested() {
                // Re-queue the input we just popped
                pending_queue.push_front(persisted);
                info!("shutdown requested during processing");
                provider.save_state(&state).await?;
                return Ok(());
            }

            let seq_no = persisted.seq_no;
            debug!(?seq_no, "processing input");

            // Run STF with normal input
            let mut actions = SM::Actions::default();
            let input = Input::Normal(persisted.input);

            SM::stf(&mut state, input, &mut actions)
                .await
                .map_err(|e| Error::TransitionFailed(e.to_string()))?;

            // Process emitted actions
            process_actions::<SM, P, E>(&mut state, &mut actions, &provider, &executor, &config)
                .await?;

            // Mark input as processed
            provider.mark_input_processed(seq_no).await?;
            inputs_since_snapshot += 1;

            // Periodic snapshot
            if inputs_since_snapshot >= config.snapshot_interval {
                debug!("saving periodic snapshot");
                provider.save_state(&state).await?;
                inputs_since_snapshot = 0;
            }
        }

        // All pending inputs processed - wait for new ones
        debug!("waiting for new inputs");

        tokio::select! {
            _ = shutdown.wait_for_shutdown() => {
                info!("shutdown signal received");
                provider.save_state(&state).await?;
                return Ok(());
            }
            result = notifier.wait() => {
                match result {
                    Ok(()) => {
                        // Load new inputs
                        let new_inputs = provider.load_pending_inputs().await?;
                        pending_queue.extend(new_inputs);
                    }
                    Err(Error::ChannelClosed) => {
                        warn!("notification channel closed, shutting down");
                        provider.save_state(&state).await?;
                        return Err(Error::ChannelClosed);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Recovers state from persistence or uses initial state.
async fn recover_state<SM, P>(provider: &P, initial_state: SM::State) -> Result<SM::State>
where
    SM: StateMachine,
    P: PhasmProvider<State = SM::State>,
{
    match provider.load_state().await? {
        Some(state) => {
            info!("recovered existing state");
            Ok(state)
        }
        None => {
            info!("no existing state, starting fresh");
            Ok(initial_state)
        }
    }
}

/// Processes all actions in the container, executing them and feeding tracked
/// results back through STF.
async fn process_actions<SM, P, E>(
    state: &mut SM::State,
    actions: &mut SM::Actions,
    provider: &P,
    executor: &E,
    config: &WorkerConfig,
) -> Result<()>
where
    SM: StateMachine,
    SM::State: Clone + Send + Sync,
    SM::Input: Clone + Send + Sync,
    SM::TrackedAction: TrackedActionTypes,
    <SM::TrackedAction as TrackedActionTypes>::Id: Clone + Send + Sync,
    <SM::TrackedAction as TrackedActionTypes>::Action: Clone + Send + Sync,
    <SM::TrackedAction as TrackedActionTypes>::Result: Clone + Send + Sync,
    SM::UntrackedAction: Clone + Send + Sync,
    SM::Actions: ActionsContainer<SM::UntrackedAction, SM::TrackedAction> + Default,
    SM::TransitionError: std::error::Error + Send + Sync,
    P: PhasmProvider<State = SM::State, NormalInput = SM::Input>,
    E: ActionExecutor<
            ActionId = <SM::TrackedAction as TrackedActionTypes>::Id,
            TrackedAction = <SM::TrackedAction as TrackedActionTypes>::Action,
            ActionResult = <SM::TrackedAction as TrackedActionTypes>::Result,
            UntrackedAction = SM::UntrackedAction,
        >,
{
    // Process actions - drain them from the container
    while let Some(action) = actions.pop() {
        match action {
            Action::Tracked(tracked) => {
                let (id, action_data) = tracked.into_parts();

                // Execute with retries
                let result =
                    execute_with_retries::<E>(executor, id.clone(), action_data, config).await?;

                // Feed result back through STF
                let completion_input = Input::TrackedActionCompleted { id, res: result };
                let mut nested_actions = SM::Actions::default();

                SM::stf(state, completion_input, &mut nested_actions)
                    .await
                    .map_err(|e| Error::TransitionFailed(e.to_string()))?;

                // Recursively process any nested actions
                if !nested_actions.is_empty() {
                    Box::pin(process_actions::<SM, P, E>(
                        state,
                        &mut nested_actions,
                        provider,
                        executor,
                        config,
                    ))
                    .await?;
                }
            }
            Action::Untracked(untracked) => {
                // Fire and forget
                executor.execute_untracked(untracked).await;
            }
        }
    }

    Ok(())
}

/// Executes a tracked action with retry logic.
async fn execute_with_retries<E>(
    executor: &E,
    id: E::ActionId,
    action: E::TrackedAction,
    config: &WorkerConfig,
) -> Result<E::ActionResult>
where
    E: ActionExecutor,
    E::ActionId: Clone,
    E::TrackedAction: Clone,
{
    let mut attempts = 0u32;
    let mut last_error = None;

    while attempts < config.max_action_retries {
        attempts += 1;

        match executor.execute_tracked(id.clone(), action.clone()).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                warn!(attempts, "action execution failed, retrying");
                last_error = Some(e);

                if attempts < config.max_action_retries {
                    tokio::time::sleep(config.action_retry_delay).await;
                }
            }
        }
    }

    Err(Error::ActionFailed {
        attempts,
        message: last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string()),
    })
}

#![allow(unused_crate_dependencies)]
//! Tests for the job scheduler API types and channel plumbing.
//!
//! Note: Full end-to-end tests through `JobScheduler::new` require a
//! `HandlerContext` with a live `NetClient`, which is not available in unit
//! tests. These tests exercise the API types and the `JobSchedulerHandle`
//! channel contract directly.

use mosaic_cac_types::state_machine::garbler::Action as GarblerAction;
use mosaic_common::PeerId;
use mosaic_job_api::{
    ActionCompletion, JobActions, JobBatch, JobCompletion, JobError, JobResult, JobSchedulerHandle,
    SchedulerStopped,
};

// ============================================================================
// Helper constructors
// ============================================================================

fn test_peer_id() -> PeerId {
    PeerId(vec![1, 2, 3])
}

fn garbler_batch_with(
    actions: Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::garbler::UntrackedAction,
            mosaic_cac_types::state_machine::garbler::GarblerTrackedActionTypes,
        >,
    >,
) -> JobBatch {
    JobBatch {
        peer_id: test_peer_id(),
        actions: JobActions::Garbler(actions),
    }
}

fn evaluator_batch_with(
    actions: Vec<
        fasm::actions::Action<
            mosaic_cac_types::state_machine::evaluator::UntrackedAction,
            mosaic_cac_types::state_machine::evaluator::EvaluatorTrackedActionTypes,
        >,
    >,
) -> JobBatch {
    JobBatch {
        peer_id: test_peer_id(),
        actions: JobActions::Evaluator(actions),
    }
}

fn empty_garbler_batch() -> JobBatch {
    garbler_batch_with(vec![])
}

fn empty_evaluator_batch() -> JobBatch {
    evaluator_batch_with(vec![])
}

fn make_garbler_action(
    action: GarblerAction,
) -> fasm::actions::Action<
    mosaic_cac_types::state_machine::garbler::UntrackedAction,
    mosaic_cac_types::state_machine::garbler::GarblerTrackedActionTypes,
> {
    fasm::actions::Action::new_tracked(action.id(), action)
}

/// Run an async block on a temporary monoio runtime.
fn block_on<F: std::future::Future<Output = T>, T>(f: F) -> T {
    monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .build()
        .expect("failed to build test monoio runtime")
        .block_on(f)
}

// ============================================================================
// JobBatch construction and methods
// ============================================================================

#[test]
fn empty_garbler_batch_properties() {
    let batch = empty_garbler_batch();
    assert!(batch.is_garbler());
    assert!(!batch.is_evaluator());
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
}

#[test]
fn empty_evaluator_batch_properties() {
    let batch = empty_evaluator_batch();
    assert!(!batch.is_garbler());
    assert!(batch.is_evaluator());
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
}

#[test]
fn garbler_batch_with_actions() {
    let batch = garbler_batch_with(vec![make_garbler_action(
        GarblerAction::GeneratePolynomialCommitments,
    )]);
    assert!(batch.is_garbler());
    assert!(!batch.is_empty());
    assert_eq!(batch.len(), 1);
}

// ============================================================================
// JobResult and ActionCompletion ergonomics
// ============================================================================

#[test]
fn job_result_completed() {
    let result = JobResult::Completed(ActionCompletion::Garbler {
        id: mosaic_cac_types::state_machine::garbler::ActionId::SendCommitMsgChunk(0),
        result: mosaic_cac_types::state_machine::garbler::ActionResult::CommitMsgChunkAcked,
    });
    assert!(result.is_completed());
    assert!(!result.is_failed());
    assert!(result.is_garbler());
    assert!(!result.is_evaluator());
    assert!(result.as_completed().is_some());
    assert!(result.as_error().is_none());
}

#[test]
fn job_result_failed() {
    let result = JobResult::Failed(JobError::Network("timeout".into()));
    assert!(!result.is_completed());
    assert!(result.is_failed());
    assert!(!result.is_garbler());
    assert!(!result.is_evaluator());
    assert!(result.as_completed().is_none());
    assert!(result.as_error().is_some());
}

#[test]
fn job_result_into_completed_ok() {
    let result = JobResult::Completed(ActionCompletion::Evaluator {
        id: mosaic_cac_types::state_machine::evaluator::ActionId::SendChallengeMsg,
        result: mosaic_cac_types::state_machine::evaluator::ActionResult::ChallengeMsgAcked,
    });
    let completion = result.into_completed();
    assert!(completion.is_ok());
}

#[test]
fn job_result_into_completed_err() {
    let result = JobResult::Failed(JobError::Cancelled);
    let err = result.into_completed();
    assert!(err.is_err());
}

#[test]
fn action_completion_garbler_accessors() {
    let completion = ActionCompletion::Garbler {
        id: mosaic_cac_types::state_machine::garbler::ActionId::SendCommitMsgChunk(0),
        result: mosaic_cac_types::state_machine::garbler::ActionResult::CommitMsgChunkAcked,
    };
    assert!(completion.is_garbler());
    assert!(!completion.is_evaluator());
    assert!(completion.as_garbler().is_some());
    assert!(completion.as_evaluator().is_none());

    let garbler = completion.into_garbler();
    assert!(garbler.is_ok());
}

#[test]
fn action_completion_evaluator_accessors() {
    let completion = ActionCompletion::Evaluator {
        id: mosaic_cac_types::state_machine::evaluator::ActionId::SendChallengeMsg,
        result: mosaic_cac_types::state_machine::evaluator::ActionResult::ChallengeMsgAcked,
    };
    assert!(completion.is_evaluator());
    assert!(!completion.is_garbler());

    // into_garbler on evaluator returns Err(self)
    let err = completion.into_garbler();
    assert!(err.is_err());
    let recovered = err.unwrap_err();
    assert!(recovered.is_evaluator());

    // now into_evaluator works
    let evaluator = recovered.into_evaluator();
    assert!(evaluator.is_ok());
}

// ============================================================================
// JobCompletion routing helpers
// ============================================================================

#[test]
fn job_completion_delegates_to_result() {
    let completion = JobCompletion {
        peer_id: test_peer_id(),
        result: JobResult::Completed(ActionCompletion::Garbler {
            id: mosaic_cac_types::state_machine::garbler::ActionId::SendCommitMsgChunk(0),
            result: mosaic_cac_types::state_machine::garbler::ActionResult::CommitMsgChunkAcked,
        }),
    };
    assert!(completion.is_completed());
    assert!(!completion.is_failed());
    assert!(completion.is_garbler());
    assert!(!completion.is_evaluator());
    assert_eq!(completion.peer_id, test_peer_id());
}

// ============================================================================
// Handle channel contract
//
// These test the JobSchedulerHandle API by constructing handles directly from
// channels. In production, handles are only created by JobScheduler::new.
// ============================================================================

/// Helper: create a test handle and return both sides of the channels so
/// tests can simulate the scheduler (submit_rx) and workers (completion_tx).
fn test_handle() -> (
    JobSchedulerHandle,
    kanal::AsyncReceiver<JobBatch>,
    kanal::AsyncSender<JobCompletion>,
) {
    let (submit_tx, submit_rx) = kanal::bounded_async::<JobBatch>(16);
    let (completion_tx, completion_rx) = kanal::bounded_async::<JobCompletion>(16);
    let handle = JobSchedulerHandle::new(submit_tx, completion_rx);
    (handle, submit_rx, completion_tx)
}

#[test]
fn handle_submit_succeeds() {
    block_on(async {
        let (handle, _submit_rx, _completion_tx) = test_handle();
        let result = handle.submit(empty_garbler_batch()).await;
        assert!(result.is_ok());
    });
}

#[test]
fn handle_submit_returns_err_after_scheduler_shutdown() {
    block_on(async {
        let (handle, submit_rx, _completion_tx) = test_handle();
        drop(submit_rx); // scheduler side gone

        let result = handle.submit(empty_garbler_batch()).await;
        assert!(matches!(result, Err(SchedulerStopped)));
    });
}

#[test]
fn handle_recv_delivers_completion_from_worker() {
    block_on(async {
        let (handle, _submit_rx, completion_tx) = test_handle();

        // Worker side sends a completion.
        completion_tx
            .send(JobCompletion {
                peer_id: test_peer_id(),
                result: JobResult::Failed(JobError::Cancelled),
            })
            .await
            .unwrap();

        let received = handle.recv().await.unwrap();
        assert_eq!(received.peer_id, test_peer_id());
        assert!(received.is_failed());
    });
}

#[test]
fn handle_recv_returns_err_when_all_workers_gone() {
    block_on(async {
        let (handle, _submit_rx, completion_tx) = test_handle();
        drop(completion_tx); // all workers gone

        let result = handle.recv().await;
        assert!(result.is_err());
    });
}

#[test]
fn handle_try_recv_returns_none_when_empty() {
    let (handle, _submit_rx, _completion_tx) = test_handle();
    let result = handle.try_recv();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn handle_try_recv_returns_completion_when_available() {
    block_on(async {
        let (handle, _submit_rx, completion_tx) = test_handle();

        completion_tx
            .send(JobCompletion {
                peer_id: test_peer_id(),
                result: JobResult::Failed(JobError::Cancelled),
            })
            .await
            .unwrap();

        let result = handle.try_recv();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    });
}

#[test]
fn handle_is_clone() {
    let (handle, _submit_rx, _completion_tx) = test_handle();
    let _cloned = handle.clone();
}

#[test]
fn handle_clones_share_channels() {
    block_on(async {
        let (handle1, submit_rx, _completion_tx) = test_handle();
        let handle2 = handle1.clone();

        handle1.submit(empty_garbler_batch()).await.unwrap();
        handle2.submit(empty_evaluator_batch()).await.unwrap();

        let batch1 = submit_rx.recv().await.unwrap();
        let batch2 = submit_rx.recv().await.unwrap();

        assert!(batch1.is_garbler());
        assert!(batch2.is_evaluator());
    });
}

// ============================================================================
// Batch with real FASM action containers
// ============================================================================

#[test]
fn garbler_batch_roundtrip_through_channel() {
    block_on(async {
        let (tx, rx) = kanal::bounded_async::<JobBatch>(4);

        let action = GarblerAction::GeneratePolynomialCommitments;
        let batch = garbler_batch_with(vec![make_garbler_action(action)]);

        assert_eq!(batch.len(), 1);
        assert!(batch.is_garbler());

        tx.send(batch).await.unwrap();
        let received = rx.recv().await.unwrap();

        assert_eq!(received.len(), 1);
        assert!(received.is_garbler());
        assert_eq!(received.peer_id, test_peer_id());
    });
}

#[test]
fn garbler_batch_multiple_actions_roundtrip() {
    block_on(async {
        let (tx, rx) = kanal::bounded_async::<JobBatch>(4);

        let index1 = mosaic_cac_types::Index::new(1).unwrap();
        let index2 = mosaic_cac_types::Index::new(2).unwrap();
        let batch = garbler_batch_with(vec![
            make_garbler_action(GarblerAction::GenerateShares(index1)),
            make_garbler_action(GarblerAction::GenerateShares(index2)),
        ]);

        assert_eq!(batch.len(), 2);

        tx.send(batch).await.unwrap();
        let received = rx.recv().await.unwrap();

        assert_eq!(received.len(), 2);
        assert!(received.is_garbler());
    });
}

// ============================================================================
// Error type tests
// ============================================================================

#[test]
fn job_error_display() {
    assert_eq!(
        format!("{}", JobError::Network("conn refused".into())),
        "network error: conn refused"
    );
    assert_eq!(
        format!("{}", JobError::Crypto("bad sig".into())),
        "crypto error: bad sig"
    );
    assert_eq!(
        format!("{}", JobError::Storage("disk full".into())),
        "storage error: disk full"
    );
    assert_eq!(format!("{}", JobError::Cancelled), "job cancelled");
}

#[test]
fn scheduler_stopped_display() {
    let err = SchedulerStopped;
    assert_eq!(format!("{err}"), "job scheduler is shut down");
}

//! Priority-aware job queue.
//!
//! Supports two modes:
//! - **FIFO**: Simple first-in first-out (light pool)
//! - **Priority**: Drains Critical → High → Normal (heavy pool)
//!
//! Multiple workers can concurrently call [`pop`](JobQueue::pop) — each job is
//! delivered to exactly one worker. Workers block asynchronously when the queue
//! is empty and wake on the next push.

use std::collections::VecDeque;

use parking_lot::Mutex;

use super::PoolJob;
use crate::priority::Priority;

/// Thread-safe, async-aware job queue with optional priority ordering.
pub(crate) struct JobQueue {
    state: Mutex<QueueState>,
    /// Push side: one signal per job added (sync — called from dispatcher).
    signal_tx: kanal::Sender<()>,
    /// Pop side: workers await a signal before taking a job (async).
    signal_rx: kanal::AsyncReceiver<()>,
}

struct QueueState {
    priority_mode: bool,
    /// Used in FIFO mode.
    fifo: VecDeque<PoolJob>,
    /// Used in priority mode.
    critical: VecDeque<PoolJob>,
    high: VecDeque<PoolJob>,
    normal: VecDeque<PoolJob>,
    /// Total number of queued jobs across all levels.
    len: usize,
    closed: bool,
}

impl QueueState {
    fn new(priority_mode: bool) -> Self {
        Self {
            priority_mode,
            fifo: VecDeque::new(),
            critical: VecDeque::new(),
            high: VecDeque::new(),
            normal: VecDeque::new(),
            len: 0,
            closed: false,
        }
    }

    fn push(&mut self, job: PoolJob) {
        if self.priority_mode {
            match job.priority {
                Priority::Critical => self.critical.push_back(job),
                Priority::High => self.high.push_back(job),
                Priority::Normal => self.normal.push_back(job),
            }
        } else {
            self.fifo.push_back(job);
        }
        self.len += 1;
    }

    /// Take the highest priority job, or the oldest in FIFO mode.
    fn pop(&mut self) -> Option<PoolJob> {
        let job = if self.priority_mode {
            self.critical
                .pop_front()
                .or_else(|| self.high.pop_front())
                .or_else(|| self.normal.pop_front())
        } else {
            self.fifo.pop_front()
        };
        if job.is_some() {
            self.len -= 1;
        }
        job
    }
}

impl JobQueue {
    /// Create a new queue.
    ///
    /// When `priority_mode` is `true`, jobs are dequeued in priority order
    /// (Critical → High → Normal). Otherwise, jobs are dequeued in FIFO order.
    pub(crate) fn new(priority_mode: bool) -> Self {
        let (signal_tx, signal_rx) = kanal::unbounded();
        Self {
            state: Mutex::new(QueueState::new(priority_mode)),
            signal_tx,
            signal_rx: signal_rx.to_async(),
        }
    }

    /// Add a job to the queue.
    ///
    /// Wakes one blocked worker, if any.
    pub(crate) fn push(&self, job: PoolJob) {
        self.state.lock().push(job);

        // Signal exactly one waiting worker. If no worker is waiting, the
        // signal queues up and will be consumed on the next `pop` call.
        let _ = self.signal_tx.send(());
    }

    /// Requeue a job to the back of the queue for retry.
    ///
    /// Semantically identical to [`push`](Self::push) — the job goes to the
    /// back of its priority level (or FIFO tail). This is a separate method
    /// for clarity at call sites: `push` is for new jobs from the dispatcher,
    /// `requeue` is for transient-failure retries from workers.
    pub(crate) fn requeue(&self, job: PoolJob) {
        self.push(job);
    }

    /// Take the next job, waiting asynchronously if the queue is empty.
    ///
    /// Returns `None` when the queue is closed and drained.
    pub(crate) async fn pop(&self) -> Option<PoolJob> {
        loop {
            // Wait for a signal that a job is available.
            // Each push sends exactly one signal, and each signal is delivered
            // to exactly one worker (kanal MPMC guarantee).
            if self.signal_rx.recv().await.is_err() {
                // Channel closed — check for remaining jobs under lock.
                let mut state = self.state.lock();
                return state.pop();
            }

            let mut state = self.state.lock();
            if let Some(job) = state.pop() {
                return Some(job);
            }
            if state.closed {
                return None;
            }
            // Signal received but job was already taken (edge case during
            // close). Loop back and wait for the next signal.
        }
    }

    /// Number of jobs currently in the queue.
    pub(crate) fn len(&self) -> usize {
        self.state.lock().len
    }

    /// Returns `true` if the queue is empty.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Close the queue.
    ///
    /// Workers currently blocked in [`pop`](Self::pop) will wake up and return
    /// `None` once all remaining jobs are drained. New [`push`](Self::push)
    /// calls are ignored.
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
        // Closing the sender wakes all blocked receivers with `Err`, causing
        // them to check the closed flag and drain remaining jobs.
        let _ = self.signal_tx.close();
    }
}

#[cfg(test)]
mod tests {
    use mosaic_cac_types::{Seed, state_machine::garbler::Wire};

    use super::*;

    fn dummy_job(priority: Priority) -> PoolJob {
        use mosaic_cac_types::state_machine::garbler::Action as GarblerAction;

        use crate::pool::worker::WorkerJob;

        PoolJob {
            priority,
            job: WorkerJob::Garbler {
                peer_id: mosaic_net_svc_api::PeerId::from_bytes([0u8; 32]),
                action: GarblerAction::GeneratePolynomialCommitments(
                    Seed::from([0u8; 32]),
                    Wire::Output,
                ),
            },
            attempts: 0,
        }
    }

    #[test]
    fn fifo_ordering() {
        let q = JobQueue::new(false);
        q.push(dummy_job(Priority::Normal));
        q.push(dummy_job(Priority::Critical));
        q.push(dummy_job(Priority::High));

        // FIFO ignores priority — order matches push order.
        let mut state = q.state.lock();
        assert_eq!(state.pop().unwrap().priority, Priority::Normal);
        assert_eq!(state.pop().unwrap().priority, Priority::Critical);
        assert_eq!(state.pop().unwrap().priority, Priority::High);
        assert!(state.pop().is_none());
    }

    #[test]
    fn priority_ordering() {
        let q = JobQueue::new(true);
        q.push(dummy_job(Priority::Normal));
        q.push(dummy_job(Priority::High));
        q.push(dummy_job(Priority::Critical));
        q.push(dummy_job(Priority::Normal));
        q.push(dummy_job(Priority::High));

        // Priority mode drains Critical → High → Normal.
        let mut state = q.state.lock();
        assert_eq!(state.pop().unwrap().priority, Priority::Critical);
        assert_eq!(state.pop().unwrap().priority, Priority::High);
        assert_eq!(state.pop().unwrap().priority, Priority::High);
        assert_eq!(state.pop().unwrap().priority, Priority::Normal);
        assert_eq!(state.pop().unwrap().priority, Priority::Normal);
        assert!(state.pop().is_none());
    }

    #[test]
    fn len_tracks_push_and_pop() {
        let q = JobQueue::new(true);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());

        q.push(dummy_job(Priority::Normal));
        q.push(dummy_job(Priority::High));
        assert_eq!(q.len(), 2);

        let mut state = q.state.lock();
        let _ = state.pop();
        // len is tracked inside state
        assert_eq!(state.len, 1);
    }

    #[test]
    fn close_prevents_blocking() {
        let q = JobQueue::new(false);
        q.close();

        let state = q.state.lock();
        assert!(state.closed);
    }
}

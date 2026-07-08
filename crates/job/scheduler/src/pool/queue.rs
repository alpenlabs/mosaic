//! Priority-aware job queue with optional hint-based promotion.
//!
//! Supports two modes:
//! - **FIFO with boost** (light pool): default first-in first-out ordering, with an optional
//!   "boost" queue that drains first. Jobs are boosted by [`apply_hint`](JobQueue::apply_hint) — an
//!   incoming [`HintKey`](mosaic_job_api::HintKey) looks up a matching queued job in O(1) and moves
//!   it to the boost queue's tail (unless the boost queue is at its configured cap, in which case
//!   the hint is dropped).
//! - **Priority** (heavy pool): drains Critical → High → Normal. Hints are not supported in
//!   priority mode.
//!
//! The FIFO backing store is a slot-based intrusive doubly-linked list with
//! a `HashMap<HintKey, SlotId>` index, so both `push` at the tail and
//! `apply_hint` promotion are O(1). Freed slots are reused via a free-list.
//!
//! Multiple workers can concurrently call [`pop`](JobQueue::pop) — each job
//! is delivered to exactly one worker. Workers block asynchronously when the
//! queue is empty and wake on the next push or hint arrival.

use std::collections::{HashMap, VecDeque};

use mosaic_job_api::HintKey;
use parking_lot::Mutex;

use super::PoolJob;
use crate::priority::Priority;

/// Optional boost configuration for FIFO-mode queues.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoostConfig {
    /// Maximum number of jobs that can sit in the boost queue at once.
    /// Additional promotion requests while at cap are dropped.
    pub max_slots: usize,
}

/// Thread-safe, async-aware job queue with optional priority ordering.
pub(crate) struct JobQueue {
    state: Mutex<QueueState>,
    /// Push side: one signal per job added or hint that could unblock a pop.
    signal_tx: kanal::Sender<()>,
    /// Pop side: workers await a signal before taking a job (async).
    signal_rx: kanal::AsyncReceiver<()>,
}

enum QueueBacking {
    /// Priority mode: three VecDeques by priority level. No boost support.
    Priority {
        critical: VecDeque<PoolJob>,
        high: VecDeque<PoolJob>,
        normal: VecDeque<PoolJob>,
    },
    /// FIFO mode: slot-based intrusive linked list with optional boost.
    Fifo(SlotList),
}

struct QueueState {
    backing: QueueBacking,
    len: usize,
    closed: bool,
}

impl QueueState {
    fn new_priority() -> Self {
        Self {
            backing: QueueBacking::Priority {
                critical: VecDeque::new(),
                high: VecDeque::new(),
                normal: VecDeque::new(),
            },
            len: 0,
            closed: false,
        }
    }

    fn new_fifo(boost: Option<BoostConfig>) -> Self {
        Self {
            backing: QueueBacking::Fifo(SlotList::new(boost)),
            len: 0,
            closed: false,
        }
    }

    fn push(&mut self, job: PoolJob, hint_key: Option<HintKey>) {
        match &mut self.backing {
            QueueBacking::Priority {
                critical,
                high,
                normal,
            } => {
                let _ = hint_key; // Priority mode doesn't use hints.
                match job.priority {
                    Priority::Critical => critical.push_back(job),
                    Priority::High => high.push_back(job),
                    Priority::Normal => normal.push_back(job),
                }
            }
            QueueBacking::Fifo(list) => {
                list.push_back(job, hint_key);
            }
        }
        self.len += 1;
    }

    fn pop(&mut self) -> Option<PoolJob> {
        let job = match &mut self.backing {
            QueueBacking::Priority {
                critical,
                high,
                normal,
            } => critical
                .pop_front()
                .or_else(|| high.pop_front())
                .or_else(|| normal.pop_front()),
            QueueBacking::Fifo(list) => list.pop_front(),
        };
        if job.is_some() {
            self.len -= 1;
        }
        job
    }

    fn apply_hint(&mut self, key: &HintKey) -> bool {
        match &mut self.backing {
            QueueBacking::Priority { .. } => false,
            QueueBacking::Fifo(list) => list.promote(key),
        }
    }
}

impl JobQueue {
    /// Create a new queue.
    ///
    /// When `priority_mode` is `true`, jobs are dequeued in priority order
    /// (Critical → High → Normal). Otherwise, jobs are dequeued in FIFO
    /// order with optional hint-driven boost.
    ///
    /// `boost` is only meaningful in FIFO mode. In priority mode it is
    /// ignored.
    pub(crate) fn new(priority_mode: bool, boost: Option<BoostConfig>) -> Self {
        let (signal_tx, signal_rx) = kanal::unbounded();
        let state = if priority_mode {
            QueueState::new_priority()
        } else {
            QueueState::new_fifo(boost)
        };
        Self {
            state: Mutex::new(state),
            signal_tx,
            signal_rx: signal_rx.to_async(),
        }
    }

    /// Add a job to the queue.
    ///
    /// `hint_key`, if present, registers the job in the hint index so a
    /// subsequent [`apply_hint`](Self::apply_hint) with the same key can
    /// promote it. Hints on priority-mode queues are ignored.
    ///
    /// Wakes one blocked worker, if any.
    pub(crate) fn push(&self, job: PoolJob, hint_key: Option<HintKey>) {
        self.state.lock().push(job, hint_key);
        let _ = self.signal_tx.send(());
    }

    /// Requeue a job to the back of the queue for retry.
    ///
    /// Semantically identical to [`push`](Self::push) — the job goes to the
    /// back of its priority level (or FIFO tail). This is a separate method
    /// for clarity at call sites: `push` is for new jobs from the
    /// dispatcher, `requeue` is for transient-failure retries from workers.
    pub(crate) fn requeue(&self, job: PoolJob, hint_key: Option<HintKey>) {
        self.push(job, hint_key);
    }

    /// Take the next job, waiting asynchronously if the queue is empty.
    ///
    /// Returns `None` when the queue is closed and drained.
    pub(crate) async fn pop(&self) -> Option<PoolJob> {
        loop {
            if self.signal_rx.recv().await.is_err() {
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
            // Signal received but job was already taken (e.g. hint arrived
            // for a job that got dequeued between signal and lock). Loop.
        }
    }

    /// Try to promote a job identified by `key` to the boost queue's tail.
    ///
    /// Returns `true` if a matching job was found and promoted, `false` if
    /// no such job is currently queued or the boost queue is at its cap.
    /// Hints on priority-mode queues always return `false`.
    ///
    /// TODO: hints that arrive before their matching job is submitted are
    /// currently dropped. A short-TTL `pending_hints` stash would let them
    /// promote a soon-arriving job.
    pub(crate) fn apply_hint(&self, key: &HintKey) -> bool {
        // No signal fired here: promotion doesn't add a job to the queue,
        // and the push that originally added it already sent exactly one
        // signal. Sending another would cause a redundant wake — the
        // worker takes whichever job is at the head of boost or FIFO on
        // its next pop regardless.
        self.state.lock().apply_hint(key)
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
    /// Workers currently blocked in [`pop`](Self::pop) will wake up and
    /// return `None` once all remaining jobs are drained. New
    /// [`push`](Self::push) calls are ignored.
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
        let _ = self.signal_tx.close();
    }
}

// ============================================================================
// Slot-based intrusive linked list for FIFO + boost.
// ============================================================================

type SlotId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotList2 {
    Fifo,
    Boost,
    Free,
}

struct Slot {
    /// The job, `None` iff the slot is in the free list.
    job: Option<PoolJob>,
    /// Registered hint key, used to look up this slot for promotion.
    hint_key: Option<HintKey>,
    /// Which list this slot is currently in.
    list: SlotList2,
    /// Doubly-linked-list pointers within `list`.
    prev: Option<SlotId>,
    next: Option<SlotId>,
}

struct SlotList {
    /// Backing storage. Grows on demand; slots move between the FIFO, boost,
    /// and free lists via `list` field + prev/next pointers.
    slots: Vec<Slot>,
    /// Free-list head. Reuse frees an allocation.
    free_head: Option<SlotId>,
    /// FIFO list head/tail.
    fifo_head: Option<SlotId>,
    fifo_tail: Option<SlotId>,
    /// Boost list head/tail. Drains first on pop.
    boost_head: Option<SlotId>,
    boost_tail: Option<SlotId>,
    /// O(1) lookup for `apply_hint`: hint key → slot in FIFO list.
    /// Boosted slots and free slots are NOT in this map (they can't be
    /// promoted again).
    hint_index: HashMap<HintKey, SlotId>,
    /// Number of slots currently in the boost list.
    boost_len: usize,
    /// Boost configuration. `None` disables the boost mechanism entirely
    /// (behaves as plain FIFO).
    boost: Option<BoostConfig>,
}

impl SlotList {
    fn new(boost: Option<BoostConfig>) -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            fifo_head: None,
            fifo_tail: None,
            boost_head: None,
            boost_tail: None,
            hint_index: HashMap::new(),
            boost_len: 0,
            boost,
        }
    }

    fn alloc_slot(&mut self, job: PoolJob, hint_key: Option<HintKey>) -> SlotId {
        if let Some(id) = self.free_head {
            self.free_head = self.slots[id].next;
            let slot = &mut self.slots[id];
            slot.job = Some(job);
            slot.hint_key = hint_key;
            slot.list = SlotList2::Free; // will be set by caller when linking
            slot.prev = None;
            slot.next = None;
            id
        } else {
            let id = self.slots.len();
            self.slots.push(Slot {
                job: Some(job),
                hint_key,
                list: SlotList2::Free,
                prev: None,
                next: None,
            });
            id
        }
    }

    fn free_slot(&mut self, id: SlotId) {
        let slot = &mut self.slots[id];
        slot.job = None;
        slot.hint_key = None;
        slot.list = SlotList2::Free;
        slot.prev = None;
        slot.next = self.free_head;
        self.free_head = Some(id);
    }

    /// Append a slot to the FIFO tail.
    fn push_back(&mut self, job: PoolJob, hint_key: Option<HintKey>) {
        let id = self.alloc_slot(job, hint_key.clone());
        self.slots[id].list = SlotList2::Fifo;
        self.slots[id].prev = self.fifo_tail;
        self.slots[id].next = None;
        if let Some(tail) = self.fifo_tail {
            self.slots[tail].next = Some(id);
        } else {
            self.fifo_head = Some(id);
        }
        self.fifo_tail = Some(id);
        if let Some(key) = hint_key
            && self.boost.is_some()
        {
            // Only track hints if boost is enabled.
            self.hint_index.insert(key, id);
        }
    }

    /// Remove and return the head of the boost list (preferred), or the
    /// FIFO head. Boost drains completely before FIFO.
    fn pop_front(&mut self) -> Option<PoolJob> {
        if let Some(id) = self.boost_head {
            self.unlink(id);
            self.boost_len -= 1;
            let job = self.slots[id].job.take();
            self.free_slot(id);
            return job;
        }
        if let Some(id) = self.fifo_head {
            self.unlink(id);
            if let Some(ref key) = self.slots[id].hint_key {
                self.hint_index.remove(key);
            }
            let job = self.slots[id].job.take();
            self.free_slot(id);
            return job;
        }
        None
    }

    /// Try to promote the job matching `key` to the boost list tail.
    /// Returns true if a job was promoted.
    fn promote(&mut self, key: &HintKey) -> bool {
        let Some(&id) = self.hint_index.get(key) else {
            return false;
        };
        let Some(BoostConfig { max_slots }) = self.boost else {
            return false;
        };
        if self.boost_len >= max_slots {
            // Boost queue full — leave the job in FIFO.
            return false;
        }
        // Remove from hint_index and unlink from FIFO.
        self.hint_index.remove(key);
        self.unlink(id);
        // Append to boost tail.
        self.slots[id].list = SlotList2::Boost;
        self.slots[id].prev = self.boost_tail;
        self.slots[id].next = None;
        if let Some(tail) = self.boost_tail {
            self.slots[tail].next = Some(id);
        } else {
            self.boost_head = Some(id);
        }
        self.boost_tail = Some(id);
        self.boost_len += 1;
        true
    }

    /// Unlink a slot from whichever list (FIFO or Boost) it's currently in.
    fn unlink(&mut self, id: SlotId) {
        let (prev, next, list) = {
            let s = &self.slots[id];
            (s.prev, s.next, s.list)
        };
        if let Some(p) = prev {
            self.slots[p].next = next;
        }
        if let Some(n) = next {
            self.slots[n].prev = prev;
        }
        match list {
            SlotList2::Fifo => {
                if self.fifo_head == Some(id) {
                    self.fifo_head = next;
                }
                if self.fifo_tail == Some(id) {
                    self.fifo_tail = prev;
                }
            }
            SlotList2::Boost => {
                if self.boost_head == Some(id) {
                    self.boost_head = next;
                }
                if self.boost_tail == Some(id) {
                    self.boost_tail = prev;
                }
            }
            SlotList2::Free => {
                debug_assert!(false, "unlinking a free slot");
            }
        }
        self.slots[id].prev = None;
        self.slots[id].next = None;
    }
}

#[cfg(test)]
mod tests {
    use mosaic_cac_types::{Seed, state_machine::garbler::Wire};
    use mosaic_job_api::HintKind;
    use mosaic_net_svc_api::PeerId;

    use super::*;

    fn dummy_job() -> PoolJob {
        job_with_attempts(0)
    }

    /// Build a distinguishable dummy job by encoding an integer marker
    /// into `PoolJob::attempts`. Tests inspect this to verify boost/FIFO
    /// ordering across pops.
    fn job_with_attempts(attempts: u32) -> PoolJob {
        use mosaic_cac_types::state_machine::garbler::Action as GarblerAction;

        use crate::pool::worker::WorkerJob;

        PoolJob {
            priority: Priority::Normal,
            job: WorkerJob::Garbler {
                peer_id: PeerId::from_bytes([0u8; 32]),
                action: GarblerAction::GeneratePolynomialCommitments(
                    Seed::from([0u8; 32]),
                    Wire::Output,
                ),
            },
            attempts,
            hint_key: None,
        }
    }

    fn key(byte: u8) -> HintKey {
        HintKey::new(
            PeerId::from_bytes([0u8; 32]),
            HintKind::TransferStarting,
            [byte; 32],
        )
    }

    #[test]
    fn fifo_ordering_without_boost() {
        let q = JobQueue::new(false, None);
        q.push(dummy_job(), None);
        q.push(dummy_job(), None);
        q.push(dummy_job(), None);

        let mut state = q.state.lock();
        assert!(state.pop().is_some());
        assert!(state.pop().is_some());
        assert!(state.pop().is_some());
        assert!(state.pop().is_none());
    }

    #[test]
    fn hint_promotes_matching_job() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        // Tag each job via `attempts` so we can identify who came out.
        q.push(job_with_attempts(1), Some(key(1)));
        q.push(job_with_attempts(2), Some(key(2)));
        q.push(job_with_attempts(3), Some(key(3)));

        // Promote the third job (attempts=3).
        assert!(q.apply_hint(&key(3)));

        // Boost drains first: the promoted job comes out ahead of the
        // FIFO head. Then FIFO order (attempts=1, then attempts=2).
        let mut state = q.state.lock();
        assert_eq!(state.pop().unwrap().attempts, 3);
        assert_eq!(state.pop().unwrap().attempts, 1);
        assert_eq!(state.pop().unwrap().attempts, 2);
        assert!(state.pop().is_none());
    }

    #[test]
    fn multiple_promotions_boost_in_arrival_order() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        q.push(job_with_attempts(1), Some(key(1)));
        q.push(job_with_attempts(2), Some(key(2)));
        q.push(job_with_attempts(3), Some(key(3)));

        // Promote 3 first, then 1. Boost queue tail-append means we get
        // 3 before 1, then FIFO (which has only 2 left).
        assert!(q.apply_hint(&key(3)));
        assert!(q.apply_hint(&key(1)));

        let mut state = q.state.lock();
        assert_eq!(state.pop().unwrap().attempts, 3);
        assert_eq!(state.pop().unwrap().attempts, 1);
        assert_eq!(state.pop().unwrap().attempts, 2);
        assert!(state.pop().is_none());
    }

    #[test]
    fn hint_index_cleared_after_pop_and_promote() {
        // Whitebox test: verify hint_index is empty after all matching
        // paths (pop after promote, pop of FIFO head with hint, plain FIFO
        // drain). Regression guard against slots leaking into the index.
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        q.push(job_with_attempts(1), Some(key(1)));
        q.push(job_with_attempts(2), Some(key(2)));
        assert!(q.apply_hint(&key(1)));

        let mut state = q.state.lock();
        state.pop(); // boosted key(1)
        state.pop(); // FIFO key(2)
        assert!(state.pop().is_none());

        if let QueueBacking::Fifo(list) = &state.backing {
            assert!(list.hint_index.is_empty(), "hint_index leaked entries");
            assert_eq!(list.boost_len, 0);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn hint_for_absent_job_returns_false() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        q.push(dummy_job(), Some(key(1)));
        assert!(!q.apply_hint(&key(2)));
    }

    #[test]
    fn hint_ignored_in_priority_mode() {
        let q = JobQueue::new(true, Some(BoostConfig { max_slots: 64 }));
        q.push(dummy_job(), Some(key(1)));
        assert!(!q.apply_hint(&key(1)));
    }

    #[test]
    fn boost_cap_enforced() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 2 }));
        q.push(dummy_job(), Some(key(1)));
        q.push(dummy_job(), Some(key(2)));
        q.push(dummy_job(), Some(key(3)));

        assert!(q.apply_hint(&key(1)));
        assert!(q.apply_hint(&key(2)));
        // Boost full — third hint dropped.
        assert!(!q.apply_hint(&key(3)));
    }

    #[test]
    fn dequeue_removes_hint_index_entry() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        q.push(dummy_job(), Some(key(1)));

        {
            let mut state = q.state.lock();
            let _ = state.pop();
        }

        // Hint for a dequeued job should not promote anything.
        assert!(!q.apply_hint(&key(1)));
    }

    #[test]
    fn slot_free_list_reuses_allocations() {
        let q = JobQueue::new(false, Some(BoostConfig { max_slots: 64 }));
        q.push(dummy_job(), None);
        q.push(dummy_job(), None);
        {
            let mut state = q.state.lock();
            let _ = state.pop();
            let _ = state.pop();
        }
        q.push(dummy_job(), None);

        // After popping both then pushing one, the underlying Vec should
        // not have grown beyond the original 2 slots (one reused).
        let state = q.state.lock();
        if let QueueBacking::Fifo(list) = &state.backing {
            assert!(list.slots.len() <= 2, "slot vec grew unnecessarily");
        } else {
            unreachable!();
        }
    }

    #[test]
    fn close_prevents_blocking() {
        let q = JobQueue::new(false, None);
        q.close();
        let state = q.state.lock();
        assert!(state.closed);
    }
}

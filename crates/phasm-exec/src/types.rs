//! Core types for the phasm executor.

use std::time::Duration;

/// Sequence number for ordering inputs in the durable queue.
///
/// Inputs are assigned monotonically increasing sequence numbers when persisted.
/// This enables exactly-once processing semantics through checkpointing.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InputSeqNo(u64);

impl InputSeqNo {
    /// Creates a new sequence number.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Returns the inner value.
    pub const fn inner(&self) -> u64 {
        self.0
    }

    /// Returns the next sequence number.
    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u64> for InputSeqNo {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<InputSeqNo> for u64 {
    fn from(seq: InputSeqNo) -> Self {
        seq.0
    }
}

/// A persisted input entry with its sequence number.
///
/// This represents an input that has been durably stored in the input queue
/// and is waiting to be processed.
#[derive(Clone, Debug)]
pub struct PersistedInput<T> {
    /// Sequence number for ordering.
    pub seq_no: InputSeqNo,
    /// The input data.
    pub input: T,
}

impl<T> PersistedInput<T> {
    /// Creates a new persisted input.
    pub fn new(seq_no: InputSeqNo, input: T) -> Self {
        Self { seq_no, input }
    }
}

/// Configuration for the worker.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Number of inputs to process between state snapshots.
    ///
    /// Lower values provide better crash recovery at the cost of more I/O.
    pub snapshot_interval: u32,

    /// Maximum retry attempts for tracked action execution.
    pub max_action_retries: u32,

    /// Delay between action retry attempts.
    pub action_retry_delay: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: 10,
            max_action_retries: 3,
            action_retry_delay: Duration::from_secs(1),
        }
    }
}

impl WorkerConfig {
    /// Sets the snapshot interval.
    pub fn set_snapshot_interval(&mut self, interval: u32) {
        self.snapshot_interval = interval;
    }

    /// Sets the maximum retry attempts.
    pub fn set_max_retries(&mut self, max_retries: u32) {
        self.max_action_retries = max_retries;
    }

    /// Sets the retry delay.
    pub fn set_retry_delay(&mut self, delay: Duration) {
        self.action_retry_delay = delay;
    }
}


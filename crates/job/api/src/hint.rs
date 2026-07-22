//! Scheduler hint identifiers.
//!
//! Hints are best-effort scheduler-to-scheduler messages that let a sender
//! advise a receiver's scheduler that a specific piece of work is about to
//! arrive, so the receiver can promote the matching job to the front of its
//! queue. See the cooperative-scheduling design doc for the rationale.
//!
//! The queue-layer treats [`HintKey`] as an opaque `Hash + Eq` identifier;
//! it does not interpret the discriminant or payload. The wire-level
//! `SchedulerMessage` types in `mosaic-net-client` are responsible for
//! building `HintKey` values from typed hint variants.

use mosaic_net_svc_api::PeerId;

/// Family of scheduler hint.
///
/// New variants are added at the tail. Wire-side `SchedulerMessage` types
/// map their variants onto these at receive time; unknown wire tags never
/// construct a [`HintKind`], so the enum stays closed at the queue layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HintKind {
    /// Sender is about to open a bulk stream to transfer a garbling table.
    /// Payload: the 32-byte commitment hash.
    TransferStarting,
}

/// Identifier used to route a scheduler hint to a matching queued job.
///
/// A hint fires from one peer's scheduler at another; the `peer` field
/// carries the identity of the *sender* (i.e. "peer X told me they're about
/// to send Y"). The receiver's scheduler builds the same [`HintKey`] at
/// job-submission time and stores it alongside the job so incoming hints
/// can locate the corresponding entry in O(1).
///
/// `kind` discriminates the hint family; `payload` is family-specific —
/// typically a hash-like identifier such as a garbling-table commitment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HintKey {
    /// Identity of the peer this hint is *from* / *for*.
    pub peer: PeerId,
    /// Discriminates the hint family.
    pub kind: HintKind,
    /// Family-specific identifier.
    pub payload: [u8; 32],
}

impl HintKey {
    /// Construct a new hint key.
    pub fn new(peer: PeerId, kind: HintKind, payload: [u8; 32]) -> Self {
        Self {
            peer,
            kind,
            payload,
        }
    }
}

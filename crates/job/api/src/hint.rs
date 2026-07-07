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

/// Identifier used to route a scheduler hint to a matching queued job.
///
/// A hint fires from one peer's scheduler at another; the `peer` field
/// carries the identity of the *sender* (i.e. "peer X told me they're about
/// to send Y"). The receiver's scheduler builds the same [`HintKey`] at
/// job-submission time and stores it alongside the job so incoming hints
/// can locate the corresponding entry in O(1).
///
/// `kind` discriminates the hint family (e.g. `HintKind::TRANSFER_STARTING`).
/// `payload` is family-specific — typically a hash-like identifier such as
/// a garbling-table commitment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HintKey {
    /// Identity of the peer this hint is *from* / *for*.
    pub peer: PeerId,
    /// Discriminates the hint family. See [`HintKind`] for defined values.
    pub kind: u8,
    /// Family-specific identifier.
    pub payload: [u8; 32],
}

impl HintKey {
    /// Construct a new hint key.
    pub fn new(peer: PeerId, kind: u8, payload: [u8; 32]) -> Self {
        Self {
            peer,
            kind,
            payload,
        }
    }
}

/// Numeric discriminants for known hint families.
///
/// New families are added by allocating a new constant. Values are stable
/// across mosaic versions (hints are advisory and best-effort; forward
/// compatibility is maintained by receivers ignoring unknown kinds).
#[derive(Debug)]
pub struct HintKind;

impl HintKind {
    /// Sender is about to open a bulk stream to transfer a garbling table.
    /// Payload: the 32-byte commitment hash.
    pub const TRANSFER_STARTING: u8 = 1;
}

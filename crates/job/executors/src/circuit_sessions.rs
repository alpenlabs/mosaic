//! Concrete [`CircuitSession`] implementations for the garbling coordinator.
//!
//! Each session type wraps a `ckt-gobble` garbling or evaluation instance and
//! processes [`OwnedChunk`] data block-by-block as driven by the coordinator.
//!
//! - [`CommitmentSession`] — G3/E3: hashes ciphertext output for commitment.
//! - [`TransferSession`] — G8: streams ciphertexts to peer via bulk transfer.
//! - [`EvaluationSession`] — E8: evaluates circuit with stored ciphertexts.
//!
//! E4 (`ReceiveGarblingTable`) is a pool action — it receives data from the
//! network and does not need the shared circuit reader.
//!
//! # Enum Wrappers
//!
//! [`GarblerCircuitSession`] and [`EvaluatorCircuitSession`] unify the
//! different session types per role into a single `type Session` for the
//! `ExecuteGarblerJob` / `ExecuteEvaluatorJob` traits.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use ark_ff::PrimeField;
use blake3::Hasher;
use ckt_gobble::{
    Label, OutputTranslationMaterial,
    traits::{
        EvaluationInstance as EvaluationInstanceTrait, GarblingInstance as GarblingInstanceTrait,
    },
    translate_output,
    types::Ciphertext,
};
use cynosure::site_d::{mpsc_light, oneshot};
use futures::{
    FutureExt,
    future::{Either, select},
    pin_mut,
};
use mosaic_cac_types::{
    GarblingSeed, GarblingTableCommitment,
    state_machine::{
        evaluator::{ActionId as EvaluatorActionId, ActionResult as EvaluatorActionResult},
        garbler::{
            ActionId as GarblerActionId, ActionResult as GarblerActionResult, GarblingMetadata,
        },
    },
};
use mosaic_job_api::{
    ActionCompletion, CircuitError, CircuitSession, HandlerOutcome, OwnedBlock, OwnedChunk,
};
use mosaic_net_client::BulkSender;
use mosaic_storage_api::table_store::TableReader;
use mosaic_vs3::{Index, Scalar, Share};

use crate::{
    garbling::{GarblingSession, GarblingSetup, compute_commitment, hash_garbling_params},
    progress::{HEARTBEAT_PERIOD, HeartbeatTracker, ProgressUnit},
};

/// Short-id helper used to label progress logs. Renders the first 4 bytes
/// of a digest as `0x........`. Truncates gracefully if shorter.
fn short_id(digest: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in digest.iter().take(4) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ════════════════════════════════════════════════════════════════════════════
// Gate parsing helpers for OwnedBlock
// ════════════════════════════════════════════════════════════════════════════

/// Read a u32 LE from a byte slice at the given offset.
#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Check if gate at `index` is an AND gate (bit set in type bitmap).
#[inline]
fn is_and_gate(gate_types: &[u8], index: usize) -> bool {
    let byte_idx = index / 8;
    let bit_idx = index % 8;
    (gate_types[byte_idx] >> bit_idx) & 1 != 0
}

/// Process an [`OwnedBlock`] through a **garbling** instance, collecting AND
/// gate ciphertexts into the provided buffer.
fn process_owned_block_garble(
    instance: &mut ckt_gobble::GarblingInstance,
    block: &OwnedBlock,
    ct_buffer: &mut Vec<u8>,
) {
    for i in 0..block.num_gates {
        let offset = i * 12; // 3 × u32
        let in1 = read_u32(&block.gate_data, offset) as usize;
        let in2 = read_u32(&block.gate_data, offset + 4) as usize;
        let out = read_u32(&block.gate_data, offset + 8) as usize;

        if is_and_gate(&block.gate_types, i) {
            let ct = instance.feed_and_gate(in1, in2, out);
            let ct_bytes: [u8; 16] = ct.into();
            ct_buffer.extend_from_slice(&ct_bytes);
        } else {
            instance.feed_xor_gate(in1, in2, out);
        }
    }
}

/// Process an [`OwnedBlock`] through an **evaluation** instance, consuming
/// pre-read ciphertext data for AND gates.
fn process_owned_block_eval(
    instance: &mut ckt_gobble::EvaluationInstance,
    block: &OwnedBlock,
    ct_data: &[u8],
    ct_offset: &mut usize,
) {
    for i in 0..block.num_gates {
        let offset = i * 12; // 3 × u32
        let in1 = read_u32(&block.gate_data, offset) as usize;
        let in2 = read_u32(&block.gate_data, offset + 4) as usize;
        let out = read_u32(&block.gate_data, offset + 8) as usize;

        if is_and_gate(&block.gate_types, i) {
            let mut ct_bytes = [0u8; 16];
            ct_bytes.copy_from_slice(&ct_data[*ct_offset..*ct_offset + 16]);
            *ct_offset += 16;
            instance.feed_and_gate(in1, in2, out, Ciphertext::from(ct_bytes));
        } else {
            instance.feed_xor_gate(in1, in2, out);
        }
    }
}

/// Count AND gates in an [`OwnedBlock`].
fn count_and_gates(block: &OwnedBlock) -> usize {
    let mut count = 0;
    for i in 0..block.num_gates {
        if is_and_gate(&block.gate_types, i) {
            count += 1;
        }
    }
    count
}

// ════════════════════════════════════════════════════════════════════════════
// Type-erased ciphertext reader (for EvaluationSession)
// ════════════════════════════════════════════════════════════════════════════

/// Dyn-compatible wrapper around [`TableReader::read_ciphertext`].
///
/// The [`EvaluationSession`] needs to stream ciphertexts from storage during
/// `process_chunk`, but `TableReader` uses `impl Future` returns (not
/// dyn-compatible). This trait provides a boxed-future alternative so the
/// session can hold a `Box<dyn DynCiphertextReader>` without knowing the
/// concrete storage backend.
pub(crate) trait DynCiphertextReader: Send {
    /// Read the next chunk of ciphertext data into `buf`.
    ///
    /// Returns the number of bytes read. Returns `0` at EOF.
    fn read_ciphertext<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, CircuitError>> + Send + 'a>>;
}

/// Adapts any [`TableReader`] into a `DynCiphertextReader`.
pub(crate) struct CiphertextReaderAdapter<R> {
    reader: R,
}

impl<R> CiphertextReaderAdapter<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R: TableReader + Send> DynCiphertextReader for CiphertextReaderAdapter<R> {
    fn read_ciphertext<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, CircuitError>> + Send + 'a>> {
        Box::pin(async move {
            self.reader
                .read_ciphertext(buf)
                .await
                .map_err(|e| CircuitError::ChunkFailed(format!("ciphertext read: {e}")))
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CommitmentSession (G3/E3)
// ════════════════════════════════════════════════════════════════════════════

/// Circuit session that garbles and hashes ciphertext output for commitment
/// computation. Used by both garbler (G3) and evaluator (E3) — the algorithm
/// is identical, only the data source differs.
pub struct CommitmentSession {
    // Debug impl is manual because GarblingSetup/Hasher don't derive Debug.
    /// The garbling setup (contains the session + translation bytes).
    setup: GarblingSetup,
    /// Running blake3 hasher for the ciphertext stream.
    ct_hasher: Hasher,
    /// blake3 hash of the translation material (computed at creation).
    translate_hash: blake3::Hash,
    /// Output wire IDs from the circuit file (needed for finish).
    output_wire_ids: Vec<u32>,
    /// The circuit index this session is garbling for.
    index: Index,
    /// Whether this is a garbler (G3) or evaluator (E3) session — determines
    /// which ActionId/ActionResult variant to use in the completion.
    is_garbler: bool,
    /// Reusable buffer for ciphertext bytes per chunk.
    ct_buffer: Vec<u8>,
    /// Heartbeat progress tracker for operator visibility.
    heartbeat: HeartbeatTracker,
    /// Cumulative gates processed so far (matches `HeaderV5c::total_gates`).
    gates_processed: u64,
}

impl std::fmt::Debug for CommitmentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitmentSession")
            .field("index", &self.index)
            .field("is_garbler", &self.is_garbler)
            .finish_non_exhaustive()
    }
}

impl CommitmentSession {
    /// Create a new commitment session from a garbling setup.
    ///
    /// `output_wire_ids` should come from the circuit reader's `outputs()`.
    pub fn new(
        setup: GarblingSetup,
        output_wire_ids: Vec<u32>,
        index: Index,
        is_garbler: bool,
        total_gates: u64,
    ) -> Self {
        let translate_hash = blake3::hash(&setup.translation_bytes);
        let label = if is_garbler {
            "garbling.commit"
        } else {
            "garbling.verify"
        };
        let heartbeat = HeartbeatTracker::new(
            label,
            format!("ckt{index}"),
            Some(total_gates),
            ProgressUnit::Blocks,
            HEARTBEAT_PERIOD,
        );

        Self {
            setup,
            ct_hasher: Hasher::new(),
            translate_hash,
            output_wire_ids,
            index,
            is_garbler,
            ct_buffer: Vec::new(),
            heartbeat,
            gates_processed: 0,
        }
    }
}

impl CircuitSession for CommitmentSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        let chunk = Arc::clone(chunk);
        Box::pin(async move {
            for block in &chunk.blocks {
                self.ct_buffer.clear();
                process_owned_block_garble(
                    &mut self.setup.session.instance,
                    block,
                    &mut self.ct_buffer,
                );
                self.ct_hasher.update(&self.ct_buffer);
                self.gates_processed = self.gates_processed.saturating_add(block.num_gates as u64);
            }
            self.heartbeat.maybe_log(self.gates_processed);
            Ok(())
        })
    }

    fn finish(mut self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        self.heartbeat.done(self.gates_processed);
        Box::pin(async move {
            let ct_hash = self.ct_hasher.finalize();

            let finish = self.setup.session.finish(&self.output_wire_ids);
            let params_hash = hash_garbling_params(
                &finish.aes128_key,
                &finish.public_s,
                &finish.constant_one_label,
                &finish.constant_zero_label,
            );
            let commitment = compute_commitment(
                &ct_hash,
                &self.translate_hash,
                &finish.output_label_ct,
                &params_hash,
            );

            if self.is_garbler {
                let metadata = GarblingMetadata {
                    aes128_key: finish.aes128_key,
                    public_s: finish.public_s,
                    constant_zero_label: finish.constant_zero_label,
                    constant_one_label: finish.constant_one_label,
                    output_label_ct: finish.output_label_ct,
                };
                HandlerOutcome::Done(ActionCompletion::Garbler {
                    id: GarblerActionId::GenerateTableCommitment(self.index),
                    result: GarblerActionResult::TableCommitmentGenerated(
                        self.index, commitment, metadata,
                    ),
                })
            } else {
                HandlerOutcome::Done(ActionCompletion::Evaluator {
                    id: EvaluatorActionId::GenerateTableCommitment(self.index),
                    result: EvaluatorActionResult::TableCommitmentGenerated(self.index, commitment),
                })
            }
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TransferSession (G8)
// ════════════════════════════════════════════════════════════════════════════

/// Circuit session that garbles and streams ciphertext to a peer via bulk
/// transfer.
///
/// The commitment is NOT recomputed — it was already computed by G3 and is
/// looked up from storage. This session only produces the ciphertext byte
/// stream. Translation material is sent during session creation (before the
/// coordinator starts reading blocks), so `process_chunk` only handles
/// ciphertext.
///
/// Created by `ExecuteGarblerJob::begin_table_transfer`, which:
/// 1. Loads shares from storage
/// 2. Resolves seed → commitment from SM root state
/// 3. Creates a [`GarblingSession`]
/// 4. Opens a bulk transfer stream to the peer
/// 5. Sends translation material over the stream
/// 6. Returns this session for the coordinator to drive block-by-block
pub struct TransferSession {
    // Debug impl is manual because GarblingSession/Stream don't derive Debug.
    /// The garbling session that processes blocks.
    session: GarblingSession,
    /// Bulk transfer stream to the evaluator peer. Moved into the drain
    /// task when the outbox spawns on the first ciphertext-bearing chunk;
    /// `Some` until then (and forever, for a table with no AND gates).
    stream: Option<BulkSender>,
    /// Outbox decoupling garbling from the wire (see [`TransferOutbox`]).
    outbox: Option<TransferOutbox>,
    /// The garbling seed (for the completion's ActionId).
    seed: GarblingSeed,
    /// Pre-computed commitment from G3 (for the completion's ActionResult).
    commitment: GarblingTableCommitment,
    /// Output wire IDs from the circuit file.
    output_wire_ids: Vec<u32>,
    /// Reusable buffer for ciphertext bytes per block.
    ct_buffer: Vec<u8>,
    /// Heartbeat progress tracker for operator visibility.
    heartbeat: HeartbeatTracker,
    /// Cumulative ciphertext bytes garbled and enqueued to the outbox.
    /// Wire progress trails this by at most the outbox depth.
    bytes_sent: u64,
}

/// Bounded outbox between garbling and the wire, plus the drain task's
/// completion signal.
///
/// Garbling outruns the wire by roughly an order of magnitude, and the
/// coordinator's per-chunk barrier means a session that waits on the wire
/// inside `process_chunk` holds its whole pass hostage to the slowest
/// peer's momentary pace. The outbox absorbs that jitter: `process_chunk`
/// completes as soon as a chunk's ciphertext is *enqueued*, the drain task
/// writes at the peer's own pace during barrier waits, and read (commit
/// pipelining), garble, and transfer all overlap. A peer that is slow for
/// longer than the buffer can absorb fills it, `send` parks, and the
/// worker's strike budget takes over — sustained slowness still evicts,
/// transient slowness no longer couples sessions.
///
/// Teardown relies on `mpsc_light`'s close semantics in both directions:
/// producer drop (finish or eviction) surfaces to the drain as
/// `recv() == None` (flush + FIN), drain death surfaces to the producer
/// as a send error (`ChunkFailed` → normal eviction path).
struct TransferOutbox {
    /// Garbled ciphertext buffers awaiting the wire.
    ct_tx: mpsc_light::Sender<Vec<u8>>,
    /// Spent buffers coming back from the drain for reuse (keeps the
    /// steady state alloc-free, like the old buffer-swap write).
    recycle_rx: mpsc_light::Receiver<Vec<u8>>,
    /// Resolves once the drain has flushed everything and dropped the
    /// stream (FIN on success), or reports the write error.
    done_rx: oneshot::Receiver<Result<(), String>>,
}

/// Outbox depth in garbled chunks (~350 KiB of ciphertext each at the
/// production circuit's AND-gate density): ~2.8 MiB of slack per transfer
/// session, noise next to its ~1 GB garbling instance.
const TRANSFER_OUTBOX_DEPTH: usize = 8;

/// Maximum time a single ciphertext write may wait for the peer to return
/// its buffer. A stalled-but-live peer can otherwise hold the QUIC flow-control
/// window closed indefinitely, leaking the drain thread and bulk stream.
const TRANSFER_CHUNK_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `finish` waits for the drain to flush the outbox tail and FIN.
/// Under the coordinator's per-worker finish window; on expiry the table
/// retries (idempotent — a receipted table drops as `AlreadyComplete`).
const DRAIN_FINISH_TIMEOUT: Duration = Duration::from_secs(30);

/// Stream surface used by the outbox drain.
///
/// Keeping the drain generic makes its timeout and teardown paths testable
/// without constructing a live net service.
trait OutboxStream: Send + 'static {
    fn write(
        &mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + '_>>;

    fn reset(self, code: u32) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

impl OutboxStream for BulkSender {
    fn write(
        &mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + '_>> {
        Box::pin(
            BulkSender::write(self, buf)
                .map(|result| result.map_err(|error| format!("stream write: {error:?}"))),
        )
    }

    fn reset(self, code: u32) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(BulkSender::reset(self, code))
    }
}

async fn write_outbox_chunk<S: OutboxStream>(
    stream: &mut S,
    payload: Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let write = stream.write(payload);
    let delay = futures_timer::Delay::new(timeout)
        .map(move |_| Err(format!("stream write timed out after {timeout:?}")));
    pin_mut!(write);
    pin_mut!(delay);
    match select(write, delay).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

async fn drain_transfer_outbox<S: OutboxStream>(
    mut stream: S,
    mut ct_rx: mpsc_light::Receiver<Vec<u8>>,
    recycle_tx: mpsc_light::Sender<Vec<u8>>,
    write_timeout: Duration,
) -> Result<(), String> {
    while let Some(buf) = ct_rx.recv().await {
        match write_outbox_chunk(&mut stream, buf, write_timeout).await {
            // Hand the spent buffer back for reuse; if the recycle lane is
            // full or its receiver is gone, just drop it.
            Ok(spent) => {
                let _ = recycle_tx.try_send(spent);
            }
            Err(error) => {
                // A plain drop sends FIN, which makes a truncated table look
                // like a clean short transfer. Reset explicitly so the peer
                // observes failure and so a timed-out write cannot survive
                // into a retried transfer indefinitely.
                stream.reset(0).await;
                return Err(error);
            }
        }
    }

    // Producer gone (finish or eviction) and queue drained. Dropping sends
    // FIN after the final successful write.
    drop(stream);
    Ok(())
}

impl std::fmt::Debug for TransferSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferSession")
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl TransferSession {
    /// Create a new transfer session.
    ///
    /// `session` is the garbling session (translation already sent by caller).
    /// `stream` is an open bulk transfer stream to the evaluator.
    pub fn new(
        session: GarblingSession,
        stream: BulkSender,
        seed: GarblingSeed,
        commitment: GarblingTableCommitment,
        output_wire_ids: Vec<u32>,
        total_and_gates: u64,
    ) -> Self {
        // Each AND gate emits 16 ciphertext bytes on the wire.
        let total_bytes = total_and_gates.saturating_mul(16);
        let heartbeat = HeartbeatTracker::new(
            "table.upload",
            short_id(commitment.as_ref()),
            Some(total_bytes),
            ProgressUnit::Bytes,
            HEARTBEAT_PERIOD,
        );
        Self {
            session,
            stream: Some(stream),
            outbox: None,
            seed,
            commitment,
            output_wire_ids,
            ct_buffer: Vec::new(),
            heartbeat,
            bytes_sent: 0,
        }
    }

    /// Spawn the drain on a dedicated thread, moving the stream into it.
    ///
    /// A thread (driving its future with `futures::executor::block_on`)
    /// rather than a runtime task keeps this crate runtime-agnostic —
    /// sessions are created on the coordinator's runtime, driven on worker
    /// runtimes, and driven under tokio in tests. Everything the drain
    /// awaits is channel-based, so no reactor is needed, and there are at
    /// most `max_concurrent` drains alive. Precedent: the circuit-header
    /// read in `expected_table_ciphertext_bytes` uses the same pattern.
    fn spawn_drain(&mut self) {
        let stream = self
            .stream
            .take()
            .expect("spawn_drain called once, before any stream take");
        let (ct_tx, ct_rx) = mpsc_light::bounded::<Vec<u8>>(TRANSFER_OUTBOX_DEPTH);
        let (recycle_tx, recycle_rx) = mpsc_light::bounded::<Vec<u8>>(TRANSFER_OUTBOX_DEPTH);
        let (done_tx, done_rx) = oneshot::oneshot();

        let drain = async move {
            let result =
                drain_transfer_outbox(stream, ct_rx, recycle_tx, TRANSFER_CHUNK_WRITE_TIMEOUT)
                    .await;
            let _ = done_tx.send(result);
            // Dropping ct_rx flips the channel closed: a producer still
            // garbling gets a send error and evicts through the normal
            // path.
        };

        if let Err(e) = std::thread::Builder::new()
            .name("mosaic-drain".to_string())
            .spawn(move || futures::executor::block_on(drain))
        {
            // Thread spawn failure: leave the outbox senders in place; the
            // first send errors (receiver dropped with `drain`) and the
            // session evicts for retry.
            tracing::error!(%e, "failed to spawn transfer drain thread");
        }

        self.outbox = Some(TransferOutbox {
            ct_tx,
            recycle_rx,
            done_rx,
        });
    }
}

impl CircuitSession for TransferSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        let chunk = Arc::clone(chunk);
        Box::pin(async move {
            // Garble each block into the outbox. Enqueueing (not wire
            // delivery) completes the chunk: the drain task owns the wire
            // and writes at the peer's pace, overlapping the coordinator's
            // barrier waits. `send` only parks once the peer has fallen a
            // full outbox behind.
            for block in &chunk.blocks {
                self.ct_buffer.clear();
                process_owned_block_garble(&mut self.session.instance, block, &mut self.ct_buffer);
                if !self.ct_buffer.is_empty() {
                    if self.outbox.is_none() {
                        self.spawn_drain();
                    }
                    let outbox = self.outbox.as_mut().expect("outbox just spawned");

                    let n = self.ct_buffer.len() as u64;
                    let out = std::mem::take(&mut self.ct_buffer);
                    outbox.ct_tx.send(out).await.map_err(|_| {
                        CircuitError::ChunkFailed(
                            "transfer drain closed — peer write failed".to_string(),
                        )
                    })?;
                    self.bytes_sent = self.bytes_sent.saturating_add(n);

                    // Reuse a spent buffer when the drain has returned one.
                    if let Ok(spent) = outbox.recycle_rx.try_recv() {
                        self.ct_buffer = spent;
                    }
                }
            }
            self.heartbeat.maybe_log(self.bytes_sent);
            Ok(())
        })
    }

    fn finish(mut self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        // NB: the summary log fires here, before the returned future runs and
        // the stream is FIN'd on drop. For multi-minute uploads the gap is
        // negligible, but the log marks "session work done" rather than
        // "bytes-on-wire FIN".
        self.heartbeat.done(self.bytes_sent);
        Box::pin(async move {
            // Finalize the garbling session to properly release the ~1 GB
            // working space. We discard the output — the commitment was
            // pre-computed by G3. The drain keeps flushing concurrently.
            let _finish = self.session.finish(&self.output_wire_ids);

            let done = ActionCompletion::Garbler {
                id: GarblerActionId::TransferGarblingTable(self.seed),
                result: GarblerActionResult::GarblingTableTransferred(self.seed, self.commitment),
            };

            match self.outbox.take() {
                Some(outbox) => {
                    // Close the outbox: with all senders gone the drain's
                    // recv() drains the tail then returns None, and the
                    // drain FINs the stream. Only then is the table
                    // complete on the wire — Done must not race the tail.
                    drop(outbox.ct_tx);
                    drop(outbox.recycle_rx);

                    let done_rx = outbox.done_rx;
                    let delay = futures_timer::Delay::new(DRAIN_FINISH_TIMEOUT);
                    pin_mut!(done_rx);
                    pin_mut!(delay);
                    match select(done_rx, delay).await {
                        Either::Left((Ok(Ok(())), _)) => HandlerOutcome::Done(done),
                        Either::Left((Ok(Err(e)), _)) => {
                            tracing::warn!(%e, "transfer drain failed — retrying table");
                            HandlerOutcome::Retry
                        }
                        Either::Left((Err(_), _)) => {
                            tracing::warn!(
                                "transfer drain dropped without result — retrying table"
                            );
                            HandlerOutcome::Retry
                        }
                        Either::Right(_) => {
                            tracing::warn!(
                                timeout = ?DRAIN_FINISH_TIMEOUT,
                                "transfer drain flush timed out — retrying table"
                            );
                            HandlerOutcome::Retry
                        }
                    }
                }
                // No ciphertext was ever produced: dropping self (and the
                // stream still inside it) FINs the empty table body.
                None => HandlerOutcome::Done(done),
            }
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EvaluationSession (E8)
// ════════════════════════════════════════════════════════════════════════════

/// Circuit session that evaluates a stored garbling table.
///
/// Needs both the circuit gate structure (from the shared reader, delivered
/// via `process_chunk`) AND stored ciphertext data (from `TableStore`,
/// read via the `DynCiphertextReader`).
///
/// For each chunk of blocks the coordinator delivers:
/// 1. Count AND gates across all blocks in the chunk.
/// 2. Pre-read exactly that many ciphertexts (16 bytes each) from storage.
/// 3. Feed gates + ciphertexts to the `EvaluationInstance`.
///
/// This keeps the number of storage reads proportional to circuit chunks
/// (~34K reads), not individual AND gates (~2.9B).
///
/// Created by `ExecuteEvaluatorJob::begin_evaluation`, which performs all
/// setup work (share interpolation, label translation, instance creation)
/// before returning this session.
pub struct EvaluationSession {
    // Debug impl is manual because EvaluationInstance/DynCiphertextReader don't derive Debug.
    /// The ckt-gobble evaluation instance (~1 GB working space).
    instance: ckt_gobble::EvaluationInstance,
    /// Type-erased ciphertext reader for streaming AND gate ciphertexts
    /// from the table store.
    ct_reader: Box<dyn DynCiphertextReader>,
    /// The circuit index being evaluated.
    index: Index,
    /// The expected commitment (returned in the completion).
    commitment: GarblingTableCommitment,
    /// Output wire IDs from the circuit file.
    output_wire_ids: Vec<u32>,
    /// Output label ciphertext for translating the evaluation result back
    /// to a share value. Stored as raw bytes ([u8; 32]) since Byte32 may
    /// not be Copy.
    output_label_ct: [u8; 32],
    /// Heartbeat progress tracker for operator visibility.
    heartbeat: HeartbeatTracker,
    /// Cumulative gates evaluated so far (matches `HeaderV5c::total_gates`).
    gates_processed: u64,
}

impl std::fmt::Debug for EvaluationSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvaluationSession")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl EvaluationSession {
    /// Create a new evaluation session.
    ///
    /// All setup (share interpolation, label translation, instance creation,
    /// table reader opening) is done by the caller before constructing this.
    pub(crate) fn new(
        instance: ckt_gobble::EvaluationInstance,
        ct_reader: Box<dyn DynCiphertextReader>,
        index: Index,
        commitment: GarblingTableCommitment,
        output_wire_ids: Vec<u32>,
        output_label_ct: [u8; 32],
        total_gates: u64,
    ) -> Self {
        let heartbeat = HeartbeatTracker::new(
            "table.eval",
            short_id(commitment.as_ref()),
            Some(total_gates),
            ProgressUnit::Blocks,
            HEARTBEAT_PERIOD,
        );
        Self {
            instance,
            ct_reader,
            index,
            commitment,
            output_wire_ids,
            output_label_ct,
            heartbeat,
            gates_processed: 0,
        }
    }
}

impl CircuitSession for EvaluationSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        let chunk = Arc::clone(chunk);
        Box::pin(async move {
            // Count AND gates across all blocks in this chunk so we can
            // pre-read exactly the right number of ciphertexts in one call.
            let and_count: usize = chunk.blocks.iter().map(count_and_gates).sum();

            // Pre-read all ciphertexts needed for this chunk.
            let ct_bytes_needed = and_count * 16;
            let mut ct_data = vec![0u8; ct_bytes_needed];
            if ct_bytes_needed > 0 {
                let mut filled = 0;
                while filled < ct_bytes_needed {
                    let n = self
                        .ct_reader
                        .read_ciphertext(&mut ct_data[filled..])
                        .await?;
                    if n == 0 {
                        return Err(CircuitError::ChunkFailed(
                            "unexpected EOF reading ciphertexts from table store".into(),
                        ));
                    }
                    filled += n;
                }
            }

            // Feed gates + ciphertexts to the evaluation instance.
            let mut ct_offset = 0;
            for block in &chunk.blocks {
                process_owned_block_eval(&mut self.instance, block, &ct_data, &mut ct_offset);
                self.gates_processed = self.gates_processed.saturating_add(block.num_gates as u64);
            }
            debug_assert_eq!(ct_offset, ct_bytes_needed);
            self.heartbeat.maybe_log(self.gates_processed);

            Ok(())
        })
    }

    fn finish(mut self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        self.heartbeat.done(self.gates_processed);
        Box::pin(async move {
            // Extract output labels and values from the evaluation instance.
            let wire_ids: Vec<u64> = self.output_wire_ids.iter().map(|&w| w as u64).collect();
            let n = self.output_wire_ids.len();
            let mut output_labels = vec![[0u8; 16]; n];
            let mut output_values = vec![false; n];
            self.instance.get_labels(&wire_ids, &mut output_labels);
            self.instance.get_values(&wire_ids, &mut output_values);

            // Build output translation material from the stored output label
            // ciphertext and translate the evaluation result back to a share.
            let output_translation_material: OutputTranslationMaterial = vec![self.output_label_ct];
            let label_vec: Vec<Label> = output_labels.iter().map(|l| Label::from(*l)).collect();
            let translate_result =
                translate_output(&label_vec, &output_values, &output_translation_material);

            let output_share = match translate_result {
                Ok(ref results) if !results.is_empty() => results[0].as_ref().map(|bytes| {
                    let scalar = Scalar::from_le_bytes_mod_order(bytes);
                    Share::new(self.index, scalar)
                }),
                _ => None,
            };

            HandlerOutcome::Done(ActionCompletion::Evaluator {
                id: EvaluatorActionId::EvaluateGarblingTable(self.index),
                result: EvaluatorActionResult::TableEvaluationResult(self.commitment, output_share),
            })
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GarblerCircuitSession — enum wrapper for garbler circuit sessions
// ════════════════════════════════════════════════════════════════════════════

/// Unifies garbler circuit session types into a single associated type for
/// `ExecuteGarblerJob::Session`.
///
/// - G3 (`GenerateTableCommitment`) → [`CommitmentSession`]
/// - G8 (`TransferGarblingTable`) → [`TransferSession`]
#[derive(Debug)]
pub enum GarblerCircuitSession {
    /// Garbling for commitment computation (G3).
    Commitment(Box<CommitmentSession>),
    /// Garbling for bulk transfer to evaluator (G8).
    Transfer(Box<TransferSession>),
}

impl CircuitSession for GarblerCircuitSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        match self {
            Self::Commitment(s) => s.process_chunk(chunk),
            Self::Transfer(s) => s.as_mut().process_chunk(chunk),
        }
    }

    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        match *self {
            Self::Commitment(s) => s.finish(),
            Self::Transfer(s) => s.finish(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EvaluatorCircuitSession — enum wrapper for evaluator circuit sessions
// ════════════════════════════════════════════════════════════════════════════

/// Unifies evaluator circuit session types into a single associated type for
/// `ExecuteEvaluatorJob::Session`.
///
/// - E3 (`GenerateTableCommitment`) → [`CommitmentSession`]
/// - E8 (`EvaluateGarblingTable`) → [`EvaluationSession`]
///
/// E4 (`ReceiveGarblingTable`) is a pool action, not a circuit session.
#[derive(Debug)]
pub enum EvaluatorCircuitSession {
    /// Re-garbling for commitment verification (E3).
    Commitment(Box<CommitmentSession>),
    /// Evaluation of a stored garbling table (E8).
    Evaluation(Box<EvaluationSession>),
}

impl CircuitSession for EvaluatorCircuitSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        match self {
            Self::Commitment(s) => s.process_chunk(chunk),
            Self::Evaluation(s) => s.as_mut().process_chunk(chunk),
        }
    }

    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        match *self {
            Self::Commitment(s) => s.finish(),
            Self::Evaluation(s) => s.finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct ProbeStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        reset: Arc<AtomicBool>,
        stall: bool,
    }

    impl OutboxStream for ProbeStream {
        fn write(
            &mut self,
            mut buf: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + '_>> {
            if self.stall {
                Box::pin(futures::future::pending())
            } else {
                self.writes.lock().expect("writes lock").push(buf.clone());
                buf.clear();
                Box::pin(async move { Ok(buf) })
            }
        }

        fn reset(self, _code: u32) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                self.reset.store(true, Ordering::SeqCst);
            })
        }
    }

    #[test]
    fn outbox_drain_flushes_and_recycles_buffers() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let reset = Arc::new(AtomicBool::new(false));
        let (ct_tx, ct_rx) = mpsc_light::bounded(2);
        let (recycle_tx, mut recycle_rx) = mpsc_light::bounded(2);
        ct_tx.try_send(vec![1, 2]).expect("enqueue first buffer");
        ct_tx.try_send(vec![3]).expect("enqueue second buffer");
        drop(ct_tx);

        let stream = ProbeStream {
            writes: Arc::clone(&writes),
            reset: Arc::clone(&reset),
            stall: false,
        };
        let result = std::thread::spawn(move || {
            futures::executor::block_on(drain_transfer_outbox(
                stream,
                ct_rx,
                recycle_tx,
                Duration::from_secs(1),
            ))
        })
        .join()
        .expect("drain thread");

        assert_eq!(result, Ok(()));
        assert_eq!(
            *writes.lock().expect("writes lock"),
            vec![vec![1, 2], vec![3]]
        );
        assert!(!reset.load(Ordering::SeqCst));
        assert_eq!(recycle_rx.try_recv().expect("first recycled buffer"), []);
        assert_eq!(recycle_rx.try_recv().expect("second recycled buffer"), []);
    }

    #[test]
    fn outbox_drain_times_out_resets_and_closes_the_queue() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let reset = Arc::new(AtomicBool::new(false));
        let (ct_tx, ct_rx) = mpsc_light::bounded(1);
        let (recycle_tx, _recycle_rx) = mpsc_light::bounded(1);
        ct_tx.try_send(vec![1]).expect("enqueue buffer");

        let stream = ProbeStream {
            writes,
            reset: Arc::clone(&reset),
            stall: true,
        };
        let result = std::thread::spawn(move || {
            futures::executor::block_on(drain_transfer_outbox(
                stream,
                ct_rx,
                recycle_tx,
                Duration::from_millis(10),
            ))
        })
        .join()
        .expect("drain thread");

        assert!(
            result
                .expect_err("stalled write must fail")
                .contains("timed out")
        );
        assert!(reset.load(Ordering::SeqCst));
        assert!(
            futures::executor::block_on(ct_tx.send(vec![2])).is_err(),
            "producer must observe the dead drain"
        );
    }
}

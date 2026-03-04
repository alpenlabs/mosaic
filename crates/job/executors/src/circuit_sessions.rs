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

use std::{future::Future, pin::Pin, sync::Arc};

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
use mosaic_net_svc_api::Stream;
use mosaic_storage_api::table_store::TableReader;
use mosaic_vs3::{Index, Scalar, Share};

use crate::garbling::{GarblingSession, GarblingSetup, compute_commitment, hash_garbling_params};

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
    ) -> Self {
        let translate_hash = blake3::hash(&setup.translation_bytes);

        Self {
            setup,
            ct_hasher: Hasher::new(),
            translate_hash,
            output_wire_ids,
            index,
            is_garbler,
            ct_buffer: Vec::new(),
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
            }
            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
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
    /// Bulk transfer stream to the evaluator peer.
    stream: Stream,
    /// The garbling seed (for the completion's ActionId).
    seed: GarblingSeed,
    /// Pre-computed commitment from G3 (for the completion's ActionResult).
    pub commitment: GarblingTableCommitment,
    /// Output wire IDs from the circuit file.
    output_wire_ids: Vec<u32>,
    /// Reusable buffer for ciphertext bytes per block.
    ct_buffer: Vec<u8>,
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
        stream: Stream,
        seed: GarblingSeed,
        commitment: GarblingTableCommitment,
        output_wire_ids: Vec<u32>,
    ) -> Self {
        Self {
            session,
            stream,
            seed,
            commitment,
            output_wire_ids,
            ct_buffer: Vec::new(),
        }
    }
}

impl CircuitSession for TransferSession {
    fn process_chunk(
        &mut self,
        chunk: &Arc<OwnedChunk>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        let chunk = Arc::clone(chunk);
        Box::pin(async move {
            // Garble each block and stream the ciphertext to the peer.
            // Writes are per-block to match the standalone handler pattern and
            // keep memory usage bounded.
            for block in &chunk.blocks {
                self.ct_buffer.clear();
                process_owned_block_garble(&mut self.session.instance, block, &mut self.ct_buffer);
                if !self.ct_buffer.is_empty() {
                    self.stream
                        .write(self.ct_buffer.clone())
                        .await
                        .map_err(|e| CircuitError::ChunkFailed(format!("stream write: {e:?}")))?;
                }
            }
            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        Box::pin(async move {
            // Finalize the garbling session to properly release the ~1 GB
            // working space. We discard the output — the commitment was
            // pre-computed by G3.
            let _finish = self.session.finish(&self.output_wire_ids);

            // Dropping self.stream sends FIN to the peer, signalling that
            // all ciphertext data has been transferred.

            HandlerOutcome::Done(ActionCompletion::Garbler {
                id: GarblerActionId::TransferGarblingTable(self.seed),
                result: GarblerActionResult::GarblingTableTransferred(self.seed, self.commitment),
            })
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
    ) -> Self {
        Self {
            instance,
            ct_reader,
            index,
            commitment,
            output_wire_ids,
            output_label_ct,
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
            }
            debug_assert_eq!(ct_offset, ct_bytes_needed);

            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
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

//! Garbling core — a reusable [`GarblingSession`] that drives circuit garbling
//! block-by-block, yielding ciphertext data for the caller to hash, stream, or
//! store as needed.
//!
//! # Design
//!
//! The session separates garbling logic from I/O:
//!
//! ```text
//! let setup = GarblingSession::begin(seed, shares, output_share, &header);
//! // setup.translation_bytes — caller hashes, sends, or stores
//!
//! let mut session = setup.session;
//! for each block from the circuit reader {
//!     let ct_bytes = session.process_block(block);
//!     // ct_bytes — caller hashes, sends, or stores
//! }
//!
//! let finish = session.finish(&output_wire_ids);
//! // finish.output_label_ct, finish.aes128_key, finish.public_s
//! ```
//!
//! This serves:
//! - **G3/E3** (`GenerateTableCommitment`): caller hashes everything with blake3.
//! - **G8** (`TransferGarblingTable`): caller streams everything to the network.
//!
//! # Commitment Format
//!
//! `commitment = blake3(ct_hash ‖ translate_hash ‖ output_label_ct)`
//!
//! [`compute_commitment`] combines the three components. The caller is
//! responsible for hashing the ciphertext stream and translation bytes
//! separately, then combining here.

use ark_ff::{BigInteger, PrimeField};
use bitvec::vec::BitVec;
use ckt_fmtv5_types::{
    GateType,
    v5::c::{Block, HeaderV5c, get_block_num_gates},
};
use ckt_gobble::{
    BitLabel, ByteLabel, Engine, Label, generate_input_translation_material,
    generate_output_translation_material,
    traits::{GarblingInstance as GarblingInstanceTrait, GarblingInstanceConfig, GobbleEngine},
};
use mosaic_cac_types::{GarblingSeed, GarblingTableCommitment, WideLabelWireShares};
use mosaic_common::{Byte32, constants::N_WITHDRAWAL_INPUT_WIRES};
use mosaic_vs3::Share;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

// ════════════════════════════════════════════════════════════════════════════
// Public types
// ════════════════════════════════════════════════════════════════════════════

/// Returned by [`GarblingSession::begin`]. Contains the session and the
/// serialised translation material produced during setup.
#[derive(Debug)]
pub struct GarblingSetup {
    /// The garbling session, ready to process blocks.
    pub session: GarblingSession,
    /// Serialised input translation material. The caller should hash this
    /// (for commitment) and/or send it (for transfer).
    pub translation_bytes: Vec<u8>,
}

/// Returned by [`GarblingSession::finish`] after all blocks are processed.
#[derive(Debug)]
pub struct GarblingFinish {
    /// Output label ciphertext (32 bytes). Encrypts the output share under
    /// the garbler's output label so the evaluator can recover the share.
    pub output_label_ct: Byte32,
    /// AES-128 key used by this garbling instance.
    pub aes128_key: [u8; 16],
    /// Public S value used in the CCRND hash function.
    pub public_s: [u8; 16],
}

/// A garbling session that processes a circuit block-by-block.
///
/// Created via [`begin`](Self::begin). The caller feeds blocks from the v5c
/// circuit reader via [`process_block`](Self::process_block) and collects
/// the ciphertext bytes yielded by each call. After all blocks are processed,
/// call [`finish`](Self::finish) to extract output label material.
pub struct GarblingSession {
    /// The gobble garbling instance (holds ~1 GB working space).
    pub(crate) instance: ckt_gobble::GarblingInstance,
    /// Reusable buffer for ciphertext output from a single block.
    ct_buffer: Vec<u8>,
    /// Running block index for [`get_block_num_gates`].
    block_idx: usize,
    /// Total gates in the circuit.
    total_gates: u64,
    /// Output share as little-endian bytes, kept for [`finish`].
    output_share_bytes: [u8; 32],
    /// AES-128 key, kept for [`finish`].
    aes128_key: [u8; 16],
    /// Public S, kept for [`finish`].
    public_s: [u8; 16],
}

impl std::fmt::Debug for GarblingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarblingSession")
            .field("block_idx", &self.block_idx)
            .field("total_gates", &self.total_gates)
            .finish_non_exhaustive()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Session lifecycle
// ════════════════════════════════════════════════════════════════════════════

impl GarblingSession {
    /// Initialise a garbling session.
    ///
    /// All garbling parameters (delta, labels, AES keys, constant wire labels)
    /// are derived deterministically from `seed` via a ChaCha20 RNG, so
    /// garbling the same circuit with the same seed always produces identical
    /// output.
    ///
    /// Returns a [`GarblingSetup`] containing the ready-to-use session and
    /// the serialised translation material.
    pub fn begin(
        seed: GarblingSeed,
        withdrawal_shares: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES],
        output_share: &Share,
        header: &HeaderV5c,
    ) -> GarblingSetup {
        assert_eq!(
            header.primary_inputs as usize,
            N_WITHDRAWAL_INPUT_WIRES * 8,
            "circuit primary_inputs ({}) must equal N_WITHDRAWAL_INPUT_WIRES × 8 ({})",
            header.primary_inputs,
            N_WITHDRAWAL_INPUT_WIRES * 8,
        );

        // All randomness is derived from this single seeded RNG. The draw
        // order defines the protocol and must not change.
        let mut rng = ChaCha20Rng::from_seed(seed.into());

        // FreeXOR global delta.
        let mut delta_bytes = [0u8; 16];
        rng.fill_bytes(&mut delta_bytes);

        // Byte-level labels: truncate each share's scalar to 16 bytes.
        let byte_labels: [ByteLabel; N_WITHDRAWAL_INPUT_WIRES] = std::array::from_fn(|wire| {
            ByteLabel::new(std::array::from_fn(|val| {
                Label::from(share_to_label_bytes(&withdrawal_shares[wire][val]))
            }))
        });

        // Bit-level labels (FreeXOR: true_label = false_label ⊕ delta).
        #[cfg(target_arch = "aarch64")]
        use ckt_gobble::aarch64::xor128;
        #[cfg(target_arch = "x86_64")]
        use ckt_gobble::x86_64::xor128;

        let delta = Label::from(delta_bytes);

        let mut bit_labels_all: Vec<[BitLabel; 8]> = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
        for _wire in 0..N_WITHDRAWAL_INPUT_WIRES {
            let default_label = Label::default();
            let mut bits = [BitLabel::new([default_label, default_label]); 8];
            for bit in &mut bits {
                let mut false_bytes = [0u8; 16];
                rng.fill_bytes(&mut false_bytes);
                let false_label = Label::from(false_bytes);
                let true_label = Label(unsafe { xor128(false_label.0, delta.0) });
                *bit = BitLabel::new([false_label, true_label]);
            }
            bit_labels_all.push(bits);
        }

        // Input translation material (byte→bit label mapping).
        //
        // Serialised into a flat byte buffer so the caller can hash and/or
        // send it in one shot. Each wire contributes 256 × 8 × 16 = 32 KiB.
        let bytes_per_wire: usize = 256 * 8 * 16;
        let mut translation_bytes = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES * bytes_per_wire);

        for wire in 0..N_WITHDRAWAL_INPUT_WIRES {
            let material = generate_input_translation_material(
                wire as u64,
                byte_labels[wire],
                bit_labels_all[wire],
            );
            for byte_row in &material {
                for ciphertext in byte_row {
                    let ct_bytes: [u8; 16] = (*ciphertext).into();
                    translation_bytes.extend_from_slice(&ct_bytes);
                }
            }
        }

        // Primary input false labels (one per circuit bit input).
        let num_primary = header.primary_inputs as usize;
        let mut primary_false_labels: Vec<[u8; 16]> = Vec::with_capacity(num_primary);
        let mut count = 0;
        'outer: for bits in &bit_labels_all {
            for bit in bits {
                if count >= num_primary {
                    break 'outer;
                }
                primary_false_labels.push(bit.get_label(false).into());
                count += 1;
            }
        }
        assert_eq!(primary_false_labels.len(), num_primary);

        // AES key and public S for the CCRND hash function.
        let mut aes128_key = [0u8; 16];
        rng.fill_bytes(&mut aes128_key);
        let mut public_s = [0u8; 16];
        rng.fill_bytes(&mut public_s);

        // Labels for constant wires (wire 0 = false, wire 1 = true).
        let mut constant_zero_label = [0u8; 16];
        rng.fill_bytes(&mut constant_zero_label);
        let mut constant_one_label = [0u8; 16];
        rng.fill_bytes(&mut constant_one_label);

        // Garbling instance.
        let config = GarblingInstanceConfig {
            scratch_space: header.scratch_space as u32,
            delta: delta_bytes,
            primary_input_false_labels: &primary_false_labels,
            aes128_key,
            public_s,
            constant_zero_label,
            constant_one_label,
        };

        let engine = Engine::new();
        let instance = engine.new_garbling_instance(config);

        let session = GarblingSession {
            instance,
            ct_buffer: Vec::new(),
            block_idx: 0,
            total_gates: header.total_gates(),
            output_share_bytes: scalar_to_le_bytes(&output_share.value()),
            aes128_key,
            public_s,
        };

        GarblingSetup {
            session,
            translation_bytes,
        }
    }

    /// Process one block of gates from the circuit.
    ///
    /// Returns a byte slice containing the ciphertexts produced by AND gates
    /// in this block (16 bytes per AND gate). XOR gates produce no output
    /// (FreeXOR). The returned slice is valid until the next call to
    /// `process_block`.
    pub fn process_block(&mut self, block: &Block) -> &[u8] {
        let gates_in_block = get_block_num_gates(self.total_gates, self.block_idx);
        self.block_idx += 1;
        self.ct_buffer.clear();

        for i in 0..gates_in_block {
            let gate = &block.gates[i];
            let in1 = gate.in1 as usize;
            let in2 = gate.in2 as usize;
            let out = gate.out as usize;

            match block.gate_type(i) {
                GateType::XOR => {
                    self.instance.feed_xor_gate(in1, in2, out);
                }
                GateType::AND => {
                    let ct = self.instance.feed_and_gate(in1, in2, out);
                    let ct_bytes: [u8; 16] = ct.into();
                    self.ct_buffer.extend_from_slice(&ct_bytes);
                }
            }
        }

        &self.ct_buffer
    }

    /// Finalise the session after all blocks have been processed.
    ///
    /// Extracts the garbler's output labels and produces the output
    /// translation material that encrypts the output share under the label.
    ///
    /// `output_wire_ids` comes from the v5c reader's `outputs()`.
    pub fn finish(self, output_wire_ids: &[u32]) -> GarblingFinish {
        let wire_ids: Vec<u64> = output_wire_ids.iter().map(|&w| w as u64).collect();
        let output_values = BitVec::repeat(false, wire_ids.len());
        let mut output_labels = vec![[0u8; 16]; wire_ids.len()];
        self.instance
            .get_selected_labels(&wire_ids, &output_values, &mut output_labels);

        assert_eq!(output_labels.len(), 1, "expected single output wire");
        let output_label = output_labels[0];

        let output_translation = generate_output_translation_material(
            &[BitLabel::new([
                Label::from(output_label),
                Label::from(output_label),
            ])],
            &[self.output_share_bytes],
        )
        .expect("output translation material generation failed");

        assert_eq!(output_translation.len(), 1);
        let output_label_ct: Byte32 = output_translation[0].into();

        GarblingFinish {
            output_label_ct,
            aes128_key: self.aes128_key,
            public_s: self.public_s,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Commitment
// ════════════════════════════════════════════════════════════════════════════

/// `commitment = blake3(ct_hash ‖ translate_hash ‖ output_label_ct)`
///
/// The caller hashes the ciphertext stream and translation bytes separately,
/// then combines them here.
pub fn compute_commitment(
    ct_hash: &blake3::Hash,
    translate_hash: &blake3::Hash,
    output_label_ct: &Byte32,
) -> GarblingTableCommitment {
    let mut data = Vec::with_capacity(32 + 32 + 32);
    data.extend_from_slice(ct_hash.as_bytes());
    data.extend_from_slice(translate_hash.as_bytes());
    data.extend_from_slice(output_label_ct.as_ref());
    Byte32::from(*blake3::hash(&data).as_bytes())
}

// ════════════════════════════════════════════════════════════════════════════
// Scalar / label helpers
// ════════════════════════════════════════════════════════════════════════════

/// Serialize a scalar to 32 little-endian bytes via ark's `BigInteger`.
fn scalar_to_le_bytes(scalar: &mosaic_vs3::Scalar) -> [u8; 32] {
    scalar
        .into_bigint()
        .to_bytes_le()
        .try_into()
        .expect("scalar encodes to exactly 32 bytes")
}

/// Truncate a share's scalar to 16 bytes for use as a garbling label.
///
/// Takes the low 128 bits of the little-endian representation.
fn share_to_label_bytes(share: &Share) -> [u8; 16] {
    let full = scalar_to_le_bytes(&share.value());
    full[..16].try_into().expect("truncate to 16 bytes")
}

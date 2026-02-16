//! Setup Garbler

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use ark_ff::{BigInteger, PrimeField};
use blake3::Hash;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{
    BitLabel, ByteLabel, InputTranslationMaterial, Label, generate_input_translation_material,
    generate_output_translation_material, traits::GarblingInstanceConfig,
};
use ckt_runner_exec::{CircuitReader, GarbleTask, ReaderV5cWrapper, process_task};
use mosaic_cac_types::{
    AllGarblingSeeds, AllGarblingTableCommitments, ChallengeIndices, ChallengeMsg, CircuitInputShares, GarblingTableCommitment, HeapArray, InputPolynomialCommitments, InputPolynomials, InputShares, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares, OutputPolynomial, OutputPolynomialCommitment, OutputShares, ReservedInputShares, ReservedSetupInputShares, Seed, SetupInputs, WideLabelWirePolynomialCommitments, WideLabelWireShares
};
use mosaic_common::{
    Byte32,
    constants::{
        N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS,
        N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
    },
};
use mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Share};
use rand::CryptoRng;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

use crate::deposit_garbler::WaitAdaptorsGarbState;

pub(crate) type LabelBytes = [u8; 16];
pub(crate) type CipherBytes = Byte32;

/// Config
#[derive(Debug)]
pub struct Config {
    _vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    _ckt_file: PathBuf,
}

/// input to InitGarbState
#[derive(Debug)]
pub struct SetupGarbData {
    //_config: Config,
    /// garbler's master seed
    pub seed: Seed,
    /// setup inputs in byte form
    pub setup_input: SetupInputs,
    /// reference to static v5c ckt file
    pub input_v5c_circuit_file: PathBuf,
}

/// InitGarbState
#[derive(Debug)]
pub struct InitGarbState {
    // garbler's master seed
    seed: Seed,
    // setup input in byte form
    setup_input: SetupInputs,
    // reference to static v5c ckt file
    ckt_file: PathBuf,
}

impl InitGarbState {
    /// 0 -> InitGarbState
    pub fn init(setup_data: SetupGarbData) -> Self {
        let reader = ReaderV5cWrapper::new(
            ReaderV5c::open(setup_data.input_v5c_circuit_file.clone()).expect(&format!(
                "ckt file {:?} must exist",
                setup_data.input_v5c_circuit_file
            )),
        );
        let header = *reader.header();
        assert_eq!(
            header.primary_inputs as usize,
            N_WITHDRAWAL_INPUT_WIRES * 8,
            "expected N_WITHDRAWAL_INPUT_WIRES equals wires fed into circuit"
        );

        Self {
            seed: setup_data.seed,
            setup_input: setup_data.setup_input,
            ckt_file: setup_data.input_v5c_circuit_file,
        }
    }

    fn init_polynomials<R: CryptoRng + RngCore>(rng: &mut R) -> Box<InputPolynomials> {
        let input_polys: InputPolynomials =
            std::array::from_fn(|_| HeapArray::new(|_| Polynomial::rand(rng)));
        Box::new(input_polys)
    }

    fn commit_polynomials(input_polys: &Box<InputPolynomials>) -> Box<InputPolynomialCommitments> {
        let mut input_poly_commits: Vec<WideLabelWirePolynomialCommitments> =
            Vec::with_capacity(N_INPUT_WIRES);
        for wire in 0..N_INPUT_WIRES {
            let poly_commit: Vec<PolynomialCommitment> =
                input_polys[wire].iter().map(|x| x.commit()).collect();
            let poly_commit: WideLabelWirePolynomialCommitments = HeapArray::from_vec(poly_commit);
            input_poly_commits.push(poly_commit);
        }
        let input_poly_commits: InputPolynomialCommitments =
            input_poly_commits.try_into().expect("match length");
        Box::new(input_poly_commits)
    }

    fn compute_shares(input_polys: &Box<InputPolynomials>) -> Box<InputShares> {
        let mut input_shares: Vec<CircuitInputShares> = Vec::with_capacity(N_CIRCUITS + 1);
        for circuit_index in 0..(N_CIRCUITS + 1) {
            let mut circuit_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
            for wire in 0..N_INPUT_WIRES {
                let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
                for label in 0..WIDE_LABEL_VALUE_COUNT {
                    let idx = if circuit_index == 0 {
                        Index::reserved()
                    } else {
                        Index::new(circuit_index).expect("index should be within bounds")
                    };
                    wide_shares.push(input_polys[wire][label].eval(idx));
                }
                let shares: WideLabelWireShares = HeapArray::from_vec(wide_shares);
                circuit_shares.push(shares);
            }
            input_shares.push(HeapArray::from_vec(circuit_shares));
        }
        let input_shares: InputShares = input_shares.try_into().expect("match size");
        Box::new(input_shares)
    }

    /// InitGarbState -> WaitChalGarbState
    pub async fn exec_commit(&self) -> (WaitChalGarbState, CommitMsg) {
        let mut rng = ChaCha20Rng::from_seed(self.seed.into());

        let input_polys: Box<InputPolynomials> = Self::init_polynomials(&mut rng);
        let input_poly_commits: Box<InputPolynomialCommitments> =
            Self::commit_polynomials(&input_polys);
        let input_shares: Box<InputShares> = Self::compute_shares(&input_polys);

        // Output Polynomial, Commitments and Shares
        let output_poly: OutputPolynomial = Polynomial::rand(&mut rng);
        let output_poly_commit: Box<OutputPolynomialCommitment> = Box::new(output_poly.commit());
        let output_shares: OutputShares = std::array::from_fn(|i| {
            let idx = if i == 0 {
                Index::reserved()
            } else {
                Index::new(i).expect("index should be within bounds")
            };
            output_poly.eval(idx)
        });
        // todo: uncomment this check
        // assert!(
        //     !Signature::get_pubkey(&output_shares[0].value()).is_none(),
        //     "output share for reserved index is used to verify signature while slashing, so it
        // should be a valid public key" );
        // bip0340 compatible signing keypair"); ensure reserved output share forms a valid

        // Garbling Tables for circuits indexed [1, N_CIRCUITS]; 0 is for reserved index
        let garbling_seeds: AllGarblingSeeds = std::array::from_fn(|_| {
            let mut bytes: [u8; 32] = [0; 32];
            rng.fill_bytes(&mut bytes);
            Byte32::from(bytes)
        });
        let mut garbling_table_commitments: AllGarblingTableCommitments =
            HeapArray::from_vec([Byte32::from([0u8; 32]); N_CIRCUITS].to_vec());
        let mut expanded_output_ct: [CipherBytes; N_CIRCUITS] = [Byte32::from([0; 32]); N_CIRCUITS];
        let mut all_aes_keys: [([u8; 16], [u8; 16]); N_CIRCUITS] = [([0; 16], [0; 16]); N_CIRCUITS];
        for i in 0..N_CIRCUITS {
            let circuit_index = i + 1; // offset by reserved index
            let withdrawal_shares: &[WideLabelWireShares] =
                &input_shares[circuit_index][N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..];
            let withdrawal_shares: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES] =
                withdrawal_shares.try_into().unwrap();
            (
                garbling_table_commitments[i],
                expanded_output_ct[i],
                all_aes_keys[i],
            ) = garble_commit(
                circuit_index,
                &self.ckt_file,
                garbling_seeds[i],
                withdrawal_shares,
                &output_shares[circuit_index],
            )
            .await;
        }

        let new_state = WaitChalGarbState {
            setup_input: self.setup_input,
            input_poly: input_polys,
            output_poly,
            garbling_seeds,
            expanded_output_ct,
        };

        let output_msg: CommitMsg = CommitMsg {
            garbling_table_commitments: Box::new(garbling_table_commitments),
            polynomial_commitments: (input_poly_commits, output_poly_commit),
            all_aes_keys,
        };
        (new_state, output_msg)
    }
}

pub struct CommitMsg {
    pub garbling_table_commitments: Box<AllGarblingTableCommitments>,
    pub polynomial_commitments: (
        Box<InputPolynomialCommitments>,
        Box<OutputPolynomialCommitment>,
    ),
    pub all_aes_keys: [([u8; 16], [u8; 16]); N_CIRCUITS],
}

/// copied from gobbletest
fn write_input_translation_material(
    translation_file: &PathBuf,
    translation_material: &[InputTranslationMaterial],
) {
    let mut writer = BufWriter::new(File::create(translation_file).unwrap());
    for material in translation_material {
        for byte_row in material {
            for ciphertext in byte_row {
                let ct_bytes: LabelBytes = (*ciphertext).into();
                writer
                    .write_all(&ct_bytes)
                    .expect("Failed to write translation material");
            }
        }
    }
    writer
        .flush()
        .expect("Failed to flush translation material");
}

/// garbler writes ciphers to file and returns commitments
/// largely copied from gobbletest
/// also includes output label translation
pub(crate) async fn garble_commit(
    circuit_index: usize,
    input_v5c_circuit_file: &PathBuf,
    seed: Seed,
    input_share: &[WideLabelWireShares; N_WITHDRAWAL_INPUT_WIRES],
    output_share: &Share,
) -> (GarblingTableCommitment, CipherBytes, ([u8; 16], [u8; 16])) {
    let output_gc_file = PathBuf::from(format!("gc_{circuit_index}.bin"));
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(input_v5c_circuit_file).unwrap());

    let header = *reader.header();

    // truncate to 128 bits
    let byte_labels_vec: [ByteLabel; N_WITHDRAWAL_INPUT_WIRES] = std::array::from_fn(|i| {
        ByteLabel::new(std::array::from_fn(|j| {
            Label::from(input_share[i][j].truncate())
        }))
    });

    let mut rng = ChaCha20Rng::from_seed(seed.into());
    let mut delta_bytes = [0u8; 16];
    rng.fill_bytes(&mut delta_bytes);
    let delta = Label::from(delta_bytes);

    // Import xor128 function
    #[cfg(target_arch = "aarch64")]
    use ckt_gobble::aarch64::xor128;
    #[cfg(target_arch = "x86_64")]
    use ckt_gobble::x86_64::xor128;

    // Generate bit labels for each byte position
    let mut bit_labels_vec = Vec::new(); // Vec<[BitLabel; 8]>

    for _byte_position in 0..N_WITHDRAWAL_INPUT_WIRES {
        // Generate 8 false labels (one per bit position)
        // True labels will be computed as false_label XOR delta (FreeXOR optimization)
        let default_label = Label::from([0u8; 16]);
        let mut bit_labels_array = [BitLabel::new([default_label, default_label]); 8];

        for bit_label in &mut bit_labels_array {
            // Generate false label (for bit value 0)
            let mut false_label_bytes = [0u8; 16];
            rng.fill_bytes(&mut false_label_bytes);
            let false_label = Label::from(false_label_bytes);

            // Compute true label (for bit value 1) = false_label XOR delta
            // This ensures global delta correlation for FreeXOR optimization
            let true_label = Label(unsafe { xor128(false_label.0, delta.0) });

            *bit_label = BitLabel::new([false_label, true_label]);
        }
        bit_labels_vec.push(bit_labels_array);
    }

    // Generate translation material
    let mut translation_material: Vec<InputTranslationMaterial> = Vec::new();
    for byte_position in 0..N_WITHDRAWAL_INPUT_WIRES {
        let material = generate_input_translation_material(
            byte_position as u64,
            byte_labels_vec[byte_position],
            bit_labels_vec[byte_position],
        );
        translation_material.push(material);
    }

    // Write translation material to file
    let translation_file = PathBuf::from(format!("gc_{circuit_index}.bin.translation"));
    write_input_translation_material(&translation_file, &translation_material);
    println!("✓ Translation material written to {:?}", translation_file);

    let mut primary_input_false_labels = Vec::new();
    let mut bit_count = 0;
    'outer: for bit_labels_array in &bit_labels_vec {
        for bit_label in bit_labels_array {
            if bit_count >= header.primary_inputs as usize {
                break 'outer;
            }
            // Get false label (index 0) from BitLabel
            let false_label = bit_label.get_label(false);
            let label_bytes = false_label.into();
            primary_input_false_labels.push(label_bytes);
            bit_count += 1;
        }
    }

    assert_eq!(
        primary_input_false_labels.len(),
        header.primary_inputs as usize,
        "Expected {} primary input labels, got {}",
        header.primary_inputs,
        primary_input_false_labels.len()
    );

    let mut aes128_key = [0u8; 16];
    rng.fill_bytes(&mut aes128_key);
    let mut public_s = [0u8; 16];
    rng.fill_bytes(&mut public_s);

    // Run standard garbling
    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta: delta_bytes, // Same delta used for bit label generation
        primary_input_false_labels: &primary_input_false_labels,
        aes128_key,
        public_s,
    };

    let task_with_progress = GarbleTask::new(config);

    // Open the output writer.
    let file = File::create(&output_gc_file).unwrap();
    let writer = BufWriter::new(file);

    // Execute the garbling loop.
    let result = process_task(&task_with_progress, writer, &mut reader)
        .await
        .expect("garble: process task");

    println!("\n✓ Garbled circuit written to {:?}", output_gc_file);

    let tables_commit = read_gc_bin_and_hash(&output_gc_file);
    let translate_commit = read_gc_bin_and_hash(&translation_file);
    let output_label = result.garbler_output_labels[0].into();

    let input_share_bytes: [u8; 32] = output_share
        .value()
        .into_bigint()
        .to_bytes_le()
        .try_into()
        .unwrap();
    let expanded_output_ciphers = generate_output_translation_material(
        &[BitLabel::new([output_label, output_label])],
        &[input_share_bytes],
    )
    .expect("generate_output_translation_material");
    assert_eq!(expanded_output_ciphers.len(), 1);
    let output_label_ct = expanded_output_ciphers[0].into();
    (
        GTCommitmentFields {
            ciphertext: tables_commit,
            translation: translate_commit,
            output_label_ct,
        }
        .hash(),
        output_label_ct,
        (aes128_key, public_s),
    )
}

pub(crate) fn read_gc_bin_and_hash(output_gc_file: &PathBuf) -> Hash {
    let garbled_file = File::open(output_gc_file).unwrap();
    let mut ct_reader = BufReader::new(garbled_file);
    let mut buffer = vec![0u8; 64];

    let mut hasher = blake3::Hasher::new();
    //let mut bytes_read_count = 0;
    loop {
        let bytes_read = ct_reader.read(&mut buffer).expect("expect read");

        if bytes_read == 0 {
            break;
        }
        //bytes_read_count += bytes_read;
        let chunk = &buffer[..bytes_read];
        hasher.update(chunk);
    }
    let file_hash = hasher.finalize();
    file_hash
}

/// GarbleTableCommit
#[derive(Debug)]
pub(crate) struct GTCommitmentFields {
    /// hash of ciphertext labels
    pub(crate) ciphertext: Hash,
    /// hash of input label translator
    pub(crate) translation: Hash,
    /// output label expanded to 32 bytes such that ct = share xor blake3(16 byte label)
    /// This way you can obtain output share from 16 byte label
    pub(crate) output_label_ct: CipherBytes,
}

impl GTCommitmentFields {
    /// concat and hash
    pub(crate) fn hash(&self) -> GarblingTableCommitment {
        let mut byte_arr = vec![];
        byte_arr.extend_from_slice(self.ciphertext.as_slice());
        byte_arr.extend_from_slice(self.translation.as_slice());
        byte_arr.extend_from_slice(self.output_label_ct.as_ref());
        let hash = blake3::hash(&byte_arr);
        Byte32::from(*hash.as_bytes())
    }
}

/// WaitChalGarbState
#[derive(Debug)]
pub struct WaitChalGarbState {
    // setup inputs in bytes
    setup_input: SetupInputs,
    input_poly: Box<InputPolynomials>,
    output_poly: OutputPolynomial,
    garbling_seeds: AllGarblingSeeds,
    // 32 byte output label that when xored with share
    expanded_output_ct: [CipherBytes; N_CIRCUITS],
}

impl WaitChalGarbState {
    fn open_input_shares_at_challenge_index(
        challenge_indices: &ChallengeIndices,
        input_poly: &Box<InputPolynomials>,
    ) -> Box<OpenedInputShares> {
        let mut open_input_shares: Vec<CircuitInputShares> = Vec::with_capacity(N_OPEN_CIRCUITS);
        for i in 0..N_OPEN_CIRCUITS {
            let idx = challenge_indices[i];
            let mut input_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
            for j in 0..N_INPUT_WIRES {
                let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
                for k in 0..WIDE_LABEL_VALUE_COUNT {
                    let share = input_poly[j][k].eval(idx);
                    wide_shares.push(share);
                }
                input_shares.push(HeapArray::from_vec(wide_shares));
            }
            open_input_shares.push(HeapArray::from_vec(input_shares));
        }
        let opened_input_shares: [CircuitInputShares; N_OPEN_CIRCUITS] =
            open_input_shares.try_into().unwrap();
        Box::new(opened_input_shares)
    }

    fn get_reserved_input_shares(input_poly: &Box<InputPolynomials>) -> Box<ReservedInputShares> {
        let mut input_shares: Vec<WideLabelWireShares> = Vec::with_capacity(N_INPUT_WIRES);
        for i in 0..N_INPUT_WIRES {
            let wire_polys = &input_poly[i];
            let mut wide_shares: Vec<Share> = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
            for j in 0..WIDE_LABEL_VALUE_COUNT {
                let label_polys = &wire_polys[j];
                let share = label_polys.eval(Index::reserved());
                wide_shares.push(share);
            }
            input_shares.push(HeapArray::from_vec(wide_shares));
        }
        let input_shares: CircuitInputShares = HeapArray::from_vec(input_shares);
        Box::new(input_shares)
    }

    /// exec_respond
    pub fn exec_respond(&self, msg: ChallengeMsg) -> (WaitAdaptorsGarbState, ChallengeResponseMsg) {
        // open input polynomial at challenge indices
        let opened_input_shares: Box<OpenedInputShares> =
            Self::open_input_shares_at_challenge_index(&msg.challenge_indices, &self.input_poly);

        // evaluate the output false polynomial at the challenge indices
        let opened_output_shares: OpenedOutputShares =
            HeapArray::from_vec(msg.challenge_indices.map(|idx| self.output_poly.eval(idx)).to_vec());

        // evaluate each input polynomial at the reserved i=0 index
        let reserved_input_shares: Box<ReservedInputShares> =
            Self::get_reserved_input_shares(&self.input_poly);

        // take 0..N_SETUP_INPUT_WIRES indices and
        let reserved_setup_input_shares: ReservedSetupInputShares =
            HeapArray::from_vec((0..N_SETUP_INPUT_WIRES).into_iter().map(|i| reserved_input_shares[i][self.setup_input[i] as usize].clone()).collect());

        // opened garbling seeds
        let opened_garbling_seeds: OpenedGarblingSeeds = HeapArray::from_vec(msg
            .challenge_indices
            // challenge index i+1 corresponds to i_th entry in self.garbling_seeds
            // therefore subtract by 1 here; better way ? maybe GC tables should be stored as map
            // from Index to Value as the data structure can not be indexed in the
            // conventional array sense
            .map(|idx| self.garbling_seeds[idx.get() - 1]).to_vec());

        // file pointers to unopened garbling tables
        // [1..N_CIRCUIT+1] - [challenged_indices]
        let challenged_indices: Vec<usize> = msg
            .challenge_indices
            .iter()
            .map(|x| x.get())
            .collect::<Vec<usize>>();
        let unchallenged_indices: [usize; N_EVAL_CIRCUITS] = (1..=N_CIRCUITS)
            .into_iter()
            .filter(|id| !challenged_indices.contains(id))
            .collect::<Vec<usize>>()
            .try_into()
            .expect("unchallenge length");
        let unchallenged_output_ct: [CipherBytes; N_EVAL_CIRCUITS] = unchallenged_indices
            .iter()
            .map(|index| self.expanded_output_ct[index - 1])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let unopened_garbling_tables = Box::new(std::array::from_fn(|i| {
            (
                Index::new(unchallenged_indices[i]).expect("valid index"),
                unchallenged_output_ct[i],
            )
        }));

        let response_msg = ChallengeResponseMsg {
            opened_input_shares,
            reserved_setup_input_shares: Box::new(reserved_setup_input_shares),
            opened_output_shares: Box::new(opened_output_shares),
            opened_garbling_seeds: Box::new(opened_garbling_seeds),
            unchallenged_garbling_tables: unopened_garbling_tables,
        };

        let reserved: &ReservedNonSetupInputShares = reserved_input_shares[N_SETUP_INPUT_WIRES..]
            .try_into()
            .unwrap();
        let next_state = WaitAdaptorsGarbState {
            input_shares: reserved.clone(),
        };
        (next_state, response_msg)
    }
}

pub type ReservedNonSetupInputShares = [WideLabelWireShares; N_INPUT_WIRES - N_SETUP_INPUT_WIRES];
pub type UnopenedGarblingTables = [(Index, Byte32); N_EVAL_CIRCUITS];

/// ChallengeResponseMsg: Garbler -> Evaluator
/// Note: Garbling Tables are sent separately
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeResponseMsg {
    /// N_COEFFICIENTS * N_INPUT_WIRES * 256
    pub opened_input_shares: Box<OpenedInputShares>,
    /// N_SETUP_INPUT_WIRES * 256
    pub reserved_setup_input_shares: Box<ReservedSetupInputShares>,
    /// N_COEFFICIENTS
    pub opened_output_shares: Box<OpenedOutputShares>,
    /// N_COEFFICIENTS
    pub opened_garbling_seeds: Box<OpenedGarblingSeeds>,
    /// unopened garbling tables
    pub unchallenged_garbling_tables: Box<UnopenedGarblingTables>,
}

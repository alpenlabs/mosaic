//! Evaluator runs deposit time processes

use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{
    Ciphertext, InputTranslationMaterial, Label, OutputTranslationMaterial,
    traits::EvaluationInstanceConfig, translate_input, translate_output,
};
use ckt_runner_exec::{EvalTask, ReaderV5cWrapper, process_task};
use mosaic_adaptor_sigs::Adaptor;
use mosaic_cac_types::{
    ChallengeIndices, DepositAdaptors, DepositInputs, HeapArray, OpenedInputShares,
    OpenedOutputShares, ReservedSetupInputShares, Seed, SetupInputs, Sighash, WithdrawalAdaptors,
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_EVAL_CIRCUITS, N_INPUT_WIRES, N_OPEN_CIRCUITS,
    N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT,
};
use mosaic_vs3::{Index, Point, Scalar, Share, interpolate};
use num_bigint::BigUint;
use rand::SeedableRng;

use crate::{
    deposit_garbler::{AdaptorMsg, SigMsg},
    setup_evaluator::ReservedNonSetupInputShareCommits,
    setup_garbler::{CipherBytes, LabelBytes, UnopenedGarblingTables},
};
/// WaitTxDataEvalState
#[derive(Debug)]
pub struct WaitTxDataEvalState {
    /// master seed
    pub seed: Seed,
    /// challenge indices
    pub challenge_indices: ChallengeIndices,
    /// input shares challenged and opened
    pub opened_input_shares: OpenedInputShares,
    /// setup input shares for reserve index circuit
    pub reserved_setup_input_shares: ReservedSetupInputShares,
    /// opened output shares
    pub opened_output_shares: OpenedOutputShares,
    /// garbling tables for unopened indices in {1..=N_CIRCUITS}
    pub garbling_tables: UnopenedGarblingTables, // Unopened garbling tables
    /// reserved input share commitments excluding setup wires
    pub reserved_input_share_commitments: ReservedNonSetupInputShareCommits,
    /// zeroth coefficient of polynomial commitment, used as validating key for slashing condition
    pub output_commitment: Point,
    /// setup input
    pub setup_input: SetupInputs,
    /// v5c ckt file reference
    pub ckt_file: PathBuf,
    /// all_aes_keys
    pub all_aes_keys: [([u8; 16], [u8; 16]); N_CIRCUITS],
}

/// DepositEvalData
#[derive(Debug)]
pub struct DepositEvalData {
    /// sighashes
    pub sighashes: [Sighash; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES],
    /// adaptor signing key
    pub evaluator_sk: Scalar,
    /// adaptor verifying key
    pub evaluator_pk: Point,
    /// deposit input values
    pub deposit_input: DepositInputs,
}

impl WaitTxDataEvalState {
    /// exec_generate_adaptors
    pub fn exec_generate_adaptors(
        &self,
        eval_data: DepositEvalData,
    ) -> (WaitSigEvalState, AdaptorMsg) {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.seed.into());
        let deposit_adaptors: DepositAdaptors = HeapArray::from_vec(
            (0..N_DEPOSIT_INPUT_WIRES)
                .into_iter()
                .map(|i| {
                    let share_commitment = self.reserved_input_share_commitments[i]
                        [eval_data.deposit_input[i] as usize]
                        .1;
                    Adaptor::generate(
                        &mut rng,
                        share_commitment,
                        eval_data.evaluator_sk,
                        eval_data.evaluator_pk,
                        eval_data.sighashes[i].0.as_ref(),
                    )
                    .expect("generate deposit adaptors")
                })
                .collect(),
        );
        let withdrawal_adaptors: WithdrawalAdaptors = HeapArray::from_vec(
            (0..N_WITHDRAWAL_INPUT_WIRES)
                .into_iter()
                .map(|i| {
                    HeapArray::from_vec(
                        (0..WIDE_LABEL_VALUE_COUNT)
                            .into_iter()
                            .map(|j| {
                                let share_commitment = self.reserved_input_share_commitments
                                    [N_DEPOSIT_INPUT_WIRES + i][j]
                                    .1;
                                Adaptor::generate(
                                    &mut rng,
                                    share_commitment,
                                    eval_data.evaluator_sk,
                                    eval_data.evaluator_pk,
                                    eval_data.sighashes[i].0.as_ref(),
                                )
                                .expect("generate withdrawal adaptors")
                            })
                            .collect(),
                    )
                })
                .collect(),
        );

        let next_state = WaitSigEvalState {
            challenge_indices: self.challenge_indices.clone(),
            opened_input_shares: self.opened_input_shares.clone(),
            opened_output_shares: self.opened_output_shares.clone(),
            garbling_tables: self.garbling_tables,
            deposit_adaptors: deposit_adaptors.clone(),
            withdrawal_adaptors: withdrawal_adaptors.clone(),
            output_commitment: self.output_commitment,
            setup_input: self.setup_input,
            deposit_input: eval_data.deposit_input,
            reserved_setup_input_shares: self.reserved_setup_input_shares.clone(),
            ckt_file: self.ckt_file.clone(),
            all_aes_keys: self.all_aes_keys,
        };
        let adaptor_msg: AdaptorMsg = AdaptorMsg {
            deposit_adaptors: Box::new(deposit_adaptors),
            withdrawal_adaptors: Box::new(withdrawal_adaptors),
        };
        (next_state, adaptor_msg)
    }
}

/// WaitSigEvalState
#[derive(Debug)]
pub struct WaitSigEvalState {
    /// challenge indices
    pub challenge_indices: ChallengeIndices,
    /// opened input shares
    pub opened_input_shares: OpenedInputShares,
    /// opened output shares
    pub opened_output_shares: OpenedOutputShares,
    /// opened garbling tables
    pub garbling_tables: UnopenedGarblingTables,
    /// deposit adaptors given values for deposit input
    pub deposit_adaptors: DepositAdaptors,
    /// withdrawal adaptors for all possible withdrawal input values
    pub withdrawal_adaptors: WithdrawalAdaptors,
    /// zeroth coefficient of polynomial commitment, used as validating key for slashing condition
    pub output_commitment: Point,
    /// setup input values
    pub setup_input: SetupInputs,
    /// deposit input values
    pub deposit_input: DepositInputs,
    /// setup input shares for reserved index circuit
    pub reserved_setup_input_shares: ReservedSetupInputShares,
    /// refernce to ckt file
    pub ckt_file: PathBuf,
    /// aes_keys
    pub all_aes_keys: [([u8; 16], [u8; 16]); N_CIRCUITS],
}

impl WaitSigEvalState {
    /// exec_try_reveal_secret
    pub async fn exec_try_reveal_secret(&self, msg: SigMsg) -> FinishEvalState {
        // filter shares for setup, deposit, withdrawal input
        let mut selected_opened_input: [u8; N_INPUT_WIRES] = [0; N_INPUT_WIRES];
        selected_opened_input[0..N_SETUP_INPUT_WIRES].copy_from_slice(&self.setup_input);
        selected_opened_input[N_SETUP_INPUT_WIRES..N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES]
            .copy_from_slice(&self.deposit_input);
        selected_opened_input[N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
            .copy_from_slice(&msg.withdrawal_input);

        let selected_opened_input_shares: [[Share; N_INPUT_WIRES]; N_OPEN_CIRCUITS] =
            std::array::from_fn(|i| {
                std::array::from_fn(|j| {
                    let val = selected_opened_input[j] as usize;
                    self.opened_input_shares[i][j][val]
                })
            });

        let mut selected_committed_input_shares: Vec<Share> =
            self.reserved_setup_input_shares.to_vec();
        // extract shares from signatures corresponding to deposit input
        for (wire, adaptor) in self.deposit_adaptors.iter().enumerate() {
            let share_value = adaptor.extract_share(&msg.signatures[wire]);
            let share_index = Index::reserved();
            selected_committed_input_shares.push(Share::new(share_index, share_value));
        }
        for (wire, adaptors) in self.withdrawal_adaptors.iter().enumerate() {
            let val = msg.withdrawal_input[wire] as usize;
            let share_index = Index::reserved();
            let share_value =
                adaptors[val].extract_share(&msg.signatures[N_DEPOSIT_INPUT_WIRES + wire]);
            selected_committed_input_shares.push(Share::new(share_index, share_value));
        }
        let committed_input_shares: [Share; N_INPUT_WIRES] =
            selected_committed_input_shares.try_into().unwrap();

        // Rearrange: selected_opened_input_shares(k) + selected_committed_input_shares(1)
        let dummy = Share::new(Index::reserved(), Scalar::from(0));
        let mut shares_per_wire: [[Share; N_OPEN_CIRCUITS + 1]; N_INPUT_WIRES] =
            [[dummy; N_OPEN_CIRCUITS + 1]; N_INPUT_WIRES];
        for i in 0..N_INPUT_WIRES {
            for j in 0..N_OPEN_CIRCUITS {
                shares_per_wire[i][j] = selected_opened_input_shares[j][i];
            }
            shares_per_wire[i][N_OPEN_CIRCUITS] = committed_input_shares[i];
        }

        // N_EVAL_CIRCUITS many circuits in range [1, N_CIRCUITS] left to evaluate
        // Interpolate then eval on missing indices over each of the input wires
        let missing_shares_per_wire: [[Share; N_EVAL_CIRCUITS]; N_INPUT_WIRES] =
            std::array::from_fn(|i| {
                interpolate(&shares_per_wire[i])
                    .expect("interpolation should pass")
                    .try_into()
                    .expect("should return remaining number of points")
            });

        // ensure we have ciphertext for theses unchallenged shares

        let mut fault_secret = None;
        let challenged_indices: Vec<usize> = self
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

        for i in 0..N_EVAL_CIRCUITS {
            let shares: [Share; N_INPUT_WIRES] =
                std::array::from_fn(|j| missing_shares_per_wire[j][i]);
            let index = unchallenged_indices[i];
            let (output_ct_index, output_ct) = self.garbling_tables[i];

            assert_eq!(
                index,
                output_ct_index.get(),
                "ensure we're retrieving correct values from verified data"
            );
            shares.iter().for_each(|s| {
                assert_eq!(
                    index,
                    s.index().get(),
                    "ensure we're retrieving correct values from verified data"
                )
            });

            let ciphertext_file = PathBuf::from(format!("gc_{index}.bin"));
            let translation_file = PathBuf::from(format!("gc_{index}.bin.translation"));

            let (evaluated_output_share, evaluated_output_value) = evaluate_gc_table(
                &self.ckt_file,
                &ciphertext_file,
                &translation_file,
                msg.withdrawal_input.to_vec(),
                &shares.map(|x| x.truncate())[N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..],
                output_ct,
                self.all_aes_keys[index - 1].0,
                self.all_aes_keys[index - 1].1,
            )
            .await;
            println!(
                "exec_try_reveal_secret: circuit_index {index} evaluated_output_value {evaluated_output_value} "
            );
            if evaluated_output_share.is_none() {
                continue;
            }
            let mut output_shares = self.opened_output_shares.to_vec();
            output_shares.push(Share::new(output_ct_index, evaluated_output_share.unwrap()));
            let evals_at_missing_indices = interpolate(&output_shares).expect("should pass");
            let evals_at_zeroth_index = evals_at_missing_indices
                .iter()
                .find(|x| x.index().get() == 0)
                .expect("should include zeroth index evaluation");
            let calc_commitment = evals_at_zeroth_index.commit().1;
            if calc_commitment == self.output_commitment {
                fault_secret = Some(evals_at_zeroth_index.value());
                break;
            }
        }
        FinishEvalState { fault_secret }
    }
}

/// FinishEvalState
#[derive(Debug)]
pub struct FinishEvalState {
    /// fault_secret used to sign a msg that satisfies slashing condition
    pub fault_secret: Option<Scalar>,
}

/// largely copied from gobbletest
/// includes output label translation
use ckt_runner_exec::CircuitReader;
async fn evaluate_gc_table(
    circuit_file: &PathBuf,
    ciphertext_file: &PathBuf,
    translation_file: &PathBuf,
    input_bytes: Vec<u8>,
    input_byte_labels: &[LabelBytes],
    output_ct: CipherBytes,
    aes128_key: [u8; 16],
    public_s: [u8; 16],
) -> (Option<Scalar>, bool) {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(circuit_file).unwrap());
    let header = *reader.header();

    assert_eq!(
        input_byte_labels.len(),
        N_WITHDRAWAL_INPUT_WIRES,
        "Expected {} byte labels, got {}",
        N_WITHDRAWAL_INPUT_WIRES,
        input_byte_labels.len()
    );

    // Read translation material from file
    let translation_material = read_translation_material(translation_file);

    // Translate byte labels to bit labels
    // Only translate exactly primary_inputs bits (may be less than num_bytes * 8)
    let mut bit_labels = Vec::new();
    let mut input_values_bits = BitVec::new();
    let mut bit_count = 0;

    for byte_position in 0..N_WITHDRAWAL_INPUT_WIRES {
        let byte_label = Label::from(input_byte_labels[byte_position]);
        let byte_value = input_bytes[byte_position];

        // Translate: byte_label to 8 bit labels
        let translated_bit_labels = translate_input(
            byte_position as u64,
            byte_label,
            byte_value,
            translation_material[byte_position],
        );

        // Extract bit values and labels
        for (bit_position, translated_label) in translated_bit_labels.iter().enumerate() {
            if bit_count >= header.primary_inputs as usize {
                break;
            }
            let bit_value = ((byte_value >> bit_position) & 1) == 1;
            input_values_bits.push(bit_value);

            let label_bytes: LabelBytes = (*translated_label).into();
            bit_labels.push(label_bytes);
            bit_count += 1;
        }
        if bit_count >= header.primary_inputs as usize {
            break;
        }
    }

    assert_eq!(
        bit_labels.len(),
        header.primary_inputs as usize,
        "Expected {} bit labels, got {}",
        header.primary_inputs,
        bit_labels.len()
    );

    // Run standard evaluation
    let config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: &bit_labels,
        selected_primary_input_values: &input_values_bits,
        aes128_key,
        public_s,
    };

    let task_info = EvalTask::new(config);

    // Open the ciphertext reader.
    let garbled_file = File::open(ciphertext_file).unwrap();
    let ct_reader = BufReader::new(garbled_file);

    // Execute the evaluation loop.
    let output = process_task(&task_info, ct_reader, &mut reader)
        .await
        .expect("eval: process task");

    assert_eq!(output.output_labels.len(), 1);
    let output_translation_material: OutputTranslationMaterial = vec![output_ct.into()];
    let output_labels = &[Label::from(output.output_labels[0])];
    let output_shares = translate_output(
        output_labels,
        &output.output_values,
        &output_translation_material,
    )
    .unwrap();
    let output_share = if output_shares[0].is_none() {
        None
    } else {
        let scalar: Scalar = BigUint::from_bytes_le(&output_shares[0].unwrap()).into();
        Some(scalar)
    };
    (output_share, output.output_values[0])
}

/// copied from gobbletest
fn read_translation_material(translation_file: &PathBuf) -> Vec<InputTranslationMaterial> {
    let mut reader = BufReader::new(File::open(translation_file).unwrap());
    let mut translation_material = Vec::new();

    for _ in 0..N_WITHDRAWAL_INPUT_WIRES {
        let mut material = [[Ciphertext::from([0u8; 16]); 8]; 256];
        for byte_row in &mut material {
            for ciphertext in byte_row {
                let mut ct_bytes = [0u8; 16];
                reader
                    .read_exact(&mut ct_bytes)
                    .expect("Failed to read translation material");
                *ciphertext = Ciphertext::from(ct_bytes);
            }
        }
        translation_material.push(material);
    }
    translation_material
}

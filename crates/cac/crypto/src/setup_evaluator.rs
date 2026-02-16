//! Evaluator Setup Stage

use std::path::PathBuf;

use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, ChallengeIndices, ChallengeMsg,
    HeapArray, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares,
    ReservedSetupInputShares, Seed, SetupInputs,
};
use mosaic_common::constants::{
    N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, N_SETUP_INPUT_WIRES,
    WIDE_LABEL_VALUE_COUNT,
};
use mosaic_vs3::{Index, ShareCommitment};
use rand::seq::index;
use rand_chacha::rand_core::SeedableRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{
    deposit_evaluator::WaitTxDataEvalState,
    setup_garbler::{
        ChallengeResponseMsg, CommitMsg, GTCommitmentFields, garble_commit, read_gc_bin_and_hash,
    },
};

/// Config
#[derive(Debug)]
pub struct Config {
    _vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
}

///
#[derive(Debug)]
pub struct SetupEvalData {
    //_config: Config,
    /// setup input in bytes
    pub setup_input: SetupInputs,
    /// evaluator's master seed
    pub seed: Seed,
    /// ckt file in v5c format
    pub ckt_file: PathBuf,
}

/// InitEvalState
#[derive(Debug)]
pub struct InitEvalState {
    setup_input: SetupInputs,
    seed: Seed,
    ckt_file: PathBuf,
}

impl InitEvalState {
    /// init
    pub fn init(setup_data: SetupEvalData) -> Self {
        Self {
            setup_input: setup_data.setup_input,
            seed: setup_data.seed,
            ckt_file: setup_data.ckt_file,
        }
    }

    /// exec_challenge CommitMsg -> WaitRespEvalState
    pub fn exec_challenge(&self, commit_msg: CommitMsg) -> (WaitRespEvalState, ChallengeMsg) {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.seed.into());
        let sampled_indices = index::sample(&mut rng, N_CIRCUITS, N_OPEN_CIRCUITS); // samples N_OPEN_CIRCUITS many values from the domain [0, N_CIRCUITS]
        let challenge_indices: ChallengeIndices = HeapArray::from_vec(
            sampled_indices
                .into_iter()
                .map(|x| Index::new(x + 1).expect("within bounds")) // sampled values displaced to domain [1, N_CIRCUITS+1] as 0 is reserved index
                .collect::<Vec<_>>(),
        );
        let next_state = WaitRespEvalState {
            setup_input: self.setup_input,
            challenge_indices: challenge_indices.clone(),
            poly_commits: commit_msg.polynomial_commitments,
            gt_commits: commit_msg.garbling_table_commitments,
            ckt_file: self.ckt_file.clone(),
            seed: self.seed,
            all_aes_keys: commit_msg.all_aes_keys,
        };
        let challenge_msg = ChallengeMsg { challenge_indices };
        (next_state, challenge_msg)
    }
}

/// WaitRespEvalState
#[derive(Debug)]
pub struct WaitRespEvalState {
    setup_input: SetupInputs,
    challenge_indices: ChallengeIndices,
    poly_commits: AllPolynomialCommitments,
    gt_commits: Box<AllGarblingTableCommitments>,
    ckt_file: PathBuf,
    seed: Seed,
    all_aes_keys: [([u8; 16], [u8; 16]); N_CIRCUITS],
}

impl WaitRespEvalState {
    /// exec_verify
    pub async fn exec_verify(&self, response_msg: ChallengeResponseMsg) -> WaitTxDataEvalState {
        let (input_poly_commits, output_poly_commit) = &self.poly_commits;

        println!("exec_verify; Verify opened input shares against polynomial commitments");
        // ---------- 1) Verify opened input shares against polynomial commitments ----------
        let opened_input_shares: OpenedInputShares = *response_msg.opened_input_shares;
        (0..N_OPEN_CIRCUITS).into_par_iter().for_each(|idx| {
            for wire in 0..N_INPUT_WIRES {
                for val in 0..WIDE_LABEL_VALUE_COUNT {
                    let share = opened_input_shares[idx][wire][val].clone();
                    if input_poly_commits[wire][val].verify_share(share).is_err() {
                        panic!(
                            "verify opened input shares failed for index {idx}, wire {wire}, value {val}"
                        );
                    }
                }
            }
        });

        println!("exec_verify; Verify opened output (false) shares");
        // ---------- 2) Verify opened output (false) shares ----------
        let opened_output_shares: OpenedOutputShares = *response_msg.opened_output_shares;
        for idx in 0..N_OPEN_CIRCUITS {
            let share = opened_output_shares[idx].clone();
            if output_poly_commit.verify_share(share).is_err() {
                panic!("verify_share failed for output, index {idx}")
            }
        }

        println!("exec_verify; Verify garbling table commitments");
        // ---------- 3) Verify garbling table commitments ----------
        let opened_garbling_seeds: OpenedGarblingSeeds = *response_msg.opened_garbling_seeds;
        for i in 0..N_OPEN_CIRCUITS {
            let gc_seed = opened_garbling_seeds[i];
            let output_share = opened_output_shares[i].clone();
            let challenged_index = self.challenge_indices[i].get();
            let (calc_gc_commitment, _, calc_aeskey) = garble_commit(
                challenged_index,
                &self.ckt_file,
                gc_seed,
                opened_input_shares[i][N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES..]
                    .try_into()
                    .unwrap(),
                &output_share,
            )
            .await;
            // challenge index i+1 corresponds to i_th entry in self.gt_commits
            let claimed_gc_commitment = self.gt_commits[challenged_index - 1];
            assert_eq!(
                calc_gc_commitment, claimed_gc_commitment,
                "garbling seed commit mismatch at index {challenged_index}"
            );
            assert_eq!(
                calc_aeskey,
                self.all_aes_keys[challenged_index - 1],
                "should match aes keys"
            )
        }

        println!("exec_verify; Unchallenged circuits: verify provided tables against commitments");
        // 3b) Unchallenged circuits: verify provided tables against commitments
        for unchallenged_table in *response_msg.unchallenged_garbling_tables {
            let index = unchallenged_table.0.get();
            let output_gc_file = PathBuf::from(format!("gc_{index}.bin"));
            let translation_file = PathBuf::from(format!("gc_{index}.bin.translation"));
            let tables_commit = read_gc_bin_and_hash(&output_gc_file);
            let translate_commit = read_gc_bin_and_hash(&translation_file);
            let computed_hash = GTCommitmentFields {
                ciphertext: tables_commit,
                translation: translate_commit,
                output_label_ct: unchallenged_table.1,
            }
            .hash();
            let claimed_commit = self.gt_commits[index - 1]; // -1 because of offset
            assert_eq!(
                computed_hash, claimed_commit,
                "garbling table commit mismatch at unchallenged index {index}"
            );
        }

        println!(
            "exec_verify; Verify setup input shares against setup input and polynomial commitments"
        );
        // 4) Verify setup input shares against setup input and polynomial commitments
        let reserved_setup_input_shares: ReservedSetupInputShares =
            *response_msg.reserved_setup_input_shares;
        for wire in 0..N_SETUP_INPUT_WIRES {
            let val = self.setup_input[wire];
            let reserved_share = reserved_setup_input_shares[wire].clone();
            if input_poly_commits[wire][val as usize]
                .verify_share(reserved_share)
                .is_err()
            {
                panic!("verify reserved setup shares failed for wire {wire}");
            }
        }

        println!("exec_verify; store input share commitments at reserved index");
        // store input share commitments at reserved index
        let zero_idx = Index::reserved();
        let reserved_input_share_commitments: ReservedNonSetupInputShareCommits =
            std::array::from_fn(|i| {
                let wire = N_SETUP_INPUT_WIRES + i;
                let share_commits: Vec<ShareCommitment> = (0..WIDE_LABEL_VALUE_COUNT).into_iter().map(|val| input_poly_commits[wire][val].eval(zero_idx)).collect();
                HeapArray::from_vec(share_commits)
            });

        let output_commitment = output_poly_commit.get_zeroth_coefficient();

        WaitTxDataEvalState {
            challenge_indices: self.challenge_indices.clone(),
            opened_input_shares,
            opened_output_shares,
            reserved_setup_input_shares,
            garbling_tables: *response_msg.unchallenged_garbling_tables,
            reserved_input_share_commitments,
            output_commitment,
            seed: self.seed,
            setup_input: self.setup_input,
            ckt_file: self.ckt_file.clone(),
            all_aes_keys: self.all_aes_keys,
        }
    }
}


pub type ReservedNonSetupInputShareCommits =
    [HeapArray<ShareCommitment, WIDE_LABEL_VALUE_COUNT>; N_INPUT_WIRES - N_SETUP_INPUT_WIRES];

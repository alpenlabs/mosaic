//! CaC cryptographic procedures.

pub mod deposit_evaluator;
pub mod deposit_garbler;
pub mod setup_evaluator;
pub mod setup_garbler;

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufReader, Read},
        path::{Path, PathBuf},
    };

    use bitvec::vec::BitVec;
    use mosaic_adaptor_sigs::Signature;
    use mosaic_cac_types::Sighash;
    use mosaic_common::{
        Byte32,
        constants::{N_DEPOSIT_INPUT_WIRES, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES},
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::{
        deposit_evaluator::DepositEvalData,
        deposit_garbler::{DepositGarbData, WithdrawalGarbData},
        setup_evaluator::{InitEvalState, SetupEvalData},
        setup_garbler::{InitGarbState, SetupGarbData},
    };

    #[tokio::test]
    async fn test_e2e() {
        let mut garb_rng = ChaCha20Rng::seed_from_u64(42);

        // expects g16.v5c inside cac/crypto
        // Steps:
        // 1. clone: g16 repo and switch to branch test/simple_circuit_postaudit
        // test/simple_circuit_postaudit branch generates small ckt file that does input validation
        // only; not the actually groth16 verification afterwards; Meant for test purposes only]
        // 2. generate v5a ckt file: cd g16gen && cargo run generate 6 && cargo run write-input-bits
        //    6
        // 3. clone: ckt repo
        // 4. move g16gen/g16.ckt file to ckt/lvl/
        // 5. generate v5c file: cd crates/lvl && cargo run prealloc g16.ckt g16.v5c
        // 6. move lvl/g16.v5c to mosaic/cac/crypto/
        // 7. move g16gen/inputs.txt to mosaic/cac/crypto/
        // 7. Run test with
        // RUST_MIN_STACK=2256388608 cargo test --release --package mosaic-cac-crypto --lib --
        // tests::test_e2e --exact --show-output --nocapture need for RUST_MIN_STACK will be
        // avoided in future after we box large contents
        let garbler_setup_data = SetupGarbData {
            seed: Byte32::from(garb_rng.r#gen::<[u8; 32]>()),
            setup_input: [0; N_SETUP_INPUT_WIRES],
            input_v5c_circuit_file: PathBuf::from("g16.v5c"),
        };
        let init_garb_state = InitGarbState::init(garbler_setup_data);

        let mut eva_rng = ChaCha20Rng::seed_from_u64(420);

        let eval_setup_data = SetupEvalData {
            seed: Byte32::from(eva_rng.r#gen::<[u8; 32]>()),
            setup_input: [0; N_SETUP_INPUT_WIRES],
            ckt_file: PathBuf::from("g16.v5c"),
        };
        let init_eval_state = InitEvalState::init(eval_setup_data);

        println!("exec_commit");
        let (wait_chal_garb_state, commit_msg) = init_garb_state.exec_commit().await;
        println!("exec_challenge");
        let (wait_resp_eval_state, challenge_msg) = init_eval_state.exec_challenge(commit_msg);
        let (wait_adaptor_garb_state, challenge_response_msg) =
            wait_chal_garb_state.exec_respond(challenge_msg);
        println!("exec_verify");
        let wait_txdata_eval_state = wait_resp_eval_state
            .exec_verify(challenge_response_msg)
            .await;

        let eval_keypair = Signature::keypair(&mut eva_rng);

        // Deposit Time
        let deposit_eval_data = DepositEvalData {
            sighashes: [Sighash(Byte32::from([0u8; 32]));
                N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES],
            evaluator_sk: eval_keypair.0,
            evaluator_pk: eval_keypair.1,
            deposit_input: [0u8; N_DEPOSIT_INPUT_WIRES],
        };
        println!("exec_generate_adaptors");
        let (wait_sig_eval_state, adaptor_msg) =
            wait_txdata_eval_state.exec_generate_adaptors(deposit_eval_data);

        let deposit_garb_data = DepositGarbData {
            evaluator_pk: eval_keypair.1,
            sighashes: [Sighash(Byte32::from([0u8; 32]));
                N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES],
            deposit_input: [0u8; N_DEPOSIT_INPUT_WIRES],
        };

        println!("exec_verify_adaptors");
        let wait_proof_garb_state =
            wait_adaptor_garb_state.exec_verify_adaptors(deposit_garb_data, adaptor_msg);

        // Withdrawal Time
        let ckt_input_exists = std::fs::exists(Path::new("inputs.txt")).unwrap();
        let test_data = test_data();

        for (i, (withdrawal_data, should_pass)) in test_data.into_iter().enumerate() {
            println!("TEST_DATA {i}");
            println!("exec_sign");
            let (_, sig_msg) = wait_proof_garb_state.exec_sign(withdrawal_data);
            println!("exec_try_reveal_secret");
            let finish_eval_state = wait_sig_eval_state.exec_try_reveal_secret(sig_msg).await;

            println!(
                "read proof {ckt_input_exists} and got finish_eval_state {:?}",
                finish_eval_state.fault_secret
            );
            assert_eq!(
                should_pass,
                finish_eval_state.fault_secret.is_none(),
                "no fault if it should pass"
            );
        }
    }

    fn test_data() -> Vec<(WithdrawalGarbData, bool)> {
        let mut test_data: Vec<(WithdrawalGarbData, bool)> = vec![];
        test_data.push((
            WithdrawalGarbData {
                withdrawal_input: [0u8; N_WITHDRAWAL_INPUT_WIRES],
            },
            false,
        ));

        let ckt_input_exists = std::fs::exists(Path::new("inputs.txt")).unwrap();
        if ckt_input_exists {
            let withdrawal_input_bits = read_inputs("inputs.txt", N_WITHDRAWAL_INPUT_WIRES * 8);
            let withdrawal_input_bytes =
                bits_to_bytes(&withdrawal_input_bits, N_WITHDRAWAL_INPUT_WIRES);
            test_data.push((
                WithdrawalGarbData {
                    withdrawal_input: withdrawal_input_bytes.try_into().unwrap(),
                },
                true,
            )); // valid data

            // Now corrupt proof.a and make it invalid
            let mut withdrawal_input_bits = read_inputs("inputs.txt", N_WITHDRAWAL_INPUT_WIRES * 8);
            let index_to_corrupt = (36 + 16) * 8; // belongs to proof_a which we validate in ckt generated from `test/simple_circuit_postaudit`
            let prev_value = withdrawal_input_bits[index_to_corrupt];
            withdrawal_input_bits.set(index_to_corrupt, !prev_value); // toggle
            let withdrawal_input_bytes =
                bits_to_bytes(&withdrawal_input_bits, N_WITHDRAWAL_INPUT_WIRES);
            test_data.push((
                WithdrawalGarbData {
                    withdrawal_input: withdrawal_input_bytes.try_into().unwrap(),
                },
                false,
            ));

            // Now corrupt proof.b and this will still be valid because miniature circuit doesn't
            // check proof.b right now
            let index_to_corrupt = (36 + 32 + 16) * 8; // belongs to proof_a which we validate in ckt generated from `test/simple_circuit_postaudit`
            let mut withdrawal_input_bits = read_inputs("inputs.txt", N_WITHDRAWAL_INPUT_WIRES * 8);
            let prev_value = withdrawal_input_bits[index_to_corrupt];
            withdrawal_input_bits.set(index_to_corrupt, !prev_value); // toggle
            let withdrawal_input_bytes =
                bits_to_bytes(&withdrawal_input_bits, N_WITHDRAWAL_INPUT_WIRES);
            test_data.push((
                WithdrawalGarbData {
                    withdrawal_input: withdrawal_input_bytes.try_into().unwrap(),
                },
                true,
            ));
        }
        test_data
    }

    /// Read input bits from a text file containing 0s and 1s
    fn read_inputs(input_file: &str, expected_num_inputs: usize) -> BitVec {
        let mut input_string = String::new();
        let file = File::open(input_file)
            .unwrap_or_else(|_| panic!("Failed to open input file: {}", input_file));
        let mut reader = BufReader::new(file);
        reader.read_to_string(&mut input_string).unwrap();

        let input_string = input_string.trim();

        assert_eq!(
            input_string.len(),
            expected_num_inputs,
            "Input file has {} bits but circuit expects {}",
            input_string.len(),
            expected_num_inputs
        );

        let mut input_values_bits = BitVec::repeat(false, expected_num_inputs);
        for (idx, char) in input_string.chars().enumerate() {
            match char {
                '0' => input_values_bits.set(idx, false),
                '1' => input_values_bits.set(idx, true),
                _ => panic!("Invalid input character '{}' at position {}", char, idx),
            }
        }

        input_values_bits
    }

    /// Convert bits to bytes (LSB-first within each byte)
    fn bits_to_bytes(bits: &BitVec, num_bytes: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; num_bytes];
        for (bit_idx, bit) in bits.iter().enumerate() {
            if *bit {
                let byte_idx = bit_idx / 8;
                let bit_position = bit_idx % 8;
                if byte_idx < num_bytes {
                    bytes[byte_idx] |= 1 << bit_position;
                }
            }
        }
        bytes
    }
}

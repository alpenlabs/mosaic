/// Generates a suite of roundtrip tests for any storage backend implementing
/// the garbler [`StateMut`] trait.
///
/// The macro takes an expression that creates a storage **provider** — an
/// object implementing both `StorageProvider` and `StorageProviderMut`.
/// Each test obtains a mutable handle from the provider, writes data, commits,
/// then obtains a read-only handle and verifies the data was persisted.
///
/// # Example
///
/// ```ignore
/// #[cfg(test)]
/// mod garbler_tests {
///     use my_crate::MyProvider;
///     mosaic_storage_kvstore::garbler_store_tests!(MyProvider::new());
/// }
/// ```
#[macro_export]
macro_rules! garbler_store_tests {
    ($create_provider:expr) => {
        use $crate::{
            __private::{
                futures::StreamExt as _,
                mosaic_cac_types::{
                    Adaptor, AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices,
                    CompletedSignatures, DepositAdaptors, DepositId, DepositInputs, InputShares,
                    OutputShares, ReservedSetupInputShares, SecretKey, Seed, SetupInputs, Sighash,
                    Sighashes, Signature, WideLabelWireAdaptors,
                    WideLabelWirePolynomialCommitments, WideLabelWireShares, WithdrawalAdaptors,
                    WithdrawalAdaptorsChunk, WithdrawalInputs,
                    state_machine::garbler::{
                        Config, DepositState, DepositStep, GarblerState, GarblingMetadata,
                        StateMut as _, StateRead as _,
                    },
                },
                mosaic_common::{
                    Byte32,
                    constants::{
                        N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES,
                        N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES,
                    },
                },
                mosaic_vs3::{Index, Polynomial, PolynomialCommitment, Scalar, Share, gen_mul},
                rand_chacha::{ChaCha20Rng, rand_core::SeedableRng},
                tokio,
            },
            Commit, StorageProvider, StorageProviderMut,
        };

        fn test_peer_id() -> $crate::__private::mosaic_net_svc_api::PeerId {
            $crate::__private::mosaic_net_svc_api::PeerId::from([0x01; 32])
        }

        fn dep_id(byte: u8) -> DepositId {
            let mut bytes = [0u8; 32];
            bytes.fill(byte);
            DepositId(Byte32::from(bytes))
        }

        fn deposit_state(seed: u8) -> DepositState {
            let mut sk = [0u8; 32];
            sk.fill(seed);
            DepositState {
                step: DepositStep::default(),
                pk: SecretKey::from_raw_bytes(&sk).to_pubkey(),
            }
        }

        fn byte32(seed: u8) -> Byte32 {
            Byte32::from([seed; 32])
        }

        fn polynomial_commitment(seed: u64) -> PolynomialCommitment {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            Polynomial::rand(&mut rng).commit()
        }

        fn input_polynomial_commitments(seed: u64) -> WideLabelWirePolynomialCommitments {
            let c = polynomial_commitment(seed);
            WideLabelWirePolynomialCommitments::new(|_| c.clone())
        }

        fn output_polynomial_commitment(
            seed: u64,
        ) -> $crate::__private::mosaic_cac_types::OutputPolynomialCommitment {
            $crate::__private::mosaic_cac_types::OutputPolynomialCommitment::from_elem(
                polynomial_commitment(seed),
            )
        }

        fn circuit_input_shares(
            index: Index,
            seed: u64,
        ) -> $crate::__private::mosaic_cac_types::CircuitInputShares {
            $crate::__private::mosaic_cac_types::CircuitInputShares::new(|wire| {
                WideLabelWireShares::new(|value| {
                    Share::new(index, Scalar::from(seed + wire as u64 + value as u64 + 1))
                })
            })
        }

        fn circuit_output_share(
            index: Index,
            seed: u64,
        ) -> $crate::__private::mosaic_cac_types::CircuitOutputShare {
            Share::new(index, Scalar::from(seed))
        }

        fn challenge_indices() -> ChallengeIndices {
            ChallengeIndices::new(|idx| Index::new(idx + 1).expect("valid challenge index"))
        }

        fn sighashes(seed: u8) -> Sighashes {
            Sighashes::new(|idx| Sighash(byte32(seed.wrapping_add(idx as u8))))
        }

        fn deposit_inputs(seed: u8) -> DepositInputs {
            std::array::from_fn(|idx| seed.wrapping_add(idx as u8))
        }

        fn withdrawal_inputs(seed: u8) -> WithdrawalInputs {
            std::array::from_fn(|idx| seed.wrapping_add(idx as u8))
        }

        fn adaptor(seed: u64) -> Adaptor {
            let scalar = Scalar::from(seed + 1);
            let point = gen_mul(&scalar);
            Adaptor {
                tweaked_s: scalar,
                R_dash_commit: point,
                share_commitment: point,
            }
        }

        fn adaptor_msg_chunk(chunk_index: u8, seed: u64) -> AdaptorMsgChunk {
            AdaptorMsgChunk {
                deposit_id: DepositId::from([0; 32]),
                chunk_index,
                deposit_adaptor: adaptor(seed + chunk_index as u64),
                withdrawal_adaptors: WithdrawalAdaptorsChunk::new(|wire_idx| {
                    WideLabelWireAdaptors::new(|value_idx| {
                        adaptor(
                            seed + chunk_index as u64
                                + wire_idx as u64 * 256
                                + value_idx as u64
                                + 1,
                        )
                    })
                }),
            }
        }

        fn signature(seed: u8) -> Signature {
            let mut bytes = [0u8; 64];
            bytes[31] = seed.wrapping_add(1);
            bytes[63] = seed.wrapping_add(2);
            Signature::from_bytes(bytes).expect("valid test signature")
        }

        fn completed_signatures(seed: u8) -> CompletedSignatures {
            CompletedSignatures::new(|idx| signature(seed.wrapping_add(idx as u8)))
        }

        fn garbling_metadata(seed: u8) -> GarblingMetadata {
            GarblingMetadata {
                aes128_key: [seed; 16],
                public_s: [seed.wrapping_add(1); 16],
                constant_zero_label: [seed.wrapping_add(2); 16],
                constant_one_label: [seed.wrapping_add(3); 16],
                output_label_ct: byte32(seed.wrapping_add(4)),
            }
        }

        fn garbler_config(seed: u8) -> Config {
            Config {
                seed: Seed::from([seed; 32]),
                setup_inputs: std::array::from_fn(|idx| seed.wrapping_add(idx as u8)),
            }
        }

        // ----- tests -----

        #[tokio::test]
        async fn root_and_deposit_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let root = GarblerState::default();
            let deposit_id = dep_id(0xA1);
            let dep_state = deposit_state(7);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store.put_root_state(&root).await.expect("put root");
            store
                .put_deposit(deposit_id, &dep_state)
                .await
                .expect("put deposit");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(store.get_root_state().await.expect("get root"), Some(root));
            assert_eq!(
                store.get_deposit(&deposit_id).await.expect("get deposit"),
                Some(dep_state)
            );
        }

        #[tokio::test]
        async fn input_polynomial_commitment_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = input_polynomial_commitments(19);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_input_polynomial_commitments_chunk(19, &expected)
                .await
                .expect("put input commitments chunk");
            for wire_idx in 0..N_INPUT_WIRES {}
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_input_polynomial_commitment_by_wire(19)
                    .await
                    .expect("get"),
                Some(expected)
            );

            assert_eq!(
                store
                    .get_input_polynomial_commitment_by_wire(55)
                    .await
                    .expect("get"),
                None
            );
        }

        #[tokio::test]
        async fn output_polynomial_commitment_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = output_polynomial_commitment(29);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_output_polynomial_commitment(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_output_polynomial_commitment().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();

            let index = Index::new(3).expect("valid index");

            let is = circuit_input_shares(index, 10_000 + 3 as u64);
            let os = circuit_output_share(index, 20_000 + 3 as u64);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_shares_for_index(index, &is, &os)
                .await
                .expect("put shares");

            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_input_shares_for_circuit(&index)
                    .await
                    .expect("get"),
                Some(is)
            );
            assert_eq!(
                store
                    .get_output_share_for_circuit(&index)
                    .await
                    .expect("get"),
                Some(os)
            );

            let unused_index = Index::new(1).expect("valid index");

            assert_eq!(
                store
                    .get_input_shares_for_circuit(&unused_index)
                    .await
                    .expect("get"),
                None
            );
            assert_eq!(
                store
                    .get_output_share_for_circuit(&unused_index)
                    .await
                    .expect("get"),
                None
            );
        }

        #[tokio::test]
        async fn gt_commitment_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let mut expected = Vec::with_capacity(N_CIRCUITS);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            for ckt_idx in 1..=N_CIRCUITS {
                let index = Index::new(ckt_idx).expect("valid index");
                let c = byte32(ckt_idx as u8);
                store
                    .put_garbling_table_commitment(index, &c)
                    .await
                    .expect("put");
                expected.push(c);
            }
            store.commit().await.expect("commit");

            let expected_all = AllGarblingTableCommitments::from_vec(expected);
            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_garbling_table_commitment(Index::new(4).expect("valid"))
                    .await
                    .expect("get"),
                Some(byte32(4))
            );
            assert_eq!(
                store
                    .get_all_garbling_table_commitments()
                    .await
                    .expect("get"),
                Some(expected_all)
            );
        }

        #[tokio::test]
        async fn protocol_state_roundtrip_all_pairs() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = challenge_indices();

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store.put_challenge_indices(&expected).await.expect("put");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_challenge_indices().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn deposit_scoped_roundtrip_all_pairs() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let deposit_id = dep_id(0xC1);
            let exp_sig = sighashes(0x31);
            let exp_dep_in = deposit_inputs(0x41);
            let exp_wth_in = withdrawal_inputs(0x51);
            let exp_comp_sig = completed_signatures(0x61);

            let mut exp_dep_adapt = Vec::with_capacity(N_DEPOSIT_INPUT_WIRES);
            let mut exp_wth_adapt = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
            let mut chunks = Vec::with_capacity(N_ADAPTOR_MSG_CHUNKS);
            for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
                let chunk = adaptor_msg_chunk(chunk_idx as u8, 0x1000);
                exp_dep_adapt.push(chunk.deposit_adaptor);
                exp_wth_adapt.extend(chunk.withdrawal_adaptors.to_vec());
                chunks.push(chunk);
            }

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_deposit(deposit_id, &deposit_state(9))
                .await
                .expect("put deposit");
            store
                .put_sighashes_for_deposit(&deposit_id, &exp_sig)
                .await
                .expect("put");
            store
                .put_inputs_for_deposit(&deposit_id, &exp_dep_in)
                .await
                .expect("put");
            store
                .put_withdrawal_input(&deposit_id, &exp_wth_in)
                .await
                .expect("put");
            for chunk in &chunks {
                store
                    .put_adaptor_msg_chunk_for_deposit(&deposit_id, chunk)
                    .await
                    .expect("put");
            }
            store
                .put_completed_signatures(&deposit_id, &exp_comp_sig)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_deposit_sighashes(&deposit_id).await.expect("get"),
                Some(exp_sig)
            );
            assert_eq!(
                store.get_deposit_inputs(&deposit_id).await.expect("get"),
                Some(exp_dep_in)
            );
            assert_eq!(
                store.get_withdrawal_input(&deposit_id).await.expect("get"),
                Some(exp_wth_in)
            );
            assert_eq!(
                store.get_deposit_adaptors(&deposit_id).await.expect("get"),
                Some(DepositAdaptors::from_vec(exp_dep_adapt))
            );
            assert_eq!(
                store
                    .get_withdrawal_adaptors(&deposit_id)
                    .await
                    .expect("get"),
                Some(WithdrawalAdaptors::from_vec(exp_wth_adapt))
            );
            assert_eq!(
                store
                    .get_completed_signatures(&deposit_id)
                    .await
                    .expect("get"),
                Some(exp_comp_sig)
            );
        }

        #[tokio::test]
        async fn stream_all_deposits_scopes_to_deposit_state_row() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let dep1_id = dep_id(0x01);
            let dep2_id = dep_id(0x02);
            let dep1 = deposit_state(1);
            let dep2 = deposit_state(2);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store.put_deposit(dep1_id, &dep1).await.unwrap();
            store.put_deposit(dep2_id, &dep2).await.unwrap();
            store
                .put_root_state(&GarblerState::default())
                .await
                .unwrap();
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            let mut got = store
                .stream_all_deposits()
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .map(|item| item.expect("stream item"))
                .collect::<Vec<_>>();
            got.sort_by_key(|(id, _)| id.0);
            assert_eq!(got, vec![(dep1_id, dep1), (dep2_id, dep2)]);
        }

        #[tokio::test]
        async fn garbling_metadata_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            for ckt in 1..=N_CIRCUITS {
                let index = Index::new(ckt).expect("valid index");
                let md = garbling_metadata(ckt as u8);
                store
                    .put_garbling_table_metadata(index, &md)
                    .await
                    .expect("put metadata");
            }
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            let keys = store.get_all_aes128_keys().await.expect("get keys");
            let public_s = store.get_all_public_s_values().await.expect("get public_s");
            let zero = store
                .get_all_constant_zero_labels()
                .await
                .expect("get zero");
            let one = store.get_all_constant_one_labels().await.expect("get one");
            let cts = store.get_all_output_label_cts().await.expect("get cts");

            let keys = keys.expect("keys present");
            let public_s = public_s.expect("public_s present");
            let zero = zero.expect("zero labels present");
            let one = one.expect("one labels present");
            let cts = cts.expect("cts present");

            for ckt in 1..=N_CIRCUITS {
                let md = garbling_metadata(ckt as u8);
                let i = ckt - 1; // 0-based HeapArray index
                assert_eq!(keys[i], md.aes128_key);
                assert_eq!(public_s[i], md.public_s);
                assert_eq!(zero[i], md.constant_zero_label);
                assert_eq!(one[i], md.constant_one_label);
                assert_eq!(cts[i], md.output_label_ct);
            }
        }

        #[tokio::test]
        async fn output_shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();

            let mut expected_output_shares = Vec::with_capacity(N_CIRCUITS + 1);

            // Write in batches of 2 circuits to stay within FDB txn limits.
            for batch_start in (0..=N_CIRCUITS).step_by(2) {
                let batch_end = std::cmp::min(batch_start + 2, N_CIRCUITS + 1);
                let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
                for idx in batch_start..batch_end {
                    let index = if idx == 0 {
                        Index::reserved()
                    } else {
                        Index::new(idx).expect("valid index")
                    };
                    let is = circuit_input_shares(index, 10_000 + idx as u64);
                    let os = circuit_output_share(index, 20_000 + idx as u64);
                    store
                        .put_shares_for_index(index, &is, &os)
                        .await
                        .expect("put shares");
                    expected_output_shares.push(os);
                }
                store.commit().await.expect("commit");
            }

            let store = provider.garbler_state(&peer).await.expect("get read");
            let got = store
                .get_output_shares()
                .await
                .expect("get output shares")
                .expect("output shares present");
            for (i, expected) in expected_output_shares.iter().enumerate() {
                assert_eq!(&got[i], expected, "output share mismatch at index {i}");
            }
        }

        #[tokio::test]
        async fn reserved_input_shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let reserved = Index::reserved();
            let expected_is = circuit_input_shares(reserved, 7000);
            let os = circuit_output_share(reserved, 8000);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_shares_for_index(reserved, &expected_is, &os)
                .await
                .expect("put shares");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            let got = store
                .get_reserved_input_shares()
                .await
                .expect("get reserved input shares")
                .expect("reserved input shares present");
            assert_eq!(got, expected_is);
        }

        #[tokio::test]
        async fn reserved_setup_input_shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let config = garbler_config(0x10);
            let reserved = Index::reserved();
            let reserved_is = circuit_input_shares(reserved, 9000);
            let os = circuit_output_share(reserved, 9500);

            let mut store = provider.garbler_state_mut(&peer).await.expect("get mut");
            store
                .put_root_state(&GarblerState {
                    config: Some(config),
                    ..GarblerState::default()
                })
                .await
                .expect("put root state");
            store
                .put_shares_for_index(reserved, &reserved_is, &os)
                .await
                .expect("put shares");
            store.commit().await.expect("commit");

            let store = provider.garbler_state(&peer).await.expect("get read");
            let got = store
                .get_reserved_setup_input_shares()
                .await
                .expect("get reserved setup input shares")
                .expect("reserved setup input shares present");

            // Verify: for each setup wire, the returned share should be
            // the reserved circuit's share at the wide-label value from setup_inputs.
            for idx in 0..N_SETUP_INPUT_WIRES {
                let value = config.setup_inputs[idx];
                let expected_share = reserved_is[idx][value as usize];
                assert_eq!(
                    got[idx], expected_share,
                    "setup input share mismatch at wire {idx}"
                );
            }
        }
    };
}

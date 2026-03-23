/// Generates a suite of roundtrip tests for any storage backend implementing
/// the evaluator [`StateMut`] trait.
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
/// mod evaluator_tests {
///     use my_crate::MyProvider;
///     mosaic_storage_kvstore::evaluator_store_tests!(MyProvider::new());
/// }
/// ```
#[macro_export]
macro_rules! evaluator_store_tests {
    ($create_provider:expr) => {
        use $crate::{
            __private::{
                futures::StreamExt as _,
                mosaic_cac_types::{
                    Adaptor, AllGarblingTableCommitments, ChallengeIndices, CompletedSignatures,
                    DepositAdaptors, DepositId, DepositInputs, EvaluationIndices, HeapArray,
                    OpenedInputShares, ReservedSetupInputShares, SecretKey, Seed, Sighash,
                    Sighashes, Signature, WideLabelWireAdaptors,
                    WideLabelWirePolynomialCommitments, WideLabelWireShares,
                    WideLabelZerothPolynomialCoefficients, WithdrawalAdaptors,
                    WithdrawalAdaptorsChunk, WithdrawalInputs,
                    state_machine::evaluator::{
                        DepositState, DepositStep, EvaluatorState, StateMut as _, StateRead as _,
                        Step,
                    },
                },
                mosaic_common::{
                    Byte32,
                    constants::{
                        N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_EVAL_CIRCUITS, N_INPUT_WIRES,
                        N_WITHDRAWAL_INPUT_WIRES,
                    },
                },
                mosaic_vs3::{
                    Index, Point, Polynomial, PolynomialCommitment, Scalar, Share, gen_mul,
                },
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
                sk: SecretKey::from_raw_bytes(&sk),
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

        fn reserved_setup_input_shares(seed: u64) -> ReservedSetupInputShares {
            ReservedSetupInputShares::new(|idx| {
                Share::new(Index::reserved(), Scalar::from(seed + idx as u64 + 1))
            })
        }

        fn opened_output_shares(
            seed: u64,
        ) -> $crate::__private::mosaic_cac_types::OpenedOutputShares {
            $crate::__private::mosaic_cac_types::OpenedOutputShares::new(|idx| {
                let index = Index::new(idx + 1).expect("valid index");
                circuit_output_share(index, seed + idx as u64)
            })
        }

        fn opened_garbling_seeds(
            seed: u8,
        ) -> $crate::__private::mosaic_cac_types::OpenedGarblingSeeds {
            $crate::__private::mosaic_cac_types::OpenedGarblingSeeds::new(|idx| {
                Seed::from([seed.wrapping_add(idx as u8); 32])
            })
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

        fn deposit_adaptors(seed: u64) -> $crate::__private::mosaic_cac_types::DepositAdaptors {
            DepositAdaptors::new(|idx| adaptor(seed + idx as u64))
        }

        fn withdrawal_adaptors_chunk(seed: u64) -> WithdrawalAdaptorsChunk {
            WithdrawalAdaptorsChunk::new(|wire_idx| {
                WideLabelWireAdaptors::new(|value_idx| {
                    adaptor(seed + wire_idx as u64 * 256 + value_idx as u64 + 1)
                })
            })
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

        fn indexed_value(seed: u8, idx: usize) -> [u8; 16] {
            [seed.wrapping_add(idx as u8); 16]
        }

        fn zeroth_coefficients(seed: u64) -> WideLabelZerothPolynomialCoefficients {
            WideLabelZerothPolynomialCoefficients::new(|idx| {
                gen_mul(&Scalar::from(seed + idx as u64 + 1))
            })
        }

        fn heap_array_16(seed: u8) -> HeapArray<[u8; 16], { N_CIRCUITS }> {
            HeapArray::new(|idx| [seed.wrapping_add(idx as u8); 16])
        }

        fn evaluation_indices() -> EvaluationIndices {
            std::array::from_fn(|idx| Index::new(idx + 1).expect("valid eval index"))
        }

        // ----- tests -----

        #[tokio::test]
        async fn root_and_deposit_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let root = EvaluatorState {
                config: None,
                step: Step::SetupComplete,
            };
            let deposit_id = dep_id(0xA1);
            let dep_state = deposit_state(7);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store.put_root_state(&root).await.expect("put root");
            store
                .put_deposit(&deposit_id, &dep_state)
                .await
                .expect("put deposit");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
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

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_input_polynomial_commitments_chunk(0, &expected)
                .await
                .expect("put input commitments chunk");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_input_polynomial_commitments_for_wire(0)
                    .await
                    .expect("get"),
                Some(expected)
            );

            assert_eq!(
                store
                    .get_input_polynomial_commitments_for_wire(99)
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

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_output_polynomial_commitment(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_output_polynomial_commitment().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn garbling_table_commitments_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected =
                AllGarblingTableCommitments::new(|idx| byte32(0x50u8.wrapping_add(idx as u8)));

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_garbling_table_commitments(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_garbling_table_commitments().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn challenge_indices_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = challenge_indices();

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store.put_challenge_indices(&expected).await.expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_challenge_indices().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn reserved_setup_input_shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = reserved_setup_input_shares(20_000);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_reserved_setup_input_shares(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_reserved_setup_input_shares().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn opened_output_shares_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = opened_output_shares(30_000);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_opened_output_shares(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_opened_output_shares().await.expect("get"),
                Some(expected)
            );
        }

        #[tokio::test]
        async fn opened_garbling_seeds_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let expected = opened_garbling_seeds(0x61);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_opened_garbling_seeds(&expected)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_opened_garbling_seeds().await.expect("get"),
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
            let exp_dep_adapt = deposit_adaptors(0x1000);
            let exp_comp_sig = completed_signatures(0x61);

            let mut exp_wth_adapt = Vec::with_capacity(N_WITHDRAWAL_INPUT_WIRES);
            let mut chunks = Vec::with_capacity(N_ADAPTOR_MSG_CHUNKS);
            for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
                let chunk = withdrawal_adaptors_chunk(0x2000 + chunk_idx as u64);
                exp_wth_adapt.extend(chunk.to_vec());
                chunks.push((chunk_idx as u8, chunk));
            }

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_deposit(&deposit_id, &deposit_state(9))
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
                .put_withdrawal_inputs(&deposit_id, &exp_wth_in)
                .await
                .expect("put");
            store
                .put_deposit_adaptors(&deposit_id, &exp_dep_adapt)
                .await
                .expect("put");
            for (chunk_idx, chunk) in &chunks {
                store
                    .put_withdrawal_adaptors_chunk(&deposit_id, *chunk_idx, chunk)
                    .await
                    .expect("put");
            }
            store
                .put_completed_signatures(&deposit_id, &exp_comp_sig)
                .await
                .expect("put");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_deposit_sighashes(&deposit_id).await.expect("get"),
                Some(exp_sig)
            );
            assert_eq!(
                store.get_deposit_inputs(&deposit_id).await.expect("get"),
                Some(exp_dep_in)
            );
            assert_eq!(
                store.get_withdrawal_inputs(&deposit_id).await.expect("get"),
                Some(exp_wth_in)
            );
            assert_eq!(
                store.get_deposit_adaptors(&deposit_id).await.expect("get"),
                Some(exp_dep_adapt)
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

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store.put_deposit(&dep1_id, &dep1).await.unwrap();
            store.put_deposit(&dep2_id, &dep2).await.unwrap();
            store
                .put_root_state(&EvaluatorState {
                    config: None,
                    step: Step::SetupComplete,
                })
                .await
                .unwrap();
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
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
        async fn get_input_polynomial_commitments_for_wire_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let wire0_comms = input_polynomial_commitments(100);
            let wire1_comms = input_polynomial_commitments(200);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_input_polynomial_commitments_chunk(0, &wire0_comms)
                .await
                .expect("put wire 0 commitments");
            store
                .put_input_polynomial_commitments_chunk(1, &wire1_comms)
                .await
                .expect("put wire 1 commitments");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_input_polynomial_commitments_for_wire(0)
                    .await
                    .expect("get wire 0"),
                Some(wire0_comms)
            );
            assert_eq!(
                store
                    .get_input_polynomial_commitments_for_wire(1)
                    .await
                    .expect("get wire 1"),
                Some(wire1_comms)
            );
            assert_eq!(
                store
                    .get_input_polynomial_commitments_for_wire(99)
                    .await
                    .expect("get missing wire"),
                None
            );
        }

        #[tokio::test]
        async fn get_opened_input_shares_for_circuit_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let idx1 = Index::new(2).unwrap();
            let idx2 = Index::new(4).unwrap();
            let shares1 = circuit_input_shares(idx1, 5000);
            let shares2 = circuit_input_shares(idx2, 6000);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_opened_input_shares_chunk(idx1.get() as u16, &shares1)
                .await
                .expect("put circuit 2 shares");
            store
                .put_opened_input_shares_chunk(idx2.get() as u16, &shares2)
                .await
                .expect("put circuit 4 shares");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store
                    .get_opened_input_shares_for_circuit(idx1.get() as u16)
                    .await
                    .expect("get circuit 2"),
                Some(shares1)
            );
            assert_eq!(
                store
                    .get_opened_input_shares_for_circuit(idx2.get() as u16)
                    .await
                    .expect("get circuit 4"),
                Some(shares2)
            );
            assert_eq!(
                store
                    .get_opened_input_shares_for_circuit(1)
                    .await
                    .expect("get missing circuit"),
                None
            );
        }

        #[tokio::test]
        async fn zeroth_polynomial_coefficients_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let wire0 = zeroth_coefficients(100);
            let wire1 = zeroth_coefficients(200);

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_input_polynomial_commitment_zeroth_coeffs(0, &wire0)
                .await
                .expect("put wire 0");
            store
                .put_input_polynomial_commitment_zeroth_coeffs(1, &wire1)
                .await
                .expect("put wire 1");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            let got = store
                .get_input_polynomial_zeroth_coefficients(0..2)
                .await
                .expect("get range 0..2");
            assert_eq!(got.len(), 2);
            assert_eq!(got[0], wire0);
            assert_eq!(got[1], wire1);

            let got_single = store
                .get_input_polynomial_zeroth_coefficients(0..1)
                .await
                .expect("get range 0..1");
            assert_eq!(got_single.len(), 1);
            assert_eq!(got_single[0], wire0);
        }

        #[tokio::test]
        async fn garbling_material_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let keys = heap_array_16(0x10);
            let public_s = heap_array_16(0x20);
            let zero_labels = heap_array_16(0x30);
            let one_labels = heap_array_16(0x40);
            let eval_indices = evaluation_indices();
            let output_cts = HeapArray::<Byte32, { N_EVAL_CIRCUITS }>::new(|idx| {
                byte32(0x50u8.wrapping_add(idx as u8))
            });

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store.put_all_aes128_keys(&keys).await.expect("put keys");
            store
                .put_all_public_s(&public_s)
                .await
                .expect("put public_s");
            store
                .put_all_constant_zero_labels(&zero_labels)
                .await
                .expect("put zero labels");
            store
                .put_all_constant_one_labels(&one_labels)
                .await
                .expect("put one labels");
            store
                .put_unchallenged_output_label_cts(&eval_indices, &output_cts)
                .await
                .expect("put output cts");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");

            // Check a specific circuit index (1-based in the trait)
            let idx = Index::new(1).expect("valid");
            assert_eq!(
                store.get_aes128_key(idx).await.expect("get key"),
                Some(keys[0])
            );
            assert_eq!(
                store.get_public_s(idx).await.expect("get public_s"),
                Some(public_s[0])
            );
            assert_eq!(
                store
                    .get_constant_zero_label(idx)
                    .await
                    .expect("get zero label"),
                Some(zero_labels[0])
            );
            assert_eq!(
                store
                    .get_constant_one_label(idx)
                    .await
                    .expect("get one label"),
                Some(one_labels[0])
            );

            // Output label CT uses eval_indices[0] which is Index(1)
            assert_eq!(
                store
                    .get_output_label_ct(eval_indices[0])
                    .await
                    .expect("get output ct"),
                Some(output_cts[0])
            );

            // Check another valid circuit index
            let idx2 = Index::new(N_CIRCUITS).expect("valid");
            assert_eq!(
                store.get_aes128_key(idx2).await.expect("get last key"),
                Some(keys[N_CIRCUITS - 1])
            );
        }

        #[tokio::test]
        async fn fault_secret_share_roundtrip() {
            let provider = $create_provider;
            let peer = test_peer_id();
            let idx = Index::new(3).expect("valid");
            let expected = Share::new(idx, Scalar::from(42u64));

            let mut store = provider.evaluator_state_mut(&peer).await.expect("get mut");
            store
                .put_fault_secret_share(&expected)
                .await
                .expect("put fault share");
            store.commit().await.expect("commit");

            let store = provider.evaluator_state(&peer).await.expect("get read");
            assert_eq!(
                store.get_fault_secret_share().await.expect("get"),
                Some(expected)
            );
        }
    };
}

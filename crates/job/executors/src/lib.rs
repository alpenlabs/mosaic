//! Action executor implementations for the Mosaic job scheduler.
//!
//! Provides [`MosaicExecutor`], the concrete implementation of the
//! `JobExecutor` trait defined in `mosaic-job-api`.
//!
//! This crate provides [`MosaicExecutor`], the concrete implementation of the
//! `JobExecutor` trait. The scheduler is generic over `JobExecutor` and has
//! no compile-time dependency on the execution logic in this crate.
//!
//! # Modules
//!
//! - [`garbler`] / [`evaluator`] — per-role action execution.
//! - [`garbling`] — reusable [`GarblingSession`](garbling::GarblingSession) for circuit garbling
//!   (shared by commitment and transfer actions).
//! - [`polynomial_cache`] — bounded cache for polynomial data during setup.

use std::path::PathBuf;

pub mod circuit_sessions;
pub mod evaluator;
pub mod garbler;
pub mod garbling;
pub mod polynomial_cache;

use ckt_fmtv5_types::v5::c::ReaderV5c;
use mosaic_cac_types::state_machine::{evaluator::StateRead as _, garbler::StateRead as _};
use mosaic_job_api::{CircuitError, ExecuteEvaluatorJob, ExecuteGarblerJob, HandlerOutcome};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{StorageProvider, TableStore};
use mosaic_vs3::Index;

use crate::polynomial_cache::PolynomialCache;

/// Concrete executor for Mosaic job actions.
///
/// Holds all resources needed by action executors: network client, polynomial
/// cache, and a [`StorageProvider`] for reading state machine data.
///
/// Generic over [`StorageProvider`] for SM state access and [`TableStore`]
/// for garbling table persistence.
pub struct MosaicExecutor<SP: StorageProvider, TS: TableStore> {
    /// Typed network client for protocol message sends and acks.
    pub net_client: mosaic_net_client::NetClient,
    /// Polynomial cache for garbler setup (generate-once, read-many-times).
    pub polynomial_cache: PolynomialCache,
    /// Per-peer storage provider for reading state machine data.
    pub storage: SP,
    /// Persistent storage for garbling tables (ciphertexts, translation, metadata).
    pub table_store: TS,
    /// Path to the v5c circuit file used for garbling and evaluation.
    pub circuit_path: PathBuf,
}

impl<SP: StorageProvider, TS: TableStore> MosaicExecutor<SP, TS> {
    /// Create a new executor with default polynomial cache size.
    pub fn new(
        net_client: mosaic_net_client::NetClient,
        storage: SP,
        table_store: TS,
        circuit_path: PathBuf,
    ) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(4),
            storage,
            table_store,
            circuit_path,
        }
    }

    /// Create a new executor with a custom polynomial cache size.
    pub fn with_cache_size(
        net_client: mosaic_net_client::NetClient,
        storage: SP,
        table_store: TS,
        circuit_path: PathBuf,
        max_cache_entries: usize,
    ) -> Self {
        Self {
            net_client,
            polynomial_cache: PolynomialCache::new(max_cache_entries),
            storage,
            table_store,
            circuit_path,
        }
    }
}

impl<SP: StorageProvider, TS: TableStore> std::fmt::Debug for MosaicExecutor<SP, TS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MosaicExecutor").finish_non_exhaustive()
    }
}

impl<SP: StorageProvider, TS: TableStore> ExecuteGarblerJob for MosaicExecutor<SP, TS> {
    type Session = circuit_sessions::GarblerCircuitSession;

    fn generate_polynomial_commitments(
        &self,
        _peer_id: &PeerId,
        seed: mosaic_cac_types::Seed,
        wire: mosaic_cac_types::state_machine::garbler::Wire,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_generate_polynomial_commitments(self, seed, wire)
    }

    fn generate_shares(
        &self,
        _peer_id: &PeerId,
        seed: mosaic_cac_types::Seed,
        index: mosaic_vs3::Index,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_generate_shares(self, seed, index)
    }

    fn send_commit_msg_header(
        &self,
        peer_id: &PeerId,
        header: &mosaic_cac_types::CommitMsgHeader,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_commit_msg_header(self, peer_id, header)
    }

    fn send_commit_msg_chunk(
        &self,
        peer_id: &PeerId,
        wire_idx: u16,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_commit_msg_chunk(self, peer_id, wire_idx)
    }

    fn send_challenge_response_header(
        &self,
        peer_id: &PeerId,
        header: &mosaic_cac_types::ChallengeResponseMsgHeader,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_challenge_response_header(self, peer_id, header)
    }

    fn send_challenge_response_chunk(
        &self,
        peer_id: &PeerId,
        index: &Index,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_challenge_response_chunk(self, peer_id, index)
    }

    fn deposit_verify_adaptors(
        &self,
        peer_id: &PeerId,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_verify_adaptors(self, peer_id, deposit_id)
    }

    fn complete_adaptor_signatures(
        &self,
        peer_id: &PeerId,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_complete_adaptor_signatures(self, peer_id, deposit_id)
    }

    fn begin_table_commitment(
        &self,
        peer_id: &PeerId,
        index: mosaic_vs3::Index,
        seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        let peer_id = *peer_id;
        async move {
            let garb_state = self
                .storage
                .garbler_state(&peer_id)
                .await
                .map_err(|_| CircuitError::StorageUnavailable)?;
            let input_shares = garb_state
                .get_input_shares_for_circuit(&index)
                .await
                .ok()
                .flatten()
                .ok_or(CircuitError::StorageUnavailable)?;
            let output_share = garb_state
                .get_output_share_for_circuit(&index)
                .await
                .ok()
                .flatten()
                .ok_or(CircuitError::StorageUnavailable)?;

            let reader = ReaderV5c::open(&self.circuit_path)
                .map_err(|e| CircuitError::SetupFailed(format!("circuit open: {e}")))?;
            let header = *reader.header();
            let outputs = reader.outputs().to_vec();

            let setup = garbling::GarblingSession::begin(
                seed,
                input_shares.as_ref(),
                &output_share,
                &header,
            );

            Ok(circuit_sessions::GarblerCircuitSession::Commitment(
                Box::new(circuit_sessions::CommitmentSession::new(
                    setup, outputs, index, true,
                )),
            ))
        }
    }

    fn begin_table_transfer(
        &self,
        peer_id: &PeerId,
        seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        let peer_id = *peer_id;
        async move {
            let session = garbler::setup_transfer_session(self, &peer_id, seed).await?;
            Ok(circuit_sessions::GarblerCircuitSession::Transfer(Box::new(
                session,
            )))
        }
    }
}

impl<SP: StorageProvider, TS: TableStore> ExecuteEvaluatorJob for MosaicExecutor<SP, TS> {
    type Session = circuit_sessions::EvaluatorCircuitSession;

    fn send_challenge_msg(
        &self,
        peer_id: &PeerId,
        msg: &mosaic_cac_types::ChallengeMsg,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_send_challenge_msg(self, peer_id, msg)
    }

    fn verify_opened_input_shares(
        &self,
        peer_id: &PeerId,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_verify_opened_input_shares(self, peer_id)
    }

    fn send_table_transfer_receipt(
        &self,
        peer_id: &PeerId,
        msg: &mosaic_cac_types::TableTransferReceiptMsg,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_send_table_transfer_receipt(self, peer_id, msg)
    }

    fn generate_deposit_adaptors(
        &self,
        peer_id: &PeerId,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_generate_deposit_adaptors(self, peer_id, deposit_id)
    }

    fn generate_withdrawal_adaptors_chunk(
        &self,
        peer_id: &PeerId,
        deposit_id: mosaic_cac_types::DepositId,
        chunk_idx: &mosaic_cac_types::state_machine::evaluator::ChunkIndex,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_generate_withdrawal_adaptors_chunk(self, peer_id, deposit_id, chunk_idx)
    }

    fn deposit_send_adaptor_msg_chunk(
        &self,
        peer_id: &PeerId,
        deposit_id: mosaic_cac_types::DepositId,
        chunk: &mosaic_cac_types::AdaptorMsgChunk,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_send_adaptor_msg_chunk(self, peer_id, deposit_id, chunk)
    }

    fn begin_table_commitment(
        &self,
        peer_id: &PeerId,
        index: mosaic_vs3::Index,
        seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        let peer_id = *peer_id;
        async move {
            let eval_state = self
                .storage
                .evaluator_state(&peer_id)
                .await
                .map_err(|_| CircuitError::StorageUnavailable)?;
            let challenge_indices = eval_state
                .get_challenge_indices()
                .await
                .ok()
                .flatten()
                .ok_or(CircuitError::StorageUnavailable)?;
            let opened_output_shares = eval_state
                .get_opened_output_shares()
                .await
                .ok()
                .flatten()
                .ok_or(CircuitError::StorageUnavailable)?;
            let opened_input_shares = evaluator::load_opened_input_shares(
                &self.storage,
                &peer_id,
                &challenge_indices,
            )
            .await?;
            let pos = challenge_indices.iter().position(|ci| *ci == index).ok_or(
                CircuitError::SetupFailed("index not in challenge indices".into()),
            )?;

            let output_share = &opened_output_shares[pos];

            let reader = ReaderV5c::open(&self.circuit_path)
                .map_err(|e| CircuitError::SetupFailed(format!("circuit open: {e}")))?;
            let header = *reader.header();
            let outputs = reader.outputs().to_vec();

            let setup = garbling::GarblingSession::begin(
                seed,
                opened_input_shares[pos].as_ref(),
                output_share,
                &header,
            );

            Ok(circuit_sessions::EvaluatorCircuitSession::Commitment(
                Box::new(circuit_sessions::CommitmentSession::new(
                    setup, outputs, index, false,
                )),
            ))
        }
    }

    fn receive_garbling_table(
        &self,
        peer_id: &PeerId,
        commitment: mosaic_cac_types::GarblingTableCommitment,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        evaluator::handle_receive_garbling_table(self, peer_id, commitment)
    }

    fn begin_evaluation(
        &self,
        peer_id: &PeerId,
        index: mosaic_vs3::Index,
        commitment: mosaic_cac_types::GarblingTableCommitment,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        let peer_id = *peer_id;
        async move {
            let session =
                evaluator::setup_evaluation_session(self, &peer_id, index, commitment).await?;
            Ok(circuit_sessions::EvaluatorCircuitSession::Evaluation(
                Box::new(session),
            ))
        }
    }
}

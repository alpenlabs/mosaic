//! Action executor implementations for the Mosaic job scheduler.
//!
//! Provides [`MosaicExecutor`], the concrete implementation of the
//! [`JobExecutor`] trait defined in `mosaic-job-api`.
//!
//! This crate provides [`MosaicExecutor`], the concrete implementation of the
//! [`JobExecutor`] trait. The scheduler is generic over `JobExecutor` and has
//! no compile-time dependency on the execution logic in this crate.
//!
//! # Modules
//!
//! - [`garbler`] / [`evaluator`] — per-role action execution.
//! - [`garbling`] — reusable [`GarblingSession`](garbling::GarblingSession) for
//!   circuit garbling (shared by commitment and transfer actions).
//! - [`polynomial_cache`] — bounded cache for polynomial data during setup.

use std::path::PathBuf;

pub mod evaluator;
pub mod garbler;
pub mod garbling;
pub mod polynomial_cache;

use mosaic_job_api::{
    CircuitError, CircuitSession, ExecuteEvaluatorJob, ExecuteGarblerJob, HandlerOutcome,
    OwnedChunk,
};
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::{StorageProvider, TableStore};

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

/// Placeholder circuit session — will be replaced with concrete garbling/evaluation sessions.
pub struct MosaicCircuitSession;

impl std::fmt::Debug for MosaicCircuitSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MosaicCircuitSession").finish()
    }
}

impl CircuitSession for MosaicCircuitSession {
    fn process_chunk(
        &mut self,
        _chunk: &std::sync::Arc<OwnedChunk>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn finish(self: Box<Self>) -> std::pin::Pin<Box<dyn Future<Output = HandlerOutcome> + Send>> {
        Box::pin(async { HandlerOutcome::Retry })
    }
}

impl<SP: StorageProvider, TS: TableStore> ExecuteGarblerJob for MosaicExecutor<SP, TS> {
    type Session = MosaicCircuitSession;

    fn generate_polynomial_commitments(
        &self,
        peer_id: &PeerId,
        seed: mosaic_cac_types::Seed,
        wire: mosaic_cac_types::state_machine::garbler::Wire,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_generate_polynomial_commitments(self, seed, wire)
    }

    fn generate_shares(
        &self,
        peer_id: &PeerId,
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
        chunk: &mosaic_cac_types::CommitMsgChunk,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_commit_msg_chunk(self, peer_id, chunk)
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
        chunk: &mosaic_cac_types::ChallengeResponseMsgChunk,
    ) -> impl Future<Output = HandlerOutcome> + Send {
        garbler::handle_send_challenge_response_chunk(self, peer_id, chunk)
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
        _peer_id: &PeerId,
        _index: mosaic_vs3::Index,
        _seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        async {
            Err(CircuitError::SetupFailed(
                "not yet wired to coordinator".into(),
            ))
        }
    }

    fn begin_table_transfer(
        &self,
        _peer_id: &PeerId,
        _seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        async {
            Err(CircuitError::SetupFailed(
                "not yet wired to coordinator".into(),
            ))
        }
    }
}

impl<SP: StorageProvider, TS: TableStore> ExecuteEvaluatorJob for MosaicExecutor<SP, TS> {
    type Session = MosaicCircuitSession;

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
        _peer_id: &PeerId,
        _index: mosaic_vs3::Index,
        _seed: mosaic_cac_types::GarblingSeed,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        async {
            Err(CircuitError::SetupFailed(
                "not yet wired to coordinator".into(),
            ))
        }
    }

    fn begin_table_receive(
        &self,
        _peer_id: &PeerId,
        _commitment: mosaic_cac_types::GarblingTableCommitment,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        async {
            Err(CircuitError::SetupFailed(
                "not yet wired to coordinator".into(),
            ))
        }
    }

    fn begin_evaluation(
        &self,
        _peer_id: &PeerId,
        _index: mosaic_vs3::Index,
        _commitment: mosaic_cac_types::GarblingTableCommitment,
    ) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send {
        async {
            Err(CircuitError::SetupFailed(
                "not yet wired to coordinator".into(),
            ))
        }
    }
}

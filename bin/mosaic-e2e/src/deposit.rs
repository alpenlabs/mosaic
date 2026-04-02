//! Deposit mode — initialises a deposit on a tableset.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use bitcoin::XOnlyPublicKey;
use jsonrpsee::http_client::HttpClient;
use mosaic_common::constants::{N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES};
use mosaic_net_svc::PeerId;
use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::{
    CacRole, DepositStatus, EvaluatorDepositConfig, GarblerDepositConfig, RpcDepositId,
    RpcDepositInputs, RpcInputSighashes, RpcInstanceId, RpcPeerId,
};
use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::{args::Role, config::decode_exact_hex};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Build a deterministic 32-byte deposit ID from a deposit index.
/// Bytes [0..28] are zero, bytes [28..32] are the big-endian index.
fn deposit_id_from_idx(idx: u32) -> RpcDepositId {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&idx.to_be_bytes());
    RpcDepositId::new(bytes)
}

/// Build a deterministic ChaCha20Rng seeded from the deposit ID bytes.
fn rng_from_deposit_id(deposit_id: &RpcDepositId) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(*deposit_id.inner())
}

/// Derive deterministic sighashes for deposit + withdrawal input wires.
fn derive_sighashes(deposit_id: &RpcDepositId) -> RpcInputSighashes {
    let mut rng = rng_from_deposit_id(deposit_id);
    let mut sighashes = [[0u8; 32]; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];
    for sh in &mut sighashes {
        rng.fill_bytes(sh);
    }
    RpcInputSighashes::new(sighashes)
}

/// Derive deterministic deposit input wire values.
fn derive_deposit_inputs(deposit_id: &RpcDepositId) -> RpcDepositInputs {
    // Use a different stream by advancing past the sighash draws.
    let mut rng = rng_from_deposit_id(deposit_id);
    // Skip sighash bytes worth of random.
    let skip = (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 32;
    let mut discard = vec![0u8; skip];
    rng.fill_bytes(&mut discard);

    let mut inputs = [0u8; N_DEPOSIT_INPUT_WIRES];
    rng.fill_bytes(&mut inputs);
    RpcDepositInputs::new(inputs)
}

/// Parse a hex-encoded x-only public key.
fn parse_adaptor_pk(hex: &str) -> Result<XOnlyPublicKey> {
    let bytes = decode_exact_hex::<32>(hex, "adaptor_pk")?;
    XOnlyPublicKey::from_slice(&bytes).context("adaptor_pk is not a valid x-only public key")
}

/// Parse optional hex-encoded deposit inputs override.
fn parse_deposit_inputs_override(hex: Option<&str>) -> Result<Option<RpcDepositInputs>> {
    match hex {
        Some(h) => {
            let bytes = decode_exact_hex::<N_DEPOSIT_INPUT_WIRES>(h, "deposit_inputs")?;
            Ok(Some(RpcDepositInputs::new(bytes)))
        }
        None => Ok(None),
    }
}

pub(crate) async fn run(
    client: &HttpClient,
    role: Role,
    peer_id: PeerId,
    _own_peer_id: PeerId,
    deposit_idx: u32,
    adaptor_pk_hex: Option<String>,
    deposit_inputs_hex: Option<String>,
) -> Result<()> {
    let deposit_id = deposit_id_from_idx(deposit_idx);
    let sighashes = derive_sighashes(&deposit_id);
    let deposit_inputs = parse_deposit_inputs_override(deposit_inputs_hex.as_deref())?
        .unwrap_or_else(|| derive_deposit_inputs(&deposit_id));

    // Resolve the tableset ID for this (role, peer) pair.
    let cac_role = match role {
        Role::Garbler => CacRole::Garbler,
        Role::Evaluator => CacRole::Evaluator,
    };
    let tsid = client
        .get_tableset_id(
            cac_role,
            RpcPeerId::new(peer_id.to_bytes()),
            RpcInstanceId::new([0; 32]),
        )
        .await
        .context("get_tableset_id failed")?;

    tracing::info!(%tsid, ?role, ?deposit_id, "initiating deposit");

    match role {
        Role::Garbler => {
            let adaptor_pk = parse_adaptor_pk(
                adaptor_pk_hex
                    .as_deref()
                    .context("--adaptor-pk is required for garbler role")?,
            )?;
            let config = GarblerDepositConfig {
                deposit_inputs,
                sighashes,
                adaptor_pk,
            };
            client
                .init_garbler_deposit(tsid, deposit_id, config)
                .await
                .context("init_garbler_deposit failed")?;
        }
        Role::Evaluator => {
            let config = EvaluatorDepositConfig {
                deposit_inputs,
                sighashes,
            };
            client
                .init_evaluator_deposit(tsid, deposit_id, config)
                .await
                .context("init_evaluator_deposit failed")?;
        }
    }

    loop {
        let Some(status) = client
            .get_deposit_status(tsid, deposit_id)
            .await
            .context("get_deposit_status failed")?
        else {
            tracing::debug!("deposit not found yet, polling again");
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        };

        match status {
            DepositStatus::Incomplete { details } => {
                if role == Role::Evaluator {
                    match client.evaluator_get_adaptor_pubkey(tsid, deposit_id).await {
                        Ok(Some(pk)) => {
                            tracing::info!(%pk, %details, "deposit incomplete, adaptor pubkey available");
                        }
                        Ok(None) => {
                            tracing::info!(%details, "deposit incomplete, adaptor pubkey not yet available");
                        }
                        Err(e) => {
                            tracing::info!(%details, %e, "deposit incomplete, failed to fetch adaptor pubkey");
                        }
                    }
                } else {
                    tracing::info!(%details, "deposit incomplete, polling again");
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            DepositStatus::Aborted { reason } => {
                bail!("deposit aborted: {reason}");
            }
            DepositStatus::Ready => {
                tracing::info!(%tsid, ?deposit_id, "deposit ready");
                return Ok(());
            }
            DepositStatus::UncontestedWithdrawal | DepositStatus::Consumed { .. } => {
                tracing::info!(%tsid, ?deposit_id, "deposit already consumed/withdrawn");
                return Ok(());
            }
        }
    }
}

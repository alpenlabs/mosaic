//! Setup mode — creates a tableset between two mosaic nodes.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt, stream};
use jsonrpsee::http_client::HttpClient;
use mosaic_net_svc::PeerId;
use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::{
    CacRole, RpcInstanceId, RpcPeerId, RpcPeerInfo, RpcSetupConfig, RpcSetupInputs,
    RpcTablesetStatus,
};

use crate::args::Role;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const SETUP_ALL_CONCURRENCY: usize = 4;

/// Run setup for a single (role, peer_id) pair.
pub(crate) async fn run(
    client: &HttpClient,
    role: Role,
    peer_id: PeerId,
    own_peer_id: PeerId,
    known_peer_ids: &[PeerId],
) -> Result<()> {
    if peer_id == own_peer_id {
        bail!("peer_id must not be our own peer id");
    }
    if !known_peer_ids.contains(&peer_id) {
        bail!("peer_id {peer_id:?} is not among the known peers in the config");
    }

    ensure_setup(client, role, peer_id, own_peer_id).await
}

/// Run setup for all (role, peer_id) pairs — every known peer x {garbler, evaluator}.
pub(crate) async fn run_all(
    client: &HttpClient,
    own_peer_id: PeerId,
    known_peer_ids: &[PeerId],
) -> Result<()> {
    let pairs: Vec<(Role, PeerId)> = known_peer_ids
        .iter()
        .filter(|id| **id != own_peer_id)
        .flat_map(|&id| [(Role::Garbler, id), (Role::Evaluator, id)])
        .collect();

    let total = pairs.len();
    tracing::info!(
        total,
        concurrency = SETUP_ALL_CONCURRENCY,
        "starting setup for all pairs"
    );

    stream::iter(pairs)
        .map(Ok)
        .try_for_each_concurrent(SETUP_ALL_CONCURRENCY, |(role, peer_id)| async move {
            tracing::info!(?role, ?peer_id, "starting setup");
            ensure_setup(client, role, peer_id, own_peer_id)
                .await
                .map_err(|e| {
                    tracing::error!(?role, ?peer_id, %e, "setup failed");
                    anyhow::anyhow!("setup failed for peer {peer_id:?} role {role:?}: {e}")
                })?;
            tracing::info!(?role, ?peer_id, "setup complete");
            Ok::<(), anyhow::Error>(())
        })
        .await?;

    tracing::info!("setup completed successfully for all {total} pairs");
    Ok(())
}

/// Core setup logic: initiate tableset setup and poll until complete.
async fn ensure_setup(
    client: &HttpClient,
    role: Role,
    peer_id: PeerId,
    own_peer_id: PeerId,
) -> Result<()> {
    let cac_role = match role {
        Role::Garbler => CacRole::Garbler,
        Role::Evaluator => CacRole::Evaluator,
    };

    let setup_inputs = match role {
        Role::Garbler => RpcSetupInputs::new(peer_id.to_bytes()),
        Role::Evaluator => RpcSetupInputs::new(own_peer_id.to_bytes()),
    };

    let config = RpcSetupConfig {
        role: cac_role,
        peer_info: RpcPeerInfo {
            peer_id: RpcPeerId::new(peer_id.to_bytes()),
        },
        setup_inputs,
        instance_id: RpcInstanceId::new([0; 32]),
    };

    tracing::info!(?role, ?peer_id, "calling setup_tableset");
    let tsid = client
        .setup_tableset(config)
        .await
        .context("setup_tableset failed")?;
    tracing::info!(%tsid, "tableset setup initiated, waiting for completion");

    loop {
        let Some(status) = client
            .get_tableset_status(tsid)
            .await
            .context("get_tableset_status failed")?
        else {
            tracing::debug!("state machine not found yet, polling again");
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        };

        match status {
            RpcTablesetStatus::Incomplete { details } => {
                tracing::info!(%details, "setup incomplete, polling again");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            RpcTablesetStatus::Aborted { reason } => {
                bail!("setup aborted: {reason}");
            }
            RpcTablesetStatus::SetupComplete
            | RpcTablesetStatus::Contest { .. }
            | RpcTablesetStatus::Consumed { .. } => {
                tracing::info!(%tsid, "setup complete");
                return Ok(());
            }
        }
    }
}

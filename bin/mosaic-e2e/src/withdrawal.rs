//! Withdrawal mode — exercises the contested withdrawal flow on a deposit.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use jsonrpsee::http_client::HttpClient;
use mosaic_common::constants::{N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES};
use mosaic_net_svc::PeerId;
use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::{
    CacRole, EvaluatorWithdrawalConfig, RpcByte32, RpcDepositId, RpcInstanceId, RpcPeerId,
    RpcTablesetId, RpcTablesetStatus, RpcWithdrawalInputs,
};
use rand::RngCore;
use crate::args::Role;
use crate::config::decode_exact_hex;
use crate::deposit;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Derive deterministic withdrawal input wire values from a deposit ID.
/// Continues the RNG stream past sighashes and deposit inputs.
fn derive_withdrawal_inputs(deposit_id: &RpcDepositId) -> RpcWithdrawalInputs {
    let mut rng = deposit::rng_from_deposit_id(deposit_id);
    // Skip sighash bytes.
    let skip_sighashes = (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 32;
    let mut discard = vec![0u8; skip_sighashes];
    rng.fill_bytes(&mut discard);
    // Skip deposit input bytes.
    let mut discard2 = [0u8; N_DEPOSIT_INPUT_WIRES];
    rng.fill_bytes(&mut discard2);
    // Now read withdrawal inputs.
    let mut inputs = [0u8; N_WITHDRAWAL_INPUT_WIRES];
    rng.fill_bytes(&mut inputs);
    RpcWithdrawalInputs::new(inputs)
}

/// Parse optional hex-encoded withdrawal inputs override.
fn parse_withdrawal_inputs_override(hex: Option<&str>) -> Result<Option<RpcWithdrawalInputs>> {
    match hex {
        Some(h) => {
            let bytes = decode_exact_hex::<N_WITHDRAWAL_INPUT_WIRES>(h, "withdrawal_inputs")?;
            Ok(Some(RpcWithdrawalInputs::new(bytes)))
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
    withdrawal_inputs_hex: Option<String>,
    sigs_file: Option<String>,
) -> Result<()> {
    let deposit_id = deposit::deposit_id_from_idx(deposit_idx);

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

    tracing::info!(%tsid, ?role, ?deposit_id, "initiating withdrawal");

    match role {
        Role::Garbler => run_garbler(client, tsid, deposit_id, withdrawal_inputs_hex).await,
        Role::Evaluator => run_evaluator(client, tsid, deposit_id, sigs_file).await,
    }
}

async fn run_garbler(
    client: &HttpClient,
    tsid: RpcTablesetId,
    deposit_id: RpcDepositId,
    withdrawal_inputs_hex: Option<String>,
) -> Result<()> {
    let withdrawal_inputs = parse_withdrawal_inputs_override(withdrawal_inputs_hex.as_deref())?
        .unwrap_or_else(|| derive_withdrawal_inputs(&deposit_id));

    tracing::info!(%tsid, "calling complete_adaptor_sigs");
    client
        .complete_adaptor_sigs(tsid, deposit_id, withdrawal_inputs)
        .await
        .context("complete_adaptor_sigs failed")?;

    poll_until_consumed(client, tsid, &deposit_id).await?;

    tracing::info!(%tsid, "fetching completed adaptor signatures");
    let completed_sigs = client
        .get_completed_adaptor_sigs(tsid)
        .await
        .context("get_completed_adaptor_sigs failed")?;

    let config = EvaluatorWithdrawalConfig {
        withdrawal_inputs,
        completed_signatures: completed_sigs,
    };

    let json =
        serde_json::to_string_pretty(&config).context("failed to serialize withdrawal config")?;

    let filename = format!(
        "mosaic-e2e-withdrawal-{:016x}.json",
        rand::random::<u64>()
    );
    let path = std::env::temp_dir().join(&filename);

    std::fs::write(&path, json.as_bytes())
        .with_context(|| format!("failed to write sigs file to {}", path.display()))?;

    tracing::info!(path = %path.display(), "wrote evaluator withdrawal config");
    println!("{}", path.display());

    Ok(())
}

async fn run_evaluator(
    client: &HttpClient,
    tsid: RpcTablesetId,
    deposit_id: RpcDepositId,
    sigs_file: Option<String>,
) -> Result<()> {
    let sigs_path = sigs_file.context("--sigs-file is required for evaluator role")?;
    let raw = std::fs::read_to_string(&sigs_path)
        .with_context(|| format!("failed to read sigs file: {sigs_path}"))?;
    let config: EvaluatorWithdrawalConfig =
        serde_json::from_str(&raw).context("failed to deserialize withdrawal config")?;

    tracing::info!(%tsid, "calling evaluate_tableset");
    client
        .evaluate_tableset(tsid, deposit_id, config)
        .await
        .context("evaluate_tableset failed")?;

    poll_until_consumed(client, tsid, &deposit_id).await?;

    tracing::info!(%tsid, "calling sign_with_fault_secret");
    let signature = client
        .sign_with_fault_secret(tsid, RpcByte32::new([0u8; 32]), None)
        .await
        .context("sign_with_fault_secret failed")?;

    match signature {
        Some(sig) => {
            tracing::info!(%tsid, ?sig, "fault secret signature obtained");
        }
        None => {
            bail!("sign_with_fault_secret returned None");
        }
    }

    Ok(())
}

async fn poll_until_consumed(
    client: &HttpClient,
    tsid: RpcTablesetId,
    expected_deposit_id: &RpcDepositId,
) -> Result<()> {
    loop {
        let Some(status) = client
            .get_tableset_status(tsid)
            .await
            .context("get_tableset_status failed")?
        else {
            tracing::debug!(%tsid, "tableset not found yet, polling again");
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        };

        match status {
            RpcTablesetStatus::Incomplete { details } => {
                tracing::info!(%tsid, %details, "tableset incomplete, polling again");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            RpcTablesetStatus::Contest { deposit } => {
                if deposit != *expected_deposit_id {
                    bail!(
                        "tableset {tsid} in contest for unexpected deposit {deposit:?}, expected {expected_deposit_id:?}"
                    );
                }
                tracing::info!(%tsid, "tableset in contest state, polling again");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            RpcTablesetStatus::Consumed { deposit, success } => {
                if deposit != *expected_deposit_id {
                    bail!(
                        "tableset {tsid} consumed by unexpected deposit {deposit:?}, expected {expected_deposit_id:?}"
                    );
                }
                if !success {
                    bail!("tableset {tsid} consumed but success=false");
                }
                tracing::info!(%tsid, "tableset consumed successfully");
                return Ok(());
            }
            RpcTablesetStatus::SetupComplete => {
                tracing::info!(%tsid, "tableset still in SetupComplete, polling again");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            RpcTablesetStatus::Aborted { reason } => {
                bail!("tableset {tsid} aborted: {reason}");
            }
        }
    }
}

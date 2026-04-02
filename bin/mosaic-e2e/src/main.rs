//! End-to-end test runner for a Mosaic instance.
//!
//! Connects to a running Mosaic node via JSON-RPC and exercises the API.
//! Intended for pre-integration smoke tests.
//!
//! Usage: `mosaic-e2e -c <config.toml> <setup|deposit|withdrawal> [args...]`

mod args;
mod config;
mod deposit;
mod setup;
mod withdrawal;

use anyhow::{Context, Result};
use args::Command;
use jsonrpsee::http_client::HttpClientBuilder;
use mosaic_rpc_api::MosaicRpcClient;

#[tokio::main]
async fn main() -> Result<()> {
    let args = args::Args::from_cli()?;
    init_tracing(&args.config.logging.filter)?;

    let rpc_url = args.config.rpc.url();
    tracing::info!(%rpc_url, "starting e2e runner");

    let client = HttpClientBuilder::default()
        .build(&rpc_url)
        .context("failed to build RPC client")?;

    // Basic connectivity check.
    let rpc_peer_id = client.get_peer_id().await.context("get_peer_id failed")?;
    let own_peer_id = mosaic_net_svc::PeerId::from_bytes(*rpc_peer_id.inner());
    tracing::info!(?own_peer_id, "connected to mosaic node");

    let known_peer_ids = args.config.peer_ids()?;

    match args.command {
        Command::Setup {
            role,
            peer_id,
            setup_inputs,
        } => {
            let peer_id = config::decode_peer_id(&peer_id)?;
            let setup_inputs = setup::parse_setup_inputs_override(setup_inputs.as_deref())?;
            setup::run(
                &client,
                role,
                peer_id,
                own_peer_id,
                &known_peer_ids,
                setup_inputs,
            )
            .await?;
        }
        Command::SetupAll { setup_inputs } => {
            let setup_inputs = setup::parse_setup_inputs_override(setup_inputs.as_deref())?;
            setup::run_all(&client, own_peer_id, &known_peer_ids, setup_inputs).await?;
        }
        Command::Deposit {
            role,
            peer_id,
            deposit_idx,
            adaptor_pk,
            deposit_inputs,
        } => {
            let peer_id = config::decode_peer_id(&peer_id)?;
            deposit::run(
                &client,
                role,
                peer_id,
                own_peer_id,
                deposit_idx,
                adaptor_pk,
                deposit_inputs,
            )
            .await?;
        }
        Command::Withdrawal {
            role,
            peer_id,
            deposit_idx,
            withdrawal_inputs,
            sigs_file,
        } => {
            let peer_id = config::decode_peer_id(&peer_id)?;
            withdrawal::run(
                &client,
                role,
                peer_id,
                own_peer_id,
                deposit_idx,
                withdrawal_inputs,
                sigs_file,
            )
            .await?;
        }
    }

    tracing::info!("e2e run complete");
    Ok(())
}

fn init_tracing(filter: &str) -> Result<()> {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let env_filter =
        EnvFilter::try_new(filter).with_context(|| format!("invalid logging filter `{filter}`"))?;
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true))
        .try_init()
        .context("failed to initialize tracing subscriber")
}

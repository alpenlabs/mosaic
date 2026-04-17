//! Mosaic binary composition root.

mod config;
mod rpc;

use std::{
    env,
    path::PathBuf,
    sync::{Arc, mpsc},
};

use anyhow::{Context, Result, bail};
use config::{MosaicConfig, TableStoreBackend};
use mimalloc::MiMalloc;
use mosaic_cac_types::state_machine::{evaluator, garbler};
// dependency to pass feature flag
use mosaic_common as _;
use mosaic_job_executors::MosaicExecutor;
use mosaic_job_scheduler::JobScheduler;
use mosaic_net_client::NetClient;
use mosaic_net_svc::{NetService, PeerId};
use mosaic_sm_executor::{SmExecutor, SmExecutorController};
use mosaic_sm_executor_api::SmExecutorHandle;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut, TableStore};
use mosaic_storage_fdb::FdbStorageProvider;
use mosaic_storage_s3::S3TableStore;
use object_store::{ObjectStore, aws::AmazonS3Builder, local::LocalFileSystem};
use rand::SeedableRng as _;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[global_allocator]
static GLOBAL_ALLOCATOR: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let config_path = config_path_from_args()?;
    let config = MosaicConfig::from_file(&config_path)?;
    init_tracing(&config.logging.filter)?;
    config.validate()?;

    let _fdb_network = unsafe { foundationdb::boot() };
    let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .build()
        .context("failed to build mosaic monoio runtime")?;
    let running = runtime.block_on(startup(config))?;

    wait_for_shutdown_signal()?;
    shutdown(running)
}

struct RunningMosaic {
    net_controller: mosaic_net_svc::NetServiceController,
    job_scheduler_controller: mosaic_job_scheduler::JobSchedulerController,
    sm_executor_controller: SmExecutorController,
    _sm_executor_handle: SmExecutorHandle,
    rpc_controller: rpc::RpcController,
}

async fn startup(config: MosaicConfig) -> Result<RunningMosaic> {
    let net_service_config = config.build_net_service_config()?;
    let our_peer_id = net_service_config.our_peer_id();
    let known_peers = config.known_peers()?;
    ensure_peer_set_is_sound(our_peer_id, &known_peers)?;

    tracing::info!(
        peer_id = ?our_peer_id,
        peers = known_peers.len(),
        circuit_path = %config.circuit.path.display(),
        "starting mosaic binary"
    );

    let (net_handle, net_controller) =
        NetService::new(net_service_config).context("failed to start net service")?;
    let net_client = NetClient::with_config(net_handle, config.build_net_client_config());

    let db = match &config.storage.cluster_file {
        Some(cluster_file) => foundationdb::Database::from_path(
            cluster_file
                .to_str()
                .context("foundationdb cluster_file must be valid utf-8")?,
        )
        .with_context(|| {
            format!(
                "failed to open foundationdb database from cluster file {}",
                cluster_file.display()
            )
        })?,
        None => foundationdb::Database::default()
            .context("failed to open foundationdb default database")?,
    };
    let storage = FdbStorageProvider::open(db, config.build_fdb_storage_config())
        .await
        .context("failed to initialize foundationdb storage provider")?;

    run_with_state_storage(config, storage, net_client, net_controller).await
}

async fn run_with_state_storage<S>(
    config: MosaicConfig,
    storage: S,
    net_client: NetClient,
    net_controller: mosaic_net_svc::NetServiceController,
) -> Result<RunningMosaic>
where
    S: StorageProvider + StorageProviderMut + Clone + Send + Sync + 'static,
    <S as StorageProviderMut>::GarblerState: garbler::StateMut + Commit,
    <S as StorageProviderMut>::EvaluatorState: evaluator::StateMut + Commit,
    <<S as StorageProviderMut>::GarblerState as Commit>::Error: std::fmt::Debug + Send + 'static,
    <<S as StorageProviderMut>::EvaluatorState as Commit>::Error: std::fmt::Debug + Send + 'static,
{
    match &config.table_store.backend {
        TableStoreBackend::LocalFilesystem { root, prefix } => {
            std::fs::create_dir_all(root).with_context(|| {
                format!("failed to create local table-store root {}", root.display())
            })?;
            let local = LocalFileSystem::new_with_prefix(root).with_context(|| {
                format!(
                    "failed to initialize local table-store root {}",
                    root.display()
                )
            })?;
            let store = S3TableStore::new(Arc::new(local) as Arc<dyn ObjectStore>, prefix);
            run_with_components(config, storage, store, net_client, net_controller).await
        }
        TableStoreBackend::S3Compatible {
            bucket,
            region,
            prefix,
            access_key_id,
            secret_access_key,
            endpoint,
            session_token,
            allow_http,
            virtual_hosted_style_request,
        } => {
            let mut builder = AmazonS3Builder::new()
                .with_bucket_name(bucket)
                .with_region(region)
                .with_access_key_id(access_key_id)
                .with_secret_access_key(secret_access_key)
                .with_allow_http(*allow_http)
                .with_virtual_hosted_style_request(*virtual_hosted_style_request)
                // Disable the default 30-second request timeout. Ciphertext
                // objects are tens of GB and streamed over long-lived HTTP
                // connections. The S3TableReader handles connection drops
                // internally via resume-from-offset.
                .with_client_options(object_store::ClientOptions::new().with_timeout_disabled());

            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint);
            }

            if let Some(session_token) = session_token {
                builder = builder.with_token(session_token);
            }

            let s3 = builder
                .build()
                .context("failed to initialize s3-compatible table store")?;
            let store = S3TableStore::new(Arc::new(s3) as Arc<dyn ObjectStore>, prefix);
            run_with_components(config, storage, store, net_client, net_controller).await
        }
    }
}

async fn run_with_components<S, TS>(
    config: MosaicConfig,
    storage: S,
    table_store: TS,
    net_client: NetClient,
    net_controller: mosaic_net_svc::NetServiceController,
) -> Result<RunningMosaic>
where
    S: StorageProvider + StorageProviderMut + Clone + Send + Sync + 'static,
    <S as StorageProviderMut>::GarblerState: garbler::StateMut + Commit,
    <S as StorageProviderMut>::EvaluatorState: evaluator::StateMut + Commit,
    <<S as StorageProviderMut>::GarblerState as Commit>::Error: std::fmt::Debug + Send + 'static,
    <<S as StorageProviderMut>::EvaluatorState as Commit>::Error: std::fmt::Debug + Send + 'static,
    TS: TableStore + Send + Sync + 'static,
{
    let job_executor = MosaicExecutor::new(
        net_client.clone(),
        storage.clone(),
        table_store,
        config.circuit.path.clone(),
    );
    let (job_scheduler, job_handle) =
        JobScheduler::new(config.build_job_scheduler_config(), job_executor);
    let job_scheduler_controller = job_scheduler.run();

    let (sm_executor, sm_executor_handle) = SmExecutor::new(
        config.build_sm_executor_config(config.known_peers()?),
        storage.clone(),
        job_handle,
        net_client,
    );
    let sm_executor_controller = sm_executor
        .spawn()
        .context("failed to spawn sm executor thread")?;

    let rpc_bind_addr = config.rpc_bind_addr()?;
    let our_peer_id = config.build_net_service_config()?.our_peer_id();
    let other_peer_ids = config.known_peers()?;
    let rng = rand_chacha::ChaCha20Rng::from_entropy();

    let mosaic_api = mosaic_rpc_service::DefaultMosaicApi::new(
        our_peer_id,
        other_peer_ids,
        sm_executor_handle.clone(),
        storage,
        rng,
    );
    let rpc_controller =
        rpc::start_rpc_server(rpc_bind_addr, mosaic_api).context("failed to start RPC server")?;

    tracing::info!("all currently supported components started");
    Ok(RunningMosaic {
        net_controller,
        job_scheduler_controller,
        sm_executor_controller,
        _sm_executor_handle: sm_executor_handle,
        rpc_controller,
    })
}

fn shutdown(running: RunningMosaic) -> Result<()> {
    running
        .rpc_controller
        .shutdown()
        .context("failed to shut down RPC server")?;
    shutdown_net(running.net_controller)?;
    shutdown_sm_executor(running.sm_executor_controller)?;
    shutdown_job_scheduler(running.job_scheduler_controller)?;
    tracing::info!("mosaic shutdown complete");
    Ok(())
}

fn wait_for_shutdown_signal() -> Result<()> {
    let (tx, rx) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("failed to install shutdown signal handler")?;
    rx.recv()
        .context("failed while waiting for shutdown signal")?;
    tracing::info!("shutdown signal received");
    Ok(())
}

fn shutdown_net(controller: mosaic_net_svc::NetServiceController) -> Result<()> {
    controller
        .shutdown()
        .context("failed to shut down net service")
}

fn shutdown_sm_executor(controller: SmExecutorController) -> Result<()> {
    controller
        .shutdown()
        .context("failed to shut down sm executor")
}

fn shutdown_job_scheduler(controller: mosaic_job_scheduler::JobSchedulerController) -> Result<()> {
    controller
        .shutdown()
        .context("failed to shut down job scheduler")
}

fn config_path_from_args() -> Result<PathBuf> {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(path) = args.next() else {
        bail!("usage: mosaic <config.toml>");
    };
    if args.next().is_some() {
        bail!("usage: mosaic <config.toml>");
    }
    Ok(PathBuf::from(path))
}

fn init_tracing(filter: &str) -> Result<()> {
    let env_filter = EnvFilter::try_new(filter)
        .with_context(|| format!("invalid logging.filter directive `{filter}`"))?;
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true))
        .try_init()
        .context("failed to initialize tracing subscriber")
}

fn ensure_peer_set_is_sound(our_peer_id: PeerId, peers: &[PeerId]) -> Result<()> {
    if peers.contains(&our_peer_id) {
        bail!("network.peers must not include our own peer id");
    }

    let mut unique = std::collections::BTreeSet::new();
    for peer_id in peers {
        if !unique.insert(peer_id.to_bytes()) {
            bail!("network.peers contains duplicate peer id {peer_id:?}");
        }
    }
    Ok(())
}

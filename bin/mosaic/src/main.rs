//! Mosaic binary composition root.

mod config;

use std::{
    env,
    path::PathBuf,
    sync::{Arc, mpsc},
};

use anyhow::{Context, Result, bail};
use config::{MosaicConfig, TableStoreBackend};
use mimalloc::MiMalloc;
use mosaic_cac_types::state_machine::{evaluator, garbler};
use mosaic_job_executors::MosaicExecutor;
use mosaic_job_scheduler::JobScheduler;
use mosaic_net_client::NetClient;
use mosaic_net_svc::{NetService, PeerId};
use mosaic_sm_executor::{SmExecutor, SmExecutorController};
use mosaic_sm_executor_api::SmExecutorHandle;
use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut, TableStore};
// use mosaic_storage_fdb::FdbStorageProvider;
use mosaic_storage_kvstore::btreemap::{self, BTreeMapStorageProvider};
use mosaic_storage_s3::S3TableStore;
use object_store::{ObjectStore, aws::AmazonS3Builder, local::LocalFileSystem};
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
    let running: RunningMosaic<_> = runtime.block_on(startup(config))?;

    wait_for_shutdown_signal()?;
    shutdown(running)
}

struct RunningMosaic<S: StorageProvider> {
    net_controller: mosaic_net_svc::NetServiceController,
    job_scheduler_controller: mosaic_job_scheduler::JobSchedulerController,
    sm_executor_controller: SmExecutorController,
    _sm_executor_handle: SmExecutorHandle,
    storage: S, // used for test only
}

async fn startup(config: MosaicConfig) -> Result<RunningMosaic<BTreeMapStorageProvider>> {
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
    // let storage = FdbStorageProvider::open(db, config.build_fdb_storage_config())
    //     .await
    //     .context("failed to initialize foundationdb storage provider")?;

    let storage = btreemap::BTreeMapStorageProvider::new();
    run_with_state_storage(config, storage, net_client, net_controller).await
}

async fn run_with_state_storage<S>(
    config: MosaicConfig,
    storage: S,
    net_client: NetClient,
    net_controller: mosaic_net_svc::NetServiceController,
) -> Result<RunningMosaic<S>>
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
                .with_virtual_hosted_style_request(*virtual_hosted_style_request);

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
) -> Result<RunningMosaic<S>>
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

    tracing::info!("all currently supported components started");
    Ok(RunningMosaic {
        net_controller,
        job_scheduler_controller,
        sm_executor_controller,
        _sm_executor_handle: sm_executor_handle,
        storage,
    })
}

fn shutdown<S: StorageProvider>(running: RunningMosaic<S>) -> Result<()> {
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

#[cfg(test)]
mod test {

    use std::time::Duration;

    use mosaic_cac_types::{
        DepositId, DepositInputs, HeapArray, PubKey, SecretKey, Sighash, Signature,
        WithdrawalInputs,
        state_machine::{
            evaluator::{
                EvaluatorDepositInitData, EvaluatorDisputedWithdrawalData, EvaluatorInitData,
            },
            garbler::{GarblerDepositInitData, GarblerInitData, StateRead},
        },
    };
    use mosaic_common::{
        Byte32,
        constants::{N_DEPOSIT_INPUT_WIRES, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES},
    };
    use mosaic_sm_executor_api::SmCommand;
    use mosaic_storage_kvstore::btreemap::BTreeMapStorageProvider;
    use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

    use super::*;

    fn rand_byte_array<const N: usize, R: rand_chacha::rand_core::RngCore>(rng: &mut R) -> [u8; N] {
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    async fn mock_main() -> Result<()> {
        let (garb_running, garb_peer) = {
            let config_path = PathBuf::from(
                "/Users/manishbista/Documents/alpenlabs/mosaic/bin/mosaic/config/config.a.toml",
            );
            let config = MosaicConfig::from_file(&config_path)?;
            init_tracing(&config.logging.filter)?;
            config.validate()?;

            let _fdb_network = unsafe { foundationdb::boot() };
            let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .context("failed to build mosaic monoio runtime")?;
            let running: RunningMosaic<BTreeMapStorageProvider> =
                runtime.block_on(startup(config.clone()))?;
            let peer_id = config.known_peers().unwrap()[0];
            (running, peer_id)
        };

        tokio::time::sleep(Duration::from_secs(5)).await;

        let (eval_running, eval_peer) = {
            let config_path = PathBuf::from(
                "/Users/manishbista/Documents/alpenlabs/mosaic/bin/mosaic/config/config.b.toml",
            );
            let config = MosaicConfig::from_file(&config_path)?;
            //init_tracing(&config.logging.filter)?;
            config.validate()?;

            // let _fdb_network = unsafe { foundationdb::boot() };
            let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .context("failed to build mosaic monoio runtime")?;
            let running: RunningMosaic<BTreeMapStorageProvider> =
                runtime.block_on(startup(config.clone()))?;
            let peer_id = config.known_peers().unwrap()[0];
            (running, peer_id)
        };

        tokio::time::sleep(Duration::from_secs(5)).await;
        // Eval init
        {
            let setup_inputs = [0; N_SETUP_INPUT_WIRES];
            let mut eval_rng = ChaChaRng::seed_from_u64(43);
            let eval_seed = rand_byte_array(&mut eval_rng).into();

            let eval_init_data: EvaluatorInitData = EvaluatorInitData {
                seed: eval_seed,
                setup_inputs,
            };
            let init_eval_command = SmCommand::init_evaluator(eval_peer, eval_init_data);
            eval_running
                ._sm_executor_handle
                .send(init_eval_command)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        {
            let setup_inputs = [0; N_SETUP_INPUT_WIRES];
            let mut garb_rng = ChaChaRng::seed_from_u64(42);
            let garb_seed = rand_byte_array(&mut garb_rng).into();

            let garb_init_data: GarblerInitData = GarblerInitData {
                seed: garb_seed,
                setup_inputs,
            };
            let init_garb_command = SmCommand::init_garbler(garb_peer, garb_init_data);

            garb_running
                ._sm_executor_handle
                .send(init_garb_command)
                .await
                .unwrap();
        }

        let deposit_id = {
            let mut empty: [u8; 32] = [0; 32];
            empty[0] = 7;
            DepositId(Byte32::from(empty))
        };
        let mut eval_rng = ChaChaRng::seed_from_u64(45);
        let eval_keypair = Signature::keypair(&mut eval_rng);
        let sighashes =
            [Sighash(Byte32::from([0u8; 32])); N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];
        let deposit_inputs: DepositInputs = [0; N_DEPOSIT_INPUT_WIRES];

        // Wait till garbler and evaluator are in SetupComplete
        tokio::time::sleep(Duration::from_secs(30)).await;
        println!("++++++++DEPOSIT STAGE++++++++++");

        {
            let garb_deposit_data: GarblerDepositInitData = GarblerDepositInitData {
                pk: PubKey(eval_keypair.1),
                sighashes: HeapArray::from_vec(sighashes.to_vec()),
                deposit_inputs,
            };
            let init_garb_deposit_command =
                SmCommand::deposit_init_garbler(garb_peer, deposit_id, garb_deposit_data);

            garb_running
                ._sm_executor_handle
                .send(init_garb_deposit_command)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_secs(5)).await;

        {
            let eval_deposit_data: EvaluatorDepositInitData = EvaluatorDepositInitData {
                sk: SecretKey(eval_keypair.0),
                sighashes: HeapArray::from_vec(sighashes.to_vec()),
                deposit_inputs,
            };
            let init_eval_deposit_command =
                SmCommand::deposit_init_evaluator(eval_peer, deposit_id, eval_deposit_data);

            eval_running
                ._sm_executor_handle
                .send(init_eval_deposit_command)
                .await
                .unwrap();
        }

        // Wait till garbler and evaluator are in DepositReady
        tokio::time::sleep(Duration::from_secs(10)).await;
        println!("++++++++WITHDRAWAL STAGE++++++++++");

        {
            let withdrawal_inputs: WithdrawalInputs = [0; N_WITHDRAWAL_INPUT_WIRES];
            let withdrawal_command =
                SmCommand::disputed_withdrawal_garbler(garb_peer, deposit_id, withdrawal_inputs);

            garb_running
                ._sm_executor_handle
                .send(withdrawal_command)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_secs(10)).await;

        {
            let completed_sigs = garb_running
                .storage
                .garbler_state(&garb_peer)
                .await
                .unwrap()
                .get_completed_signatures(&deposit_id)
                .await
                .unwrap();
            let data = EvaluatorDisputedWithdrawalData {
                signatures: completed_sigs,
            };
            let withdrawal_command =
                SmCommand::disputed_withdrawal_evaluator(eval_peer, deposit_id, data);

            eval_running
                ._sm_executor_handle
                .send(withdrawal_command)
                .await
                .unwrap();
        }

        wait_for_shutdown_signal()?;
        let r = shutdown(garb_running);
        let _ = shutdown(eval_running);
        r
    }

    #[tokio::test]
    async fn test_binary() {
        mock_main().await.unwrap();
    }
}

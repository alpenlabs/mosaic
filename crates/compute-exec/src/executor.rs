//! Resumable computation executor worker.

use std::{
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time,
};

use bytes::Bytes;
use mosaic_compute_fw::{Computation, ComputeSnapshotProvider, Snapshot, StepResult};
use strata_codec::Codec;
use tracing::*;

use crate::config::ExecutorConfig;

#[derive(Debug)]
struct SharedState {
    // TODO
}

impl SharedState {
    fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

/// Builder for an executor.
#[derive(Debug)]
pub struct ExecutorBuilder<C: Computation> {
    config: ExecutorConfig,
    comp_state: Option<C>,
    step_idx: u64,
}

impl<C: Computation> ExecutorBuilder<C> {
    /// Constructs a new builder from a config.
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            comp_state: None,
            step_idx: 0,
        }
    }

    /// Uses an input to construct the computation's initial state.
    pub fn with_input(mut self, input: C::Input) -> anyhow::Result<Self> {
        self.comp_state = Some(C::start(input)?);
        Ok(self)
    }

    /// Uses a snapshot to construct the task's initial state.
    pub fn with_snapshot(mut self, snapshot: &Snapshot) -> anyhow::Result<Self> {
        if snapshot.exited() {
            return Err(anyhow::anyhow!(
                "tried to resume from exited state snapshot"
            ));
        }

        let ssd = decode_from_buf::<C>(snapshot.data())?;
        self.comp_state = Some(ssd);
        self.step_idx = snapshot.step_idx();

        Ok(self)
    }

    /// Launches a worker thread to manage the computation and returns a handle.
    pub fn launch(mut self, prov: impl ComputeSnapshotProvider) -> ExecutorHandle {
        let comp_state = self
            .comp_state
            .take()
            .expect("executor: missing initial state");

        let shared = SharedState::new();

        // Construct the executor's state.
        let mut exec_state = ExecutorState {
            comp_state,
            computation_done: false,
            step_idx: self.step_idx,
            config: self.config,
            last_snapshot: time::Instant::now(),
            shared: shared.clone(),
        };

        // Spawn the computation executor thread.
        // TODO convert to use the task manager system
        let handle = thread::spawn(move || {
            let comp_name = exec_state.computation_name();
            info!(%comp_name, "starting computation executor task");

            if let Err(err) = executor_task(&mut exec_state, &prov) {
                let comp_name = exec_state.computation_name();
                error!(%comp_name, ?err, "executor task failed");
            }
        });

        ExecutorHandle {
            handle: Mutex::new(Some(handle)),
            shared,
        }
    }
}

/// Handle for an executor thread.
#[derive(Debug)]
pub struct ExecutorHandle {
    handle: Mutex<Option<JoinHandle<()>>>,

    #[allow(unused, reason = "future use")]
    shared: Arc<SharedState>,
}

impl ExecutorHandle {
    /// Waits for the computation to exit.
    pub fn wait(&self) -> anyhow::Result<()> {
        let mut handle = self
            .handle
            .lock()
            .map_err(|_| anyhow::anyhow!("join mutex poisoned"))?;

        if let Some(h) = handle.take() {
            if let Err(_e) = h.join() {
                warn!("executor exited abnormally");
            }
        } else {
            warn!("executor already waited on");
        }

        Ok(())
    }

    // TODO async wait?
}

/// State for a running executor.
struct ExecutorState<C: Computation> {
    comp_state: C,
    computation_done: bool,
    step_idx: u64,
    config: ExecutorConfig,
    last_snapshot: time::Instant,

    #[allow(unused, reason = "future use")]
    shared: Arc<SharedState>,
}

impl<C: Computation> ExecutorState<C> {
    fn computation_name(&self) -> &str {
        self.comp_state.name()
    }

    /// Exports the computation state as an encoded snapshot.
    fn export_snapshot(&self) -> anyhow::Result<Snapshot> {
        let export = self.comp_state.export();
        let ssd = encode_to_bytes(&export)?;
        Ok(Snapshot::new(self.step_idx, self.computation_done, ssd))
    }

    /// Checks if we should generate a snapshot as of now.
    fn should_snapshot(&self) -> bool {
        let now = time::Instant::now();
        now > self.last_snapshot + self.config.snapshot_period()
    }

    /// Updates the timestamp of the last snapshot.
    fn update_snapshot_ts(&mut self) {
        self.last_snapshot = time::Instant::now();
    }

    /// Executes a single step and returns the step result.
    #[tracing::instrument(skip_all)]
    fn execute_step(&mut self) -> anyhow::Result<StepResult> {
        if self.computation_done {
            let computation_name = self.computation_name();
            let step_idx = self.step_idx + 1;
            debug!(%computation_name, %step_idx, "executing step");

            let res = self.comp_state.execute_step()?;

            // Update flags.
            if res.did_change_state() {
                self.step_idx += 1;
            }

            if !res.should_execute_next() {
                self.computation_done = true;
            }

            Ok(res)
        } else {
            Err(anyhow::anyhow!(
                "tried to execute computation that was done"
            ))
        }
    }
}

fn executor_task<C: Computation>(
    exec_state: &mut ExecutorState<C>,
    prov: &impl ComputeSnapshotProvider,
) -> anyhow::Result<()> {
    loop {
        let res = handle_exec_single_step(exec_state, prov);

        // Handle error/weird cases.
        match res {
            Ok(StepResult::Failed) => {
                // not sure what to do here
                // TODO expose and save failure data
                error!("computation failed!");
                break;
            }

            Ok(StepResult::AlreadyExited) => {
                warn!("tried to execute computation step but computation already exited");
                return Ok(());
            }

            Err(err) => {
                // TODO do retry with periodic backoff
                error!(%err, "error executing worker step, exiting prematurely, restart to resume");
                return Ok(());
            }

            _ => {}
        }

        if exec_state.computation_done {
            break;
        }
    }

    // Save the final state so we remember it and won't try to reexecute the
    // last step if we crash right now.
    prov.save_snapshot(exec_state.export_snapshot()?)?;

    Ok(())
}

/// Executes a single step and possibly exports the snapshot state.
#[tracing::instrument(skip_all)]
fn handle_exec_single_step<C: Computation>(
    state: &mut ExecutorState<C>,
    prov: &impl ComputeSnapshotProvider,
) -> anyhow::Result<StepResult> {
    let res = state.execute_step()?;

    if state.should_snapshot() {
        debug!("generating snapshot");
        prov.save_snapshot(state.export_snapshot()?)?;
        state.update_snapshot_ts();
    }

    Ok(res)
}

fn encode_to_bytes<T: Codec>(v: &T) -> anyhow::Result<Bytes> {
    let buf = strata_codec::encode_to_vec(v)?;
    Ok(Bytes::from_owner(buf))
}

fn decode_from_buf<T: Codec>(v: &[u8]) -> anyhow::Result<T> {
    Ok(strata_codec::decode_buf_exact(v)?)
}

//! Resumable computation executor worker.

use std::time;

use mosaic_compute_fw::{Computation, ComputeSnapshotProvider, StepResult};

use bytes::{Bytes, BytesMut};
use strata_codec::Codec;

use crate::config::ExecutorConfig;

struct ExecutorState {
    config: ExecutorConfig,
    last_snapshot: time::Instant,
}

impl ExecutorState {
    /// Checks if we should generate a snapshot as of now.
    fn should_snapshot(&self) -> bool {
        let now = time::Instant::now();
        now > self.last_snapshot + self.config.snapshot_period()
    }

    fn update_snapshot_ts(&mut self) {
        self.last_snapshot = time::Instant::now();
    }
}

fn execute_computation<'r, P: Computation<'r>, S: ComputeSnapshotProvider>() -> anyhow::Result<()> {
    // TODO
    Ok(())
}

fn execute_step<'r, P: Computation<'r>>(
    comp: &mut P,
    estate: &mut ExecutorState,
) -> anyhow::Result<StepResult> {
    let res = comp.execute_step()?;

    if estate.should_snapshot() {
        let ss = comp.export();
        // TODO export ss somehow, try to serialize in other thread?

        estate.update_snapshot_ts();
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

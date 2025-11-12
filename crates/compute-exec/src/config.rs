use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    /// Rule for when we produce snapshots.
    ///
    /// After performing a step, if the last snapshot was at least this long
    /// ago, we produce a new one.
    snapshot_period: Duration,
}

impl ExecutorConfig {
    pub fn new(snapshot_period: Duration) -> Self {
        Self { snapshot_period }
    }

    pub fn snapshot_period(&self) -> Duration {
        self.snapshot_period
    }
}

//! Job manager implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use mosaic_db_types::{JobExecState, JobId, JobRecord, JobStore, SnapshotStore};
use threadpool::ThreadPool;
use tracing::{debug, error, info, warn};

use crate::error::{JobError, JobResult};
use crate::job::{DynJob, Job, JobContext};

/// Configuration for the job manager.
#[derive(Debug, Clone)]
pub struct JobManagerConfig {
    /// Number of worker threads in the pool.
    pub num_workers: usize,
    /// How often to save snapshots (in steps).
    pub snapshot_interval: u64,
}

impl Default for JobManagerConfig {
    fn default() -> Self {
        Self {
            num_workers: 4,
            snapshot_interval: 10,
        }
    }
}

/// Handle to a running job for status tracking and cancellation.
struct RunningJob {
    /// Signaled when the job completes or fails.
    completed: Arc<(Mutex<bool>, Condvar)>,
    /// Set to true to request cancellation.
    cancel_requested: Arc<AtomicBool>,
}

/// Manages job lifecycle, execution, and crash recovery.
///
/// The job manager maintains a thread pool for executing jobs concurrently,
/// persists job state and snapshots to the database, and supports recovering
/// interrupted jobs after a crash.
pub struct JobManager<DB> {
    db: Arc<DB>,
    config: JobManagerConfig,
    pool: ThreadPool,
    running_jobs: Mutex<HashMap<u64, RunningJob>>,
    shutting_down: AtomicBool,
}

impl<DB> JobManager<DB>
where
    DB: JobStore + SnapshotStore + Send + Sync + 'static,
{
    /// Create a new job manager.
    pub fn new(db: Arc<DB>, config: JobManagerConfig) -> Self {
        let pool = ThreadPool::new(config.num_workers);
        Self {
            db,
            config,
            pool,
            running_jobs: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Create a new job and return its ID.
    ///
    /// The job is created in the `Created` state and must be started
    /// separately with `start_job`.
    pub fn create_job<J: Job>(&self, config: J::Config) -> JobResult<JobId> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(JobError::ShuttingDown);
        }

        let config_bytes =
            serde_json::to_vec(&config).map_err(|e| JobError::Snapshot(e.to_string()))?;

        let job_id = self.db.create_job(J::job_type(), &config_bytes)?;
        info!(job_id = %job_id.0, job_type = J::job_type(), "created job");

        Ok(job_id)
    }

    /// Start executing a job.
    ///
    /// The job must be in `Created` state. It will be moved to `Running`
    /// and executed in the thread pool.
    pub fn start_job<J: Job>(&self, job_id: JobId) -> JobResult<()> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(JobError::ShuttingDown);
        }

        let record = self
            .db
            .get_job(job_id)?
            .ok_or(JobError::NotFound(job_id.0))?;

        if record.state != JobExecState::Created {
            return Err(JobError::InvalidState {
                expected: "created".to_string(),
                actual: format!("{:?}", record.state),
            });
        }

        // Parse config
        let config: J::Config = serde_json::from_slice(&record.config)
            .map_err(|e| JobError::Snapshot(e.to_string()))?;

        // Create the job
        let job = J::new(config.clone()).map_err(|e| JobError::Execution(e.to_string()))?;

        // Set up tracking
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel_requested = Arc::new(AtomicBool::new(false));

        {
            let mut running = self.running_jobs.lock().unwrap();
            running.insert(
                job_id.0,
                RunningJob {
                    completed: completed.clone(),
                    cancel_requested: cancel_requested.clone(),
                },
            );
        }

        // Update state to running
        self.db.update_job_state(job_id, JobExecState::Running)?;

        // Execute in thread pool
        let db = self.db.clone();
        let snapshot_interval = self.config.snapshot_interval;

        self.pool.execute(move || {
            let result = execute_job(db.as_ref(), job_id, job, cancel_requested, snapshot_interval);

            // Signal completion
            let (lock, cvar) = &*completed;
            let mut done = lock.lock().unwrap();
            *done = true;
            cvar.notify_all();

            if let Err(e) = result {
                error!(job_id = %job_id.0, error = %e, "job execution failed");
            }
        });

        info!(job_id = %job_id.0, "started job");
        Ok(())
    }

    /// Resume a job from its last snapshot.
    ///
    /// The job must be in `Running` state (indicating it was interrupted).
    pub fn resume_job<J: Job>(&self, job_id: JobId) -> JobResult<()> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(JobError::ShuttingDown);
        }

        let record = self
            .db
            .get_job(job_id)?
            .ok_or(JobError::NotFound(job_id.0))?;

        if record.state != JobExecState::Running {
            return Err(JobError::InvalidState {
                expected: "running".to_string(),
                actual: format!("{:?}", record.state),
            });
        }

        // Parse config
        let config: J::Config = serde_json::from_slice(&record.config)
            .map_err(|e| JobError::Snapshot(e.to_string()))?;

        // Try to load snapshot
        let snapshot_key = format!("job:{}", job_id.0);
        let job = if let Some((step, snapshot_data)) = self.db.load_latest_snapshot(&snapshot_key)?
        {
            info!(job_id = %job_id.0, step = step, "resuming job from snapshot");
            J::restore(&snapshot_data, &config).map_err(|e| JobError::Snapshot(e.to_string()))?
        } else {
            info!(job_id = %job_id.0, "no snapshot found, starting fresh");
            J::new(config).map_err(|e| JobError::Execution(e.to_string()))?
        };

        // Set up tracking
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel_requested = Arc::new(AtomicBool::new(false));

        {
            let mut running = self.running_jobs.lock().unwrap();
            running.insert(
                job_id.0,
                RunningJob {
                    completed: completed.clone(),
                    cancel_requested: cancel_requested.clone(),
                },
            );
        }

        // Execute in thread pool
        let db = self.db.clone();
        let snapshot_interval = self.config.snapshot_interval;

        self.pool.execute(move || {
            let result = execute_job(db.as_ref(), job_id, job, cancel_requested, snapshot_interval);

            // Signal completion
            let (lock, cvar) = &*completed;
            let mut done = lock.lock().unwrap();
            *done = true;
            cvar.notify_all();

            if let Err(e) = result {
                error!(job_id = %job_id.0, error = %e, "job execution failed");
            }
        });

        Ok(())
    }

    /// Get the status of a job.
    pub fn get_status(&self, job_id: JobId) -> JobResult<Option<JobRecord>> {
        Ok(self.db.get_job(job_id)?)
    }

    /// Wait for a job to complete, with timeout.
    ///
    /// Returns `true` if the job completed, `false` if the timeout elapsed.
    pub fn wait_for_job(&self, job_id: JobId, timeout: Duration) -> JobResult<bool> {
        let running = self.running_jobs.lock().unwrap();
        let job = match running.get(&job_id.0) {
            Some(j) => j.completed.clone(),
            None => {
                // Job might already be done
                if let Some(record) = self.db.get_job(job_id)? {
                    return Ok(matches!(
                        record.state,
                        JobExecState::Finished | JobExecState::Failed
                    ));
                }
                return Err(JobError::NotFound(job_id.0));
            }
        };
        drop(running);

        let (lock, cvar) = &*job;
        let done = lock.lock().unwrap();
        if *done {
            return Ok(true);
        }

        let result = cvar.wait_timeout(done, timeout).unwrap();
        Ok(*result.0)
    }

    /// Cancel a running job.
    ///
    /// The job will complete its current step and then stop.
    pub fn cancel_job(&self, job_id: JobId) -> JobResult<()> {
        let running = self.running_jobs.lock().unwrap();
        if let Some(job) = running.get(&job_id.0) {
            job.cancel_requested.store(true, Ordering::SeqCst);
            info!(job_id = %job_id.0, "cancellation requested");
            Ok(())
        } else {
            Err(JobError::NotFound(job_id.0))
        }
    }

    /// List all jobs that need recovery.
    ///
    /// Returns jobs in `Created` or `Running` state.
    pub fn list_pending_jobs(&self) -> JobResult<Vec<JobRecord>> {
        Ok(self.db.list_pending_jobs()?)
    }

    /// Initiate shutdown of the job manager.
    ///
    /// No new jobs can be started after this is called.
    pub fn shutdown(&self) {
        info!("job manager shutting down");
        self.shutting_down.store(true, Ordering::SeqCst);

        // Request cancellation of all running jobs
        let running = self.running_jobs.lock().unwrap();
        for (id, job) in running.iter() {
            debug!(job_id = %id, "requesting cancellation for shutdown");
            job.cancel_requested.store(true, Ordering::SeqCst);
        }
    }

    /// Wait for all running jobs to complete.
    pub fn join(&self) {
        self.pool.join();
    }
}

/// Execute a job to completion.
fn execute_job<DB, J>(
    db: &DB,
    job_id: JobId,
    mut job: J,
    cancel_requested: Arc<AtomicBool>,
    snapshot_interval: u64,
) -> JobResult<()>
where
    DB: JobStore + SnapshotStore,
    J: DynJob,
{
    let snapshot_key = format!("job:{}", job_id.0);
    let mut step_count: u64 = 0;
    let mut ctx = JobContext::new();

    loop {
        // Check for cancellation
        if cancel_requested.load(Ordering::SeqCst) {
            ctx.cancel();
        }

        // Execute one step
        let result = match job.step(&ctx) {
            Ok(r) => r,
            Err(e) => {
                error!(job_id = %job_id.0, error = %e, "job step failed");
                db.update_job_state(job_id, JobExecState::Failed)?;
                db.set_job_error(job_id, &e.to_string())?;
                return Err(e);
            }
        };

        step_count += 1;

        // Update progress
        if let (Some(total), completed) = (job.total_work_units(), job.completed_work_units()) {
            let _ = db.update_job_progress(job_id, completed, total);
        }

        // Save snapshot periodically
        if step_count % snapshot_interval == 0 {
            let snapshot_data = job.snapshot();
            if let Err(e) = db.save_snapshot(&snapshot_key, step_count, &snapshot_data) {
                warn!(job_id = %job_id.0, error = %e, "failed to save snapshot");
            } else {
                debug!(job_id = %job_id.0, step = step_count, "saved snapshot");
                // Clean up old snapshots
                let _ = db.delete_snapshots_before(&snapshot_key, step_count.saturating_sub(1));
            }
        }

        // Check if done
        if result.is_complete() {
            if ctx.is_cancelled() {
                info!(job_id = %job_id.0, "job cancelled");
                // Leave in running state for potential resume
            } else {
                info!(job_id = %job_id.0, steps = step_count, "job completed");
                db.update_job_state(job_id, JobExecState::Finished)?;
                // Clean up snapshots
                let _ = db.delete_snapshots(&snapshot_key);
            }
            break;
        }
    }

    Ok(())
}

impl<DB> Drop for JobManager<DB> {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::StepResult;
    use mosaic_db_sqlite::SqliteDatabase;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize)]
    struct TestConfig {
        steps: u32,
    }

    struct TestJob {
        config: TestConfig,
        current_step: u32,
    }

    impl Job for TestJob {
        type Config = TestConfig;
        type Output = u32;
        type Error = std::io::Error;

        fn job_type() -> &'static str {
            "test_job"
        }

        fn new(config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self {
                config,
                current_step: 0,
            })
        }

        fn step(&mut self, ctx: &JobContext) -> Result<StepResult, Self::Error> {
            if ctx.is_cancelled() {
                return Ok(StepResult::Complete);
            }

            self.current_step += 1;

            if self.current_step >= self.config.steps {
                Ok(StepResult::Complete)
            } else {
                Ok(StepResult::Continue)
            }
        }

        fn snapshot(&self) -> Vec<u8> {
            self.current_step.to_le_bytes().to_vec()
        }

        fn restore(snapshot: &[u8], config: &Self::Config) -> Result<Self, Self::Error> {
            let current_step = u32::from_le_bytes(snapshot.try_into().unwrap());
            Ok(Self {
                config: config.clone(),
                current_step,
            })
        }

        fn output(&self) -> Result<Self::Output, Self::Error> {
            Ok(self.current_step)
        }

        fn total_work_units(&self) -> Option<u64> {
            Some(self.config.steps as u64)
        }

        fn completed_work_units(&self) -> u64 {
            self.current_step as u64
        }
    }

    fn test_manager() -> JobManager<SqliteDatabase> {
        let db = Arc::new(SqliteDatabase::open_in_memory().unwrap());
        let config = JobManagerConfig {
            num_workers: 2,
            snapshot_interval: 5,
        };
        JobManager::new(db, config)
    }

    #[test]
    fn test_create_and_run_job() {
        let manager = test_manager();

        let config = TestConfig { steps: 10 };
        let job_id = manager.create_job::<TestJob>(config).unwrap();

        manager.start_job::<TestJob>(job_id).unwrap();

        let completed = manager
            .wait_for_job(job_id, Duration::from_secs(5))
            .unwrap();
        assert!(completed);

        let status = manager.get_status(job_id).unwrap().unwrap();
        assert_eq!(status.state, JobExecState::Finished);
    }

    #[test]
    fn test_job_not_found() {
        let manager = test_manager();
        let result = manager.start_job::<TestJob>(JobId(9999));
        assert!(matches!(result, Err(JobError::NotFound(9999))));
    }

    #[test]
    fn test_list_pending_jobs() {
        let manager = test_manager();

        let config = TestConfig { steps: 1000 };
        let job_id = manager.create_job::<TestJob>(config).unwrap();

        let pending = manager.list_pending_jobs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, job_id);
    }
}

# Job Scheduler

The job scheduler executes actions emitted by the Garbler and Evaluator state machines.

## Crate Structure

```
crates/job/
├── api/          # Executor traits, session types, submission/completion types
├── executors/    # MosaicExecutor, all 18 handler impls, garbling core, poly cache
├── scheduler/    # Pools, garbling coordinator, routing, priority, requeue
```

**job-api** defines the interface: executor traits (`ExecuteGarblerJob`, `ExecuteEvaluatorJob`), `CircuitSession`, `SessionFactory`, `HandlerOutcome`, and the submission/completion types. The SM Scheduler depends only on this crate.

**job-executors** provides `MosaicExecutor<SP, TS>`, the concrete implementation of both executor traits. Contains all 18 handler implementations, the `GarblingSession` core, `PolynomialCache`, and three `CircuitSession` types (commitment, transfer, evaluation). Generic over `StorageProvider` and `TableStore`.

**job-scheduler** contains the scheduling infrastructure: light pool, heavy pool, multi-threaded garbling coordinator, action classification, priority queue, and worker retry logic. Generic over the executor traits — has no compile-time dependency on `job-executors`.

```
   ┌──────────────┐
   │ SM Scheduler  │
   └───────┬───────┘
           │
           ▼
   ┌─────────────┐   ┌──────────────┐   ┌───────────────┐
   │   job-api    │   │  net-client   │   │  storage-api   │
   └─────────────┘   └──────────────┘   └───────────────┘
           ▲                 ▲                   ▲
           └────────┬────────┴───────────────────┘
                    │
           ┌────────┴────────┐
           │  job-executors   │
           └────────┬────────┘
                    │
           ┌────────┴────────┐
           │  job-scheduler   │  (generic over executor traits)
           └─────────────────┘
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   JobScheduler (monoio thread)                           │
│                                                                          │
│  dispatch_batch: classify action → route to pool or coordinator          │
├──────────────────┬───────────────────┬───────────────────────────────────┤
│  Light Pool      │   Heavy Pool      │   Garbling Coordinator            │
│                  │                   │                                   │
│  Pull model      │  Pull model       │  Push model                      │
│  FIFO queue      │  Priority queue   │  Multi-threaded barrier sync     │
│  1 monoio worker │  2 monoio workers │  1 main thread + N worker threads│
│  32 concurrency  │  8 concurrency    │  SessionFactory + retry          │
└──────────────────┴───────────────────┴───────────────────────────────────┘
```

The scheduler thread runs its own monoio runtime. Each pool worker thread runs its own monoio runtime with bounded concurrency via a permit pool (kanal channel-based). Workers pull jobs from a shared queue as `!Send` local tasks.

The garbling coordinator runs on a dedicated main thread that reads the circuit file and broadcasts chunks to N worker threads. Workers process their assigned sessions concurrently. A barrier synchronizes each chunk.

## Action Categories

| Category | Time | Pool | Examples |
|----------|------|------|----------|
| Light | Milliseconds | FIFO, 1 thread | SendCommitMsgChunk, SendChallengeMsg, ReceiveGarblingTable |
| Heavy | Seconds–minutes | Priority, 2 threads | VerifyOpenedInputShares, DepositVerifyAdaptors |
| Garbling | Minutes | Coordinator, N threads | GenerateTableCommitment, TransferGarblingTable, EvaluateGarblingTable |

Light actions are I/O-bound (outbound protocol sends via net-client, inbound bulk receives). Heavy actions are CPU-bound. Garbling actions are CPU-bound and require coordinated sequential reads of a ~130 GB circuit file.

## All 18 Actions

### Garbler Actions (10)

| # | Action | Category | Priority | Handler |
|---|--------|----------|----------|---------|
| G1 | `GeneratePolynomialCommitments(Seed, Wire)` | Heavy | Normal | Per-wire commitment via RAII cache guard |
| G2 | `GenerateShares(Seed, Index)` | Heavy | Normal | Evaluate polynomials at circuit index (incl. reserved 0) |
| G3 | `GenerateTableCommitment(Index, GarblingSeed)` | Garbling | Normal | CommitmentSession — garble + hash → commitment |
| G4 | `SendCommitMsgHeader(CommitMsgHeader)` | Light | Normal | Net send + retry |
| G5 | `SendCommitMsgChunk(CommitMsgChunk)` | Light | Normal | Net send + retry |
| G6 | `SendChallengeResponseMsgHeader(...)` | Light | Normal | Net send + retry |
| G7 | `SendChallengeResponseMsgChunk(...)` | Light | Normal | Net send + retry |
| G8 | `TransferGarblingTable(GarblingSeed)` | Garbling | Normal | TransferSession — garble + stream to peer |
| G9 | `DepositVerifyAdaptors(DepositId)` | Heavy | High | Verify deposit + withdrawal adaptors |
| G10 | `CompleteAdaptorSignatures(DepositId)` | Heavy | Critical | Complete with reserved shares |

### Evaluator Actions (8)

| # | Action | Category | Priority | Handler |
|---|--------|----------|----------|---------|
| E1 | `SendChallengeMsg(ChallengeMsg)` | Light | Normal | Net send + retry |
| E2 | `VerifyOpenedInputShares` | Heavy | Normal | Verify 7.7M shares against polynomial commitments |
| E3 | `GenerateTableCommitment(Index, GarblingSeed)` | Garbling | Normal | CommitmentSession — re-garble to verify commitment |
| E4 | `ReceiveGarblingTable(GarblingTableCommitment)` | Light | Normal | Bulk receive + hash verify + store to TableStore |
| E5 | `GenerateDepositAdaptors(DepositId)` | Heavy | High | Generate adaptors from zeroth-coefficient commitments |
| E6 | `GenerateWithdrawalAdaptorsChunk(DepositId, ChunkIndex)` | Heavy | High | Chunked withdrawal adaptor generation |
| E7 | `DepositSendAdaptorMsgChunk(DepositId, AdaptorMsgChunk)` | Light | High | Net send + retry |
| E8 | `EvaluateGarblingTable(Index, GarblingTableCommitment)` | Garbling | Critical | EvaluationSession — evaluate with stored ciphertexts |

## API

### Executor Traits

Defined in `job-api`, implemented in `job-executors`:

```rust
pub trait ExecuteGarb
lerJob: Send + Sync + 'static {
    type Session: CircuitSession + Send;

    // Pool actions — return HandlerOutcome directly
    fn generate_polynomial_commitments(&self, peer_id: &PeerId, seed: Seed, wire: Wire)
        -> impl Future<Output = HandlerOutcome> + Send;
    fn generate_shares(&self, peer_id: &PeerId, seed: Seed, index: Index)
        -> impl Future<Output = HandlerOutcome> + Send;
    fn send_commit_msg_header(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn send_commit_msg_chunk(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn send_challenge_response_header(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn send_challenge_response_chunk(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn deposit_verify_adaptors(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn complete_adaptor_signatures(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;

    // Circuit actions — return a Session for the coordinator to drive
    fn begin_table_commitment(&self, ...) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
    fn begin_table_transfer(&self, ...) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
}

pub trait ExecuteEvaluatorJob: Send + Sync + 'static {
    type Session: CircuitSession + Send;

    // Pool actions
    fn send_challenge_msg(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn verify_opened_input_shares(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn generate_deposit_adaptors(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn generate_withdrawal_adaptors_chunk(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn deposit_send_adaptor_msg_chunk(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;
    fn receive_garbling_table(&self, ...) -> impl Future<Output = HandlerOutcome> + Send;

    // Circuit actions
    fn begin_table_commitment(&self, ...) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
    fn begin_evaluation(&self, ...) -> impl Future<Output = Result<Self::Session, CircuitError>> + Send;
}
```

Type safety is structural: pool actions return `HandlerOutcome` (submitted to worker pools), circuit actions return a `Session` (submitted to coordinator). A circuit action physically cannot go through the pool path.

The concrete implementation is `MosaicExecutor<SP: StorageProvider, TS: TableStore>` in `job-executors`.

### SessionFactory

The garbling coordinator needs to create sessions from action descriptors without knowing the concrete executor type. `SessionFactory` is a dyn-compatible trait with a blanket implementation:

```rust
pub trait SessionFactory: Send + Sync + 'static {
    fn create_session(&self, job: &PendingCircuitJob)
        -> Pin<Box<dyn Future<Output = Result<Box<dyn CircuitSession>, CircuitError>> + Send + '_>>;
}

// Blanket impl: any D: ExecuteGarblerJob + ExecuteEvaluatorJob gets this automatically.
impl<D: ExecuteGarblerJob + ExecuteEvaluatorJob> SessionFactory for D { ... }
```

The scheduler creates `Arc<dyn SessionFactory>` from the executor and passes it to the coordinator. The coordinator calls `create_session` internally with retry for transient failures.

### CircuitSession

Dyn-compatible trait for sessions driven block-by-block by the coordinator:

```rust
pub trait CircuitSession: Send {
    fn process_chunk(&mut self, chunk: &Arc<OwnedChunk>)
        -> Pin<Box<dyn Future<Output = Result<(), CircuitError>> + Send + '_>>;
    fn finish(self: Box<Self>)
        -> Pin<Box<dyn Future<Output = HandlerOutcome> + Send>>;
}
```

Three implementations:
- **CommitmentSession** (G3/E3) — garbles and hashes ciphertext for commitment computation
- **TransferSession** (G8) — garbles and streams ciphertext to peer via bulk transfer
- **EvaluationSession** (E8) — evaluates circuit with pre-read ciphertexts from TableStore

### Submission Types

```rust
pub struct JobBatch { pub peer_id: PeerId, pub actions: JobActions }
pub enum JobActions { Garbler(ActionContainer), Evaluator(ActionContainer) }
pub struct JobCompletion { pub peer_id: PeerId, pub completion: ActionCompletion }
pub enum ActionCompletion {
    Garbler { id: GarblerActionId, result: GarblerActionResult },
    Evaluator { id: EvaluatorActionId, result: EvaluatorActionResult },
}
```

The SM Scheduler submits batches via `JobSchedulerHandle` and receives individual completions. Jobs always retry internally until they succeed — the SM never sees failures.

### Circuit Action Descriptors

```rust
pub enum CircuitAction {
    GarblerCommitment { index: Index, seed: GarblingSeed },
    GarblerTransfer { seed: GarblingSeed },
    EvaluatorCommitment { index: Index, seed: GarblingSeed },
    EvaluatorEvaluation { index: Index, commitment: GarblingTableCommitment },
}

pub struct PendingCircuitJob { pub peer_id: PeerId, pub action: CircuitAction }
```

These are plain data descriptors that can be stored, retried, and resubmitted. The coordinator holds them on a pending retry list until session creation succeeds.

### Action → ActionResult Mapping

| Action (Garbler) | ActionResult |
|---|---|
| GeneratePolynomialCommitments | PolynomialCommitmentsGenerated |
| GenerateShares | SharesGenerated |
| GenerateTableCommitment | TableCommitmentGenerated |
| SendCommitMsgHeader | CommitMsgChunkAcked |
| SendCommitMsgChunk | CommitMsgChunkAcked |
| SendChallengeResponseMsgHeader | ChallengeResponseChunkAcked |
| SendChallengeResponseMsgChunk | ChallengeResponseChunkAcked |
| TransferGarblingTable | GarblingTableTransferred |
| DepositVerifyAdaptors | DepositAdaptorVerificationResult |
| CompleteAdaptorSignatures | AdaptorSignaturesCompleted |

| Action (Evaluator) | ActionResult |
|---|---|
| SendChallengeMsg | ChallengeMsgAcked |
| VerifyOpenedInputShares | VerifyOpenedInputSharesResult |
| GenerateTableCommitment | TableCommitmentGenerated |
| ReceiveGarblingTable | GarblingTableReceived |
| GenerateDepositAdaptors | DepositAdaptorsGenerated |
| GenerateWithdrawalAdaptorsChunk | WithdrawalAdaptorsChunkGenerated |
| DepositSendAdaptorMsgChunk | DepositAdaptorChunkSent |
| EvaluateGarblingTable | TableEvaluationResult |

## Light Pool

Handles I/O-bound work: outbound protocol sends (G4–G7, E1, E7) and inbound bulk receives (E4). Workers pull from a FIFO queue. High concurrency (32 per worker) lets it multiplex many tasks waiting on network.

E4 (`ReceiveGarblingTable`) is classified as Light because it receives data from the network and writes to the table store — it does not need the shared circuit reader.

## Heavy Pool

Handles CPU-intensive non-garbling work. Workers pull from a priority queue with three levels:

| Priority | Phase | Rationale |
|----------|-------|-----------|
| Critical | Withdrawal | Blockchain timeout at stake |
| High | Deposit | User waiting |
| Normal | Setup | Done in advance |

Workers drain Critical → High → Normal. Withdrawal disputes are never blocked by background setup.

## Garbling Coordinator

The coordinator solves the **shared reader problem**: garbling reads a ~130 GB circuit file. With independent readers at different offsets, disk thrashing destroys throughput. Sequential reads are dramatically faster.

**Key insight:** All circuits share the same gate topology — only the garbling seeds differ. One sequential read serves N concurrent sessions, each producing ~43 GB of different output.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│               Main thread (coordinator_loop)                      │
│                                                                    │
│  1. Collect PendingCircuitJobs (channel + retry list)             │
│  2. Create sessions via SessionFactory (retry StorageUnavailable) │
│  3. Distribute sessions round-robin across workers                │
│  4. Read circuit file sequentially                                │
│                                                                    │
│  For each chunk:                                                  │
│    ReaderV5c → convert → Arc<OwnedChunk>                          │
│        │                                                          │
│        ├── send to Worker 0 ──► process sessions ──► ChunkReport  │
│        ├── send to Worker 1 ──► process sessions ──► ChunkReport  │
│        ├── send to Worker 2 ──► process sessions ──► ChunkReport  │
│        └── send to Worker 3 ──► process sessions ──► ChunkReport  │
│                                                                    │
│    Barrier: wait for all ChunkReports                             │
│    Collect evicted jobs → retry list                              │
│                                                                    │
│  5. Send FinishPass → workers call session.finish()               │
│  6. Workers send completions directly to SM                       │
└──────────────────────────────────────────────────────────────────┘
```

### Session Distribution

Sessions are assigned to workers round-robin, spread-first:

```
7 sessions across 4 workers:
  Worker 0: sessions 0, 4     (2 sessions)
  Worker 1: sessions 1, 5     (2 sessions)
  Worker 2: sessions 2, 6     (2 sessions)
  Worker 3: session  3        (1 session)
```

This naturally balances load — no worker gets more than `ceil(total / workers)` sessions.

### Retry Guarantees

**No action is ever silently dropped.** The coordinator maintains a `pending_retry` list:

| Failure | Behavior |
|---------|----------|
| `StorageUnavailable` during session creation | Job stays on retry list, tried again next pass |
| `SetupFailed` during session creation | Permanent error — logged and dropped (programming bug) |
| Session error during `process_chunk` | Session evicted, job moved to retry list |
| Session timeout during `process_chunk` | Session evicted, job moved to retry list |
| `session.finish()` returns `Retry` | Job moved to retry list |
| Circuit reader fails to open | All jobs moved to retry list |
| Circuit reader errors mid-pass | Remaining jobs moved to retry list |
| Worker thread dies | Sessions on that worker are lost (logged as error) |

### Worker Protocol

Communication between main thread and workers uses bounded kanal channels:

```rust
// Main → Worker
enum WorkerCommand {
    AssignSessions(Vec<ActiveSession>),  // before pass
    ProcessChunk(Arc<OwnedChunk>),       // per chunk
    FinishPass,                           // after all chunks
    Shutdown,                             // coordinator shutting down
}

// Worker → Main
enum WorkerReport {
    ChunkDone(ChunkReport),   // evicted jobs + remaining count
    FinishDone(FinishReport), // retry jobs from finish()
}
```

Workers send completions directly to the SM via a cloned `completion_tx` channel — completions don't route through the main thread.

### Configuration

```rust
pub struct GarblingConfig {
    pub worker_threads: usize,      // default: 4
    pub max_concurrent: usize,      // default: 8 (caps memory at ~8 GB)
    pub circuit_path: PathBuf,
    pub batch_timeout: Duration,    // default: 500ms (wait for more jobs)
    pub chunk_timeout: Duration,    // default: 30s (per-session eviction)
}
```

## Pool Worker Retry

When an executor returns `HandlerOutcome::Retry`, the pool worker:

1. Increments `job.attempts`
2. Sleeps with exponential backoff: `min(100ms × 2^attempts, 10s)`
3. Requeues the job to the back of the pool queue

This prevents busy-spinning on transient failures (unresponsive peer, full polynomial cache, unavailable storage) while ensuring other peers' jobs get a chance to run between retries.

## Shutdown

`JobScheduler` implements `Drop`. On drop, it:

1. Closes the light and heavy pool queues (workers drain remaining jobs and exit)
2. Shuts down the garbling coordinator (closes channel, joins coordinator thread, which in turn shuts down worker threads)

The explicit `shutdown(&mut self)` method does the same but can be called manually for deterministic teardown. All operations are idempotent — calling `shutdown()` then dropping is safe.

## Stability

### Light Pool

Bursts of send operations queue up and execute as earlier tasks complete. All are I/O-bound, so high concurrency handles bursts efficiently. If the network slows, tasks take longer, the queue grows, and SMs eventually block waiting for completions — natural backpressure.

### Heavy Pool

Setup generates many Normal-priority actions. They queue and process as workers become available. If a Critical withdrawal action arrives mid-setup, it jumps the queue immediately.

### Garbling Coordinator

Multiple peers need garbling tables simultaneously. Sessions are distributed across workers and process their chunks concurrently. A per-session timeout evicts slow consumers (e.g. G8 streaming to a congested peer) without blocking other sessions. Evicted sessions are automatically retried on the next pass.

The async submission channel prevents the garbling coordinator from blocking the scheduler thread. If the coordinator is mid-pass (which can take minutes for the full 130 GB circuit), new jobs queue in the channel and are picked up for the next pass.

### Resource Protection

| Resource | Protection |
|----------|------------|
| Memory | `max_concurrent` caps sessions (~1 GB each); bounded queues; chunk-at-a-time processing |
| CPU | Concurrency limits per worker; separate pools prevent interference |
| Disk I/O | Single sequential circuit reader per pass; shared via Arc |
| Network | Async I/O yields during waits; per-session timeout evicts slow streams |
| Threads | `Drop` impl closes queues; worker threads exit when channels close |

## Configuration

```rust
pub struct JobSchedulerConfig {
    pub light: PoolConfig,            // default: 1 thread, 32 concurrency, FIFO
    pub heavy: PoolConfig,            // default: 2 threads, 8 concurrency, priority
    pub garbling: GarblingConfig,     // default: 4 workers, 8 max sessions
    pub submission_queue_size: usize, // default: 256
    pub completion_queue_size: usize, // default: 256
}
```

See `JobSchedulerConfig`, `PoolConfig`, and `GarblingConfig` in `crates/job/scheduler/src/` for all parameters and defaults.
# Job Scheduler

The job scheduler executes actions emitted by the Garbler and Evaluator state machines.

## Crate Structure

```
crates/job/
├── api/          # Submission and result types (thin)
├── scheduler/    # Pools, coordinator, handlers (fat)
```

**job-api** contains types for submitting batches and receiving results. SM Scheduler depends only on this crate.

**job-scheduler** contains the implementation: monoio thread pools, garbling coordinator, action handlers. Main binary depends on this. It re-exports job-api.

```
   ┌─────────────┐
   │SM Scheduler │
   └──────┬──────┘
          │
          ▼
   ┌───────────┐   ┌─────────────┐
   │  job-api  │   │ net-client  │
   └───────────┘   └─────────────┘
          ▲               ▲
          └───────┬───────┘
                  │
           ┌─────────────┐
           │job-scheduler│
           └─────────────┘
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                 JobScheduler (monoio thread)                  │
├────────────────┬─────────────────┬───────────────────────────┤
│  Light Pool    │   Heavy Pool    │   Garbling Coordinator    │
│                │                 │                           │
│  Pull model    │  Pull model     │  Push model               │
│  FIFO queue    │  Priority queue │  Barrier-synchronized     │
│  monoio workers│  monoio workers │                           │
└────────────────┴─────────────────┴───────────────────────────┘
```

The scheduler thread runs its own monoio runtime. Each worker thread runs its own monoio runtime with bounded concurrency via a local semaphore. Workers pull jobs from the shared queue as `!Send` local tasks.

## Action Categories

| Category | CPU Time | Examples |
|----------|----------|----------|
| Light | Milliseconds | SendCommitMsgChunk, SendChallengeMsg, DepositSendAdaptorMsgChunk |
| Heavy | Seconds–minutes | VerifyOpenedInputShares, DepositVerifyAdaptors, EvaluateGarblingTable |
| Garbling | Minutes | GenerateTableCommitment, TransferGarblingTable |

Light actions are I/O-bound (outbound protocol sends via net-client). Heavy actions are CPU-bound. Garbling actions are CPU-bound but also require coordinated disk I/O.

Message acking is not part of the job system. Incoming protocol messages are acked by the SM executor after the STF succeeds and state is persisted.

## API

### Integration Points

```
┌────────────────┐                           ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│                │         job-api                   job-scheduler
│  SM Scheduler  │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ▶│┌───────────────────────┐  │
│                │     JobBatch               │     JobScheduler      │
└────────────────┘                           ││                       │  │
        ▲                                     │  ┌─────┬─────┬─────┐  │
        │                                    ││  │Light│Heavy│Garbl│  │  │
        │          job-api                    │  └─────┴─────┴─────┘  │
        └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼│                       │  │
                 JobCompletion                │     handlers (mod)    │
                                             │└───────────┬───────────┘  │
                                              ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─
                                                          │
                                                          ▼
                                                  ┌───────────────┐
                                                  │  net-client   │
                                                  └───────────────┘
```

SM Scheduler submits batches via job-api types. Job Scheduler executes each action and returns individual completions. SM Scheduler never sees pool internals or handlers.

### job-api Types

| Type | Purpose |
|------|---------|
| `JobBatch` | PeerId + JobActions (one batch per STF call) |
| `JobActions` | Garbler(ActionContainer) or Evaluator(ActionContainer) |
| `JobCompletion` | PeerId + JobResult |
| `ActionCompletion` | ActionId + ActionResult, typed by role |
| `JobSchedulerHandle` | Cloneable handle for batch submission |

The `JobActions` enum uses the FASM `ActionContainer` types directly — no transformation needed between the SM executor and the job scheduler.

Priority is not part of the API. The scheduler derives priority internally from the action variant.

### Action → ActionResult Mapping

Each action produces a corresponding `ActionResult` delivered back to the SM via FASM's `TrackedActionCompleted`:

| Action (Garbler) | ActionResult |
|------------------|--------------|
| GeneratePolynomialCommitments | PolynomialCommitmentsGenerated |
| GenerateShares | SharesGenerated |
| GenerateTableCommitment | TableCommitmentGenerated |
| SendCommitMsgChunk | CommitMsgChunkAcked |
| SendChallengeResponseMsgChunk | ChallengeResponseChunkAcked |
| TransferGarblingTable | GarblingTableTransferred |
| DepositVerifyAdaptors | DepositAdaptorVerificationResult |
| CompleteAdaptorSignatures | AdaptorSignaturesCompleted |

| Action (Evaluator) | ActionResult |
|--------------------|--------------|
| SendChallengeMsg | ChallengeMsgAcked |
| VerifyOpenedInputShares | VerifyOpenedInputSharesResult |
| GenerateTableCommitment | TableCommitmentGenerated |
| ReceiveGarblingTables | GarblingTableReceived |
| DepositGenerateAdaptors | DepositAdaptorsGenerated |
| DepositSendAdaptorMsgChunk | DepositAdaptorChunkSent |
| EvaluateGarblingTable | TableEvaluationResult |

### Batch Submission

Actions are submitted as a `JobBatch` — one batch per STF call. All actions in a batch share the same peer ID. The `JobActions` variant (garbler or evaluator) identifies the SM role.

The scheduler unwraps the FASM `ActionContainer`, categorizes each action, assigns priority, and routes to the appropriate pool.

### Network Operations

Light actions that involve outbound protocol sends use net-client internally. `NetClient::send()` waits for the peer's protocol acknowledgment and returns when the peer confirms receipt. This ack is part of the send action's lifecycle and produces the corresponding `ActionResult`.

## Light Pool

Handles I/O-bound work. Workers pull from a FIFO queue. High concurrency per worker lets it multiplex many tasks waiting on network.

## Heavy Pool

Handles CPU-intensive non-garbling work. Workers pull from a priority queue with three levels derived from the action variant:

| Priority | Phase | Rationale |
|----------|-------|-----------|
| Critical | Withdrawal | Blockchain timeout at stake |
| High | Deposit | User waiting |
| Normal | Setup | Done in advance |

Workers drain Critical → High → Normal. Withdrawal disputes are never blocked by background setup.

## Garbling Coordinator

Garbling reads a 130GB topology file. With O_DIRECT, concurrent readers at different offsets cause disk thrashing. Sequential reads are dramatically faster.

**Solution:** A single reader thread reads the topology sequentially, broadcasting gate chunks to all active garbling jobs. Jobs process chunks in lockstep, synchronized by a barrier.

**Key insight:** All circuits share the same topology—only the garbling seeds differ. One read serves N jobs, each producing 43GB of different output.

**Chunk cycle:**
1. Reader reads next chunk sequentially
2. Coordinator pushes chunk to workers (round-robin, spread-first)
3. Workers garble with job-specific seeds, stream or hash output
4. Barrier waits for all jobs to complete
5. Repeat until topology exhausted

### Job Registration

Garbling jobs register with the coordinator rather than submitting to a queue. The first registered job starts the reader thread. Jobs receive gate chunks via their handle until the topology is exhausted. When the last job unregisters, the reader stops.

Jobs arriving mid-read-through wait for the next full pass—partial garbling tables are useless.

## Distribution

**Light/Heavy pools** use pull: workers grab from shared queue when ready. Simple, naturally load-balanced. Each worker runs a monoio runtime with a local semaphore bounding concurrent tasks.

**Garbling** uses push with round-robin: coordinator knows exact job count and must guarantee slots for barrier synchronization. Spread-first assignment maximizes parallelism—12 jobs across 4 workers means 3 each, not 8-4-0-0.

## Stability

### Light Pool

Burst of send operations: tasks queue up, start as earlier tasks complete. All are I/O-bound, so high concurrency handles bursts efficiently. If network slows, tasks take longer, queue grows, and SMs eventually block waiting for completion—natural backpressure.

### Heavy Pool

Setup generates many Normal-priority actions. They queue and process as workers become available. If a Critical withdrawal action arrives mid-setup, it jumps the queue immediately. Starvation is unlikely since setup completes before deposits begin.

### Garbling Coordinator

Multiple peers need garbling tables simultaneously. All jobs register, reader broadcasts chunks to all. The barrier rate-limits to the slowest consumer—if one peer's network is congested, streaming slows, barrier waits, reader pauses. This prevents memory exhaustion from buffering too many chunks.

### Resource Protection

| Resource | Protection |
|----------|------------|
| Memory | Bounded queues, barrier backpressure, chunk-at-a-time processing |
| CPU | Concurrency limits per worker, separate pools prevent interference |
| Disk I/O | Single sequential reader, no concurrent random access |
| Network | Async I/O yields during waits, backpressure propagates to reader |

## Configuration

See `JobSchedulerConfig`, `PoolConfig`, and `GarblingConfig` in `crates/job/scheduler/src/` for configurable parameters and their defaults.
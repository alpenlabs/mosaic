# Job Scheduler

The job scheduler executes actions emitted by the Garbler and Evaluator state machines.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       JobScheduler                           │
├────────────────┬─────────────────┬───────────────────────────┤
│  Light Pool    │   Heavy Pool    │   Garbling Coordinator    │
│                │                 │                           │
│  Pull model    │  Pull model     │  Push model               │
│  FIFO queue    │  Priority queue │  Barrier-synchronized     │
└────────────────┴─────────────────┴───────────────────────────┘
```

Each pool runs async tasks with configurable thread count and concurrency per thread.

## Action Categories

| Category | CPU Time | Examples |
|----------|----------|----------|
| Light | Milliseconds | SendCommitMsgChunk, AckChallengeMsg, ReceiveGarblingTables |
| Heavy | Seconds–minutes | VerifyOpenedInputShares, DepositVerifyAdaptors, EvaluateGarblingTable |
| Garbling | Minutes | GenerateTableCommitment, TransferGarblingTable |

Light actions are I/O-bound (network sends, acks). Heavy actions are CPU-bound. Garbling actions are CPU-bound but also require coordinated disk I/O.

## API

### Integration Points

```
┌────────────────┐         Actions          ┌────────────────┐
│                │ ───────────────────────► │                │
│  SM Scheduler  │                          │  Job Scheduler │
│                │ ◄─────────────────────── │                │
└────────────────┘         Inputs           └───────┬────────┘
                                                    │
                                                    │ send/recv
                                                    ▼
                                            ┌────────────────┐
                                            │   net-client   │
                                            └────────────────┘
```

The SM Scheduler submits actions to the Job Scheduler. When a job completes, the result is converted to an Input and sent back to the SM Scheduler for the next state transition.

### Action → Input Mapping

Each action produces a corresponding input when complete:

| Action (Garbler) | Result Input |
|------------------|--------------|
| GeneratePolynomialCommitments | PolynomialCommitmentsGenerated |
| GenerateShares | SharesGenerated |
| GenerateTableCommitment | TableCommitmentGenerated |
| SendCommitMsgChunk | CommitMsgAcked |
| AckChallengeMsg | (none, ack only) |
| SendChallengeResponseMsgChunk | ChallengeResponseAcked |
| TransferGarblingTable | GarblingTableTransferred |
| DepositAckAdaptorMsg | (none, ack only) |
| DepositVerifyAdaptors | DepositAdaptorVerificationResult |
| CompleteAdaptorSignatures | AdaptorSignaturesCompleted |

| Action (Evaluator) | Result Input |
|--------------------|--------------|
| AckCommitMsg | (none, ack only) |
| SendChallengeMsg | ChallengeMsgAcked |
| AckChallengeResponseMsg | (none, ack only) |
| VerifyOpenedInputShares | VerifyOpenedInputSharesResult |
| GenerateTableCommitment | TableCommitmentGenerated |
| ReceiveGarblingTables | GarblingTableReceived |
| DepositGenerateAdaptors | DepositAdaptorsGenerated |
| DepositSendAdaptorMsgChunk | DepositAdaptorMsgAcked |
| EvaluateGarblingTable | TableEvaluationResult |

### Submission Interface

Actions are submitted with the originating state machine ID. Results are returned with the same ID so the SM Scheduler can route them correctly.

Submission is asynchronous—the SM Scheduler does not block waiting for completion. Multiple actions from different SMs may execute concurrently.

### Network Operations

Light actions that involve network I/O use net-client internally:

- **Send actions** call `NetClient::send()` and wait for peer acknowledgment
- **Ack actions** call `InboundRequest::ack()` on a previously received message
- **Receive actions** register expectations with net-svc and complete when data arrives

The Job Scheduler owns the NetClient instance. Jobs borrow it for the duration of their execution.

## Light Pool

Handles I/O-bound work. A single thread with high concurrency can efficiently multiplex many tasks waiting on network. Workers pull from a FIFO queue.

## Heavy Pool

Handles CPU-intensive non-garbling work. Workers pull from a priority queue with three levels:

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

**Light/Heavy pools** use pull: workers grab from shared queue when ready. Simple, naturally load-balanced.

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

```toml
[job_scheduler]
light_threads = 1
light_concurrency = 32
heavy_threads = 2
heavy_concurrency = 8
garbling_threads = 4
garbling_concurrency = 8
garbling_chunk_size = "64MB"
```

Defaults assume an 8-core machine, leaving headroom for net-svc and OS. Adjust based on core count and workload.
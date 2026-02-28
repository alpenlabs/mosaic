# SM Scheduler Runtime & API

This document defines the target architecture for state machine execution in Mosaic.

The previous split between `state-machine/executor` and `state-machine/scheduler` is replaced by:

- one **runtime crate** that owns scheduling + STF execution logic
- one **public API crate** with command/handle/config types

The runtime continues to use FASM state machines (`GarblerSM`, `EvaluatorSM`) and the existing job system for all heavy work.

## Goals

1. Keep per-peer SM execution deterministic and easy to reason about.
2. Keep heavy computation out of STF execution.
3. Keep a clean public boundary for Bridge Core / RPC code.
4. Preserve at-least-once message handling semantics.
5. Make startup restore and retry behavior explicit.

## Crate Structure

```text
crates/state-machine/
├── scheduler-api/   # Public handle + command/config types (no runtime internals)
└── scheduler/       # Runtime: event loop, routing, STF wrapper calls, restore
```

### Dependencies

**`state-machine/scheduler-api`**
- `mosaic-cac-types` (command payload types)
- `mosaic-net-svc-api::PeerId`
- `kanal`

**`state-machine/scheduler`**
- `state-machine/scheduler-api`
- `mosaic-cac-protocol` (`GarblerSM`, `EvaluatorSM`)
- `mosaic-cac-types` (SM inputs/action ids/results)
- `mosaic-job-api` (`JobSchedulerHandle`, `JobBatch`, `JobCompletion`, `ActionCompletion`)
- `mosaic-net-client` / `mosaic-net-svc-api` (incoming protocol streams)
- `mosaic-storage-api` (mutable per-peer state handles)
- `fasm`
- `monoio`, `kanal`

## Why Runtime + API Split

### Why merge scheduler and executor runtime logic?

The old `executor` crate provided thin wrappers (`stf` calls) and did not justify a separate runtime boundary.

What matters operationally is one component that:

- owns per-peer state handles
- routes inbound events/completions
- invokes STF in order
- submits emitted actions

Keeping these in one runtime crate removes indirection and stale abstractions.

### Why add a separate API crate?

Same reason as `net-svc-api` and `job-api`:

- isolate cross-crate integration types from runtime internals
- keep public surface small and stable
- avoid pulling monoio/FASM/runtime internals into Bridge Core/RPC crates

## High-Level Architecture

```text
                    ┌──────────────────────────┐
                    │      Bridge Core (RPC)   │
                    └────────────┬─────────────┘
                                 │ SmCommand
                                 ▼
┌──────────────┐    ┌──────────────────────────┐    ┌──────────────────┐
│   net-svc    │───►│     SM Scheduler Runtime │◄───│  JobScheduler    │
│ protocol     │    │                          │───►│                  │
│ streams      │    │ per-peer {garbler,eval} │    │ JobBatch submit  │
└──────────────┘    │ STF call + emit actions │    │ JobCompletion recv│
                    └──────────┬───────────────┘    └──────────────────┘
                               │
                               ▼
                    ┌──────────────────────────┐
                    │ Storage (StateMut impls) │
                    │ InMemory / FDB-backed    │
                    └──────────────────────────┘
```

## STF Execution Model

The runtime executes STF directly inside the scheduler loop (per input/completion), then immediately submits emitted tracked actions to `JobScheduler`.

Internal helper functions (in runtime crate, not public API):

```rust
async fn garbler_handle_event<S: garbler::StateMut>(
    state: &mut S,
    input: garbler::Input,
) -> Result<garbler::ActionContainer, SMError>;

async fn garbler_handle_completion<S: garbler::StateMut>(
    state: &mut S,
    id: garbler::ActionId,
    result: garbler::ActionResult,
) -> Result<garbler::ActionContainer, SMError>;

async fn garbler_restore<S: garbler::StateMut>(
    state: &S,
) -> Result<garbler::ActionContainer, SMError>;

async fn evaluator_handle_event<S: evaluator::StateMut>(
    state: &mut S,
    input: evaluator::Input,
) -> Result<evaluator::ActionContainer, SMError>;

async fn evaluator_handle_completion<S: evaluator::StateMut>(
    state: &mut S,
    id: evaluator::ActionId,
    result: evaluator::ActionResult,
) -> Result<evaluator::ActionContainer, SMError>;

async fn evaluator_restore<S: evaluator::StateMut>(
    state: &S,
) -> Result<evaluator::ActionContainer, SMError>;
```

These wrappers are intentionally minimal and internal.

## Do We Need an STF Thread Pool?

No, not for current design.

### Why

- STF work is mostly validation, state reads/writes, and action emission.
- Heavy tasks are represented as actions and executed by job pools/coordinator:
  - polynomial generation
  - share generation/verification
  - garbling table commitment/transfer/evaluation
  - adaptor generation/verification/completion
  - network send/receive/retry

### Operational stance

- Use one monoio scheduler thread for ordering and determinism.
- Let job scheduler pools absorb heavy compute and I/O.
- Revisit only if real metrics show STF becoming a hotspot after TODO helpers are implemented.

## Public API Crate (`scheduler-api`)

Public, stable boundary used by RPC/Bridge-side code.

### Config

```rust
pub struct SmSchedulerConfig {
    pub command_queue_size: usize,
}
```

### Commands

```rust
pub enum SmCommand {
    InitGarbler {
        peer_id: PeerId,
        data: GarblerInitData,
    },
    InitEvaluator {
        peer_id: PeerId,
        data: EvaluatorInitData,
    },
    DepositInitGarbler {
        peer_id: PeerId,
        deposit_id: DepositId,
        data: GarblerDepositInitData,
    },
    DepositInitEvaluator {
        peer_id: PeerId,
        deposit_id: DepositId,
        data: EvaluatorDepositInitData,
    },
    DisputedWithdrawal {
        peer_id: PeerId,
        deposit_id: DepositId,
        withdrawal_input: WithdrawalInputs,
    },
    UndisputedWithdrawal {
        peer_id: PeerId,
        deposit_id: DepositId,
    },
}
```

### Handle

```rust
#[derive(Clone)]
pub struct SmSchedulerHandle {
    command_tx: kanal::AsyncSender<SmCommand>,
}

impl SmSchedulerHandle {
    pub async fn send(&self, cmd: SmCommand) -> Result<(), SchedulerStopped>;
}
```

## Runtime Crate (`scheduler`)

### Core Types

```rust
pub trait SmStateFactory: Send + Sync + 'static {
    type GarblerState: garbler::StateMut + Send;
    type EvaluatorState: evaluator::StateMut + Send;

    fn garbler_state(&self, peer_id: &PeerId) -> Self::GarblerState;
    fn evaluator_state(&self, peer_id: &PeerId) -> Self::EvaluatorState;

    fn known_peers(&self) -> impl Future<Output = Vec<PeerId>> + Send;
}

struct PeerSm<GS, ES> {
    garbler: GS,
    evaluator: ES,
}

pub struct SmScheduler<F: SmStateFactory> {
    config: SmSchedulerConfig,
    factory: F,
    peers: HashMap<PeerId, PeerSm<F::GarblerState, F::EvaluatorState>>,
    job_handle: JobSchedulerHandle,
    net_client: NetClient,
    command_rx: kanal::AsyncReceiver<SmCommand>,
}
```

### Event Loop

Single-loop input multiplexing:

1. `job_handle.recv()` (tracked completion -> STF completion input)
2. `net_client.recv()` (protocol message -> STF event input)
3. `command_rx.recv()` (RPC command -> STF event input)

If any input source shuts down, scheduler exits cleanly.

### Input Routing

#### Protocol message -> role/input

| Message | Role | Input |
|---|---|---|
| `CommitHeader` | Evaluator | `RecvCommitMsgHeader` |
| `CommitChunk` | Evaluator | `RecvCommitMsgChunk` |
| `Challenge` | Garbler | `RecvChallengeMsg` |
| `ChallengeResponseHeader` | Evaluator | `RecvChallengeResponseMsgHeader` |
| `ChallengeResponseChunk` | Evaluator | `RecvChallengeResponseMsgChunk` |
| `AdaptorChunk` | Garbler | `DepositRecvAdaptorMsgChunk` |

#### Job completion -> role/completion

| Completion variant | Role | STF input |
|---|---|---|
| `ActionCompletion::Garbler` | Garbler | `TrackedActionCompleted { id, result }` |
| `ActionCompletion::Evaluator` | Evaluator | `TrackedActionCompleted { id, result }` |

### Action Submission

Every successful STF call emits zero or more tracked actions.

Runtime immediately submits them as:

```rust
JobBatch {
    peer_id,
    actions: JobActions::{Garbler|Evaluator}(container),
}
```

No local action buffering across STF calls.

## Protocol Ack Semantics

For incoming protocol requests:

1. receive stream + decode message
2. apply STF and persist state mutations
3. submit emitted actions
4. ack stream

Ack happens after successful STF application and state write path.

This gives at-least-once delivery semantics under crash/restart.

## Restore on Startup

On startup, runtime:

1. calls `factory.known_peers()`
2. creates per-peer garbler/evaluator handles
3. invokes `garbler_restore` + `evaluator_restore`
4. submits restored actions to job scheduler
5. inserts peer into active map

Restore failures are logged per peer; scheduler continues processing others.

## Storage Integration

The scheduler runtime is storage-backend agnostic behind `SmStateFactory`.

### In-memory (tests)

Factory returns in-memory `StoredGarblerState` / `StoredEvaluatorState` handles and peer enumeration from in-memory index.

### FDB/production

Factory returns FDB-backed `StateMut` handles scoped by peer and enumerates peer IDs from persisted prefixes.

## Atomicity

FASM requires STF atomicity.

- **Transactional storage (preferred production path):** one STF call scoped to one storage transaction.
- **In-memory test storage:** acceptable for tests/dev; failures should not partially commit externally visible state.

## Threading Model

| Component | Threading | Runtime |
|---|---|---|
| SM scheduler runtime | 1 thread | monoio |
| STF calls | on scheduler thread | monoio |
| Job scheduler | dedicated thread + worker pools | monoio |
| net-svc | dedicated thread | tokio |
| RPC server | service thread(s) | tokio |

Per-peer execution remains sequential because STF requires exclusive mutable state.

## Backpressure and Failure Behavior

### Backpressure

- Command channel bounded by `SmSchedulerConfig.command_queue_size`.
- Job submission channel bounded in `JobSchedulerConfig`.
- If job system slows, action submission awaits and naturally backpressures STF intake.

### Failure handling

- STF errors are logged with peer + role + input context; scheduler continues.
- Unknown peer completions/messages are logged and dropped.
- Job scheduler guarantees internal retries for transient execution failures.

## Testing Strategy

### Unit tests (runtime)

- message->role routing correctness
- completion->role routing correctness
- command handling and peer lifecycle
- restore path and action submission

### Integration tests

- end-to-end: protocol stream -> STF -> job batch -> completion -> STF
- scheduler restart with restore replay
- bounded-channel backpressure behavior

### Property/simulation tests (recommended)

- random event/completion ordering per peer
- invariant checks (no duplicate role routing, no cross-peer contamination)

## Migration Notes

1. Remove legacy `state-machine/executor` runtime role.
2. Move STF wrappers into `state-machine/scheduler` internal module.
3. Introduce `state-machine/scheduler-api` for public handle/command/config.
4. Update workspace members and crate deps accordingly.
5. Update references in docs/comments that still mention `StateMachineId`-based executor submission path.

## Deliverable Checklist (This Week)

1. `scheduler-api` crate created and integrated.
2. `scheduler` runtime crate created and integrated.
3. Internal STF wrappers implemented in runtime.
4. Startup restore implemented with `known_peers`.
5. Protocol + completion routing fully wired.
6. Lints/tests green in CI-equivalent local run.

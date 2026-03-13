# SM Executor & API

This document defines the target architecture for state machine execution in Mosaic.

The legacy split between thin `state-machine/executor` wrappers and separate orchestration logic is replaced by a single, fully-owned **SM executor** plus a small **executor API crate**.

The executor continues to execute FASM state machines (`GarblerSM`, `EvaluatorSM`) and delegates heavy compute/I/O actions to the job scheduler.

## Non-Negotiable Requirements

1. Correctness and soundness are primary. Throughput is secondary.
2. Per-peer and per-role execution must be deterministic and sequential.
3. No externally visible partial state commits are allowed.
4. Inbound protocol ack must happen only after durable state transition + action submission.
5. Bridge/RPC boundary must be strict and explicit (no silent coercions).
6. Unknown or malformed inputs must fail closed.

## Crate Structure

```text
crates/
├── sm-executor-api/  # Public command/handle/config types, stable integration boundary
└── sm-executor/      # Event loop, routing, STF, restore, submission
```

### Dependencies

**`sm-executor-api`**
- `mosaic-cac-types` (command payloads)
- `mosaic-net-svc-api::PeerId`
- `kanal`

**`sm-executor`**
- `sm-executor-api`
- `mosaic-cac-protocol` (`GarblerSM`, `EvaluatorSM`)
- `mosaic-cac-types` (inputs/action ids/results/messages)
- `mosaic-job-api` (`JobSchedulerHandle`, `JobBatch`, `JobCompletion`, `ActionCompletion`)
- `mosaic-net-client` / `mosaic-net-svc-api`
- `mosaic-storage-api` (`StorageProviderMut`, `Commit`)
- `fasm`
- `monoio`, `kanal`

## Why Executor + API Split

- Keep executor internals isolated from RPC/bridge crates.
- Keep executor public surface small and stable.
- Prevent monoio/FASM internals from leaking across crate boundaries.

## High-Level Architecture

```text
                    ┌────────────────────────────┐
                    │      Bridge Core (RPC)     │
                    └──────────────┬─────────────┘
                                   │ ExecutorCommand
                                   ▼
┌──────────────┐    ┌────────────────────────────┐    ┌──────────────────┐
│   net-svc    │───►│      SM Executor        │◄───│  JobScheduler    │
│ protocol     │    │                            │───►│                  │
│ streams      │    │ per-peer {garbler,eval}    │    │ JobBatch submit  │
└──────────────┘    │ STF call + commit + submit │    │ JobCompletion recv│
                    └─────────────┬──────────────┘    └──────────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │  Storage (StateMut+Commit) │
                    │  InMemory / FDB / kvstore  │
                    └────────────────────────────┘
```

## Boundary Policy (RPC and IDs)

### v1 execution targeting

Executor v1 targets by `{peer_id, role}` internally.

The executor API itself accepts explicit `{peer_id, role}` targets only.
If an upstream boundary (e.g. RPC adapter) carries additional identity fields,
that mapping/validation is handled upstream before constructing `SmCommand`.

## Executor API (`sm-executor-api`)

### Config

```rust
pub struct SmExecutorConfig {
    pub command_queue_size: usize,
    pub known_peers: Vec<PeerId>,
}
```

### Commands

```rust
pub enum SmRole {
    Garbler,
    Evaluator,
}

impl SmRole {
    pub const fn is_garbler(self) -> bool;
    pub const fn is_evaluator(self) -> bool;
}

pub struct SmTarget {
    pub peer_id: PeerId,
    pub role: SmRole,
}

pub struct SmCommand {
    pub target: SmTarget,
    pub kind: SmCommandKind,
}

pub enum SmCommandKind {
    Init(InitData),
    DepositInit {
        deposit_id: DepositId,
        data: DepositInitData,
    },
    DisputedWithdrawal {
        deposit_id: DepositId,
        data: DisputedWithdrawalData,
    },
    UndisputedWithdrawal {
        deposit_id: DepositId,
    },
}

pub enum InitData {
    Garbler(GarblerInitData),
    Evaluator(EvaluatorInitData),
}

pub enum DepositInitData {
    Garbler(GarblerDepositInitData),
    Evaluator(EvaluatorDepositInitData),
}

pub enum DisputedWithdrawalData {
    Garbler(WithdrawalInputs),
    Evaluator(EvaluatorDisputedWithdrawalData),
}

impl SmCommand {
    pub const fn role(&self) -> SmRole;
    pub fn peer_id(&self) -> &PeerId;
}
```

Command construction helpers must enforce role/payload pairing so invalid combinations are hard to construct.

### Handle

```rust
#[derive(Clone)]
pub struct SmExecutorHandle {
    command_tx: kanal::AsyncSender<SmCommand>,
}

impl SmExecutorHandle {
    pub async fn send(&self, cmd: SmCommand) -> Result<(), ExecutorStopped>;
}
```

## Executor Core (`sm-executor`)

### Core types

```rust
pub struct SmExecutor<S: StorageProviderMut> {
    config: SmExecutorConfig,
    storage: S,
    job_handle: JobSchedulerHandle,
    net_client: NetClient,
    command_rx: kanal::AsyncReceiver<SmCommand>,
}
```

No `Send`/`Sync` requirements are needed for mutable state handles on the single-thread monoio executor path.

### Event loop

Single loop multiplexing:

1. `job_handle.recv()`
2. `net_client.recv()`
3. `command_rx.recv()`

If any critical source shuts down, exit cleanly with explicit logging.

## STF Execution Model

For each event/completion/command:

1. Acquire mutable state session from storage provider.
2. Apply STF (`Normal` or `TrackedActionCompleted`).
3. Commit storage session.
4. Submit emitted tracked actions to job scheduler.
5. Ack inbound protocol request if applicable.

## Routing Matrix

### Protocol message -> role/input

| Message | Role | Input |
|---|---|---|
| `CommitHeader` | Evaluator | `RecvCommitMsgHeader` |
| `CommitChunk` | Evaluator | `RecvCommitMsgChunk` |
| `Challenge` | Garbler | `RecvChallengeMsg` |
| `ChallengeResponseHeader` | Evaluator | `RecvChallengeResponseMsgHeader` |
| `ChallengeResponseChunk` | Evaluator | `RecvChallengeResponseMsgChunk` |
| `AdaptorChunk` | Garbler | `DepositRecvAdaptorMsgChunk` |

### Bridge command -> role/input

| Command kind | Role | STF input |
|---|---|---|
| `Init` | Garbler | `garbler::Input::Init` |
| `Init` | Evaluator | `evaluator::Input::Init` |
| `DepositInit` | Garbler | `garbler::Input::DepositInit` |
| `DepositInit` | Evaluator | `evaluator::Input::DepositInit` |
| `UndisputedWithdrawal` | Garbler | `garbler::Input::DepositUndisputedWithdrawal` |
| `UndisputedWithdrawal` | Evaluator | `evaluator::Input::DepositUndisputedWithdrawal` |
| `DisputedWithdrawal` | Garbler | `garbler::Input::DisputedWithdrawal` |
| `DisputedWithdrawal` | Evaluator | `evaluator::Input::DisputedWithdrawal` |

### Job completion -> role/completion input

| Completion | Role | STF input |
|---|---|---|
| `ActionCompletion::Garbler` | Garbler | `TrackedActionCompleted { id, result }` |
| `ActionCompletion::Evaluator` | Evaluator | `TrackedActionCompleted { id, result }` |

## Critical Soundness Invariants

1. **Ordering invariant**: for a given `(peer_id, role)`, STF applications are strictly serial.
2. **Atomicity invariant**: no partial external commit from a failed STF application.
3. **Ack invariant**: inbound protocol message is acked only after `commit` and `submit_actions` succeed.
4. **Role isolation invariant**: garbler/evaluator completions can never cross-route.
5. **Peer isolation invariant**: no cross-peer state access from any routed input.
6. **Idempotence invariant**: crash/restart with at-least-once delivery cannot violate protocol safety.
7. **Restore invariant**: startup restore must only emit actions implied by persisted state.
8. **Validation invariant**: unsupported IDs, unknown peers, and malformed transitions fail closed.

## Security and Failure Model

### Fail-closed rules

- Invalid role/payload command combinations are rejected.
- Unknown peers/deposits are logged with context and dropped.
- Unsupported/unknown command or protocol paths are rejected with explicit context.
- Commit failures prevent ack and prevent success response.

### Recovery model

- Protocol ingress uses at-least-once semantics.
- Job scheduler performs internal retries for transient action failures.
- Executor restore replays pending work deterministically from persisted state.

### Required observability

Logs must be structured and clear about origin and purpose.

- Include `peer_id` and `role` wherever they are known.
- Include input/completion kind for routed work.
- Include `deposit_id` and `action_id` when available on that path.

## Startup Restore

On startup:

1. Iterate `config.known_peers`.
2. For each peer, run garbler restore and evaluator restore.
3. Submit restored actions immediately.
4. Continue across per-peer failures.

## Backpressure and Shutdown

- Command channel is bounded (`SmExecutorConfig`).
- Job submission channel remains bounded (`JobSchedulerConfig`).
- Natural backpressure is applied by awaiting submission.
- On channel closure, executor exits cleanly and explicitly.

## Single-PR Implementation Plan

All work lands in one PR, gated by correctness-first criteria.

### Workstream A: API and crate wiring

1. Add `sm-executor-api` and `sm-executor` crates.
2. Wire workspace members/dependencies.
3. Add `SmExecutorConfig`, `SmCommand`, `SmExecutorHandle`.

### Workstream B: storage/session correctness

1. Keep `Commit` in `storage-api`.
2. Ensure `StorageProviderMut` mutable handles satisfy `StateMut + Commit`.
3. Add no-op commit for in-memory handles.
4. Add mutable provider implementation for in-memory backend.

### Workstream C: executor and routing

1. Implement monoio single-loop executor event loop.
2. Implement protocol/command/completion routing tables.
3. Implement internal STF wrappers and commit boundary.
4. Implement startup restore.

### Workstream D: RPC integration

1. Bridge/RPC maps incoming requests to `{peer_id, role}` targets.
2. Any upstream identity validation/coercion happens before constructing `SmCommand`.
3. Map RPC operations to executor commands.

### Workstream E: protocol gap closure

1. Ensure adaptor chunk routing includes `deposit_id` end-to-end.
2. Remove any implicit assumption that single in-flight deposit is sufficient.

### Workstream F: removal of legacy path

1. Remove deprecated orchestration paths and stale executor wrappers.
2. Update docs and comments to use “SM executor” terminology.

## Verification Gates (Must Pass Before Merge)

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. Deterministic replay tests for restore.
5. Property/simulation tests for randomized interleavings per peer.
6. Negative tests for malformed routing, unknown peers, and role mismatches.
7. Ack-order tests proving “no ack before commit+submit”.
8. Crash-recovery test proving at-least-once safety.

No merge without all gates passing.

## Migration Notes

1. Introduce executor crates and wire all call sites.
2. Move STF wrapper logic under executor crate internals.
3. Replace “SM scheduler” terminology with “SM executor”.
4. Keep job scheduler terminology unchanged.
5. Remove obsolete paths after integration tests are green.

# SM Scheduler & Executor

The SM Scheduler runs garbler and evaluator state machines, routing protocol
messages and job completions to the correct SM, and submitting emitted actions
to the job system.

The SM Executor is a set of stateless functions that wrap FASM's STF. The
scheduler calls these to process inputs through the correct SM.

## Architecture

```
                    ┌──────────────────────────┐
                    │      Bridge Core (RPC)    │
                    └────────────┬─────────────┘
                                 │ SmCommand (init, deposit, withdrawal)
                                 ▼
┌──────────────┐    ┌──────────────────────────┐    ┌──────────────────┐
│   net-svc    │───►│      SmScheduler         │◄───│  JobScheduler    │
│              │    │                          │───►│                  │
│  protocol    │    │  Per-peer SM pairs:      │    │  JobBatch →      │
│  streams     │    │    garbler + evaluator   │    │  JobCompletion ← │
└──────────────┘    │                          │    └──────────────────┘
                    │  For each input:         │
                    │    executor::stf(state)   │
                    │    → emit JobBatch        │
                    └──────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  Storage (StateMut impls) │
                    │  FDB / InMemory          │
                    └──────────────────────────┘
```

## Crate Structure

```
crates/state-machine/
├── executor/    # Stateless STF wrapper functions (6 functions)
└── scheduler/   # Event loop, per-peer SM management, input multiplexing
```

**state-machine/executor** depends on:
- `mosaic-cac-protocol` (`GarblerSM`, `EvaluatorSM`)
- `mosaic-cac-types` (`Input`, `Action`, `StateRead`, `StateMut`)
- `fasm` (`StateMachine`, `Input`)

**state-machine/scheduler** depends on:
- `state-machine/executor`
- `mosaic-job-api` (`JobSchedulerHandle`, `JobBatch`, `JobCompletion`, `ActionCompletion`)
- `mosaic-net-svc-api` (`NetServiceHandle`, `PeerId`, `Stream`)
- `mosaic-cac-types` (garbler/evaluator `Input`, `StateMut`)
- `kanal`, `monoio`

## SM Executor

Thin, stateless wrapper around FASM. Six functions — two per concern (event,
completion, restore) × two roles (garbler, evaluator).

The executor does not manage storage. The `StateMut` handle IS the storage —
the executor just passes it to the STF. Whether the handle is in-memory
(`StoredGarblerState`) or FDB-backed is invisible to the executor.

### Functions

```rust
/// Process a garbler external event (protocol message, bridge command).
pub async fn garbler_handle_event<S: garbler::StateMut>(
    state: &mut S,
    input: garbler::Input,
) -> Result<garbler::ActionContainer, SMError>;

/// Process a garbler tracked action completion (job result).
pub async fn garbler_handle_completion<S: garbler::StateMut>(
    state: &mut S,
    id: garbler::ActionId,
    result: garbler::ActionResult,
) -> Result<garbler::ActionContainer, SMError>;

/// Restore garbler pending actions from persisted state (after crash).
pub async fn garbler_restore<S: garbler::StateMut>(
    state: &S,
) -> Result<garbler::ActionContainer, SMError>;

/// Process an evaluator external event.
pub async fn evaluator_handle_event<S: evaluator::StateMut>(
    state: &mut S,
    input: evaluator::Input,
) -> Result<evaluator::ActionContainer, SMError>;

/// Process an evaluator tracked action completion.
pub async fn evaluator_handle_completion<S: evaluator::StateMut>(
    state: &mut S,
    id: evaluator::ActionId,
    result: evaluator::ActionResult,
) -> Result<evaluator::ActionContainer, SMError>;

/// Restore evaluator pending actions from persisted state.
pub async fn evaluator_restore<S: evaluator::StateMut>(
    state: &S,
) -> Result<evaluator::ActionContainer, SMError>;
```

### Implementation

Each function is a thin wrapper around `GarblerSM::stf` / `EvaluatorSM::stf`:

```rust
pub async fn garbler_handle_event<S: garbler::StateMut>(
    state: &mut S,
    input: garbler::Input,
) -> Result<garbler::ActionContainer, SMError> {
    let mut actions = Vec::new();
    GarblerSM::<S>::stf(state, FasmInput::Normal(input), &mut actions).await?;
    Ok(actions)
}

pub async fn garbler_handle_completion<S: garbler::StateMut>(
    state: &mut S,
    id: garbler::ActionId,
    result: garbler::ActionResult,
) -> Result<garbler::ActionContainer, SMError> {
    let mut actions = Vec::new();
    GarblerSM::<S>::stf(
        state,
        FasmInput::TrackedActionCompleted { id, result },
        &mut actions,
    ).await?;
    Ok(actions)
}
```

No `Db` trait, no `ArtifactStore` wrapper, no `todo!()`. The old executor
pattern of load → STF → save is replaced by the `StateMut` impl handling
persistence internally on each `get_*` / `put_*` call.

## SM Scheduler

### Input Sources

The scheduler multiplexes three async input sources using `monoio::select!`:

| Source | Channel | Produces |
|--------|---------|----------|
| **net-svc** | `NetServiceHandle::protocol_streams()` | Protocol messages from peers |
| **Job system** | `JobSchedulerHandle::recv()` | Action completions (job results) |
| **RPC / Bridge Core** | `SmSchedulerHandle` (kanal) | Init, deposit, withdrawal commands |

### Types

```rust
// ════════════════════════════════════════════════════════════════════
// Config
// ════════════════════════════════════════════════════════════════════

pub struct SmSchedulerConfig {
    /// Capacity of the command channel (from RPC).
    pub command_queue_size: usize,
}

// ════════════════════════════════════════════════════════════════════
// State factory — creates per-peer StateMut handles
// ════════════════════════════════════════════════════════════════════

/// Creates garbler/evaluator StateMut handles for a given peer.
///
/// For in-memory: returns StoredGarblerState / StoredEvaluatorState.
/// For FDB: returns an FDB-backed handle keyed by peer_id.
pub trait SmStateFactory: Send + Sync + 'static {
    type GarblerState: garbler::StateMut + Send;
    type EvaluatorState: evaluator::StateMut + Send;

    fn garbler_state(&self, peer_id: &PeerId) -> Self::GarblerState;
    fn evaluator_state(&self, peer_id: &PeerId) -> Self::EvaluatorState;
}

// ════════════════════════════════════════════════════════════════════
// Per-peer SM pair
// ════════════════════════════════════════════════════════════════════

/// One garbler SM + one evaluator SM for a single peer.
struct PeerSm<GS, ES> {
    garbler: GS,
    evaluator: ES,
}

// ════════════════════════════════════════════════════════════════════
// Commands (from RPC / Bridge Core)
// ════════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════════
// Handle (for RPC to send commands)
// ════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct SmSchedulerHandle {
    command_tx: kanal::AsyncSender<SmCommand>,
}

impl SmSchedulerHandle {
    pub async fn send(&self, cmd: SmCommand) -> Result<(), SchedulerStopped> {
        self.command_tx.send(cmd).await.map_err(|_| SchedulerStopped)
    }
}
```

### Scheduler

```rust
pub struct SmScheduler<F: SmStateFactory> {
    config: SmSchedulerConfig,
    factory: F,
    /// Per-peer SM state handles, keyed by PeerId.
    peers: HashMap<PeerId, PeerSm<F::GarblerState, F::EvaluatorState>>,
    /// Job system interface (submit batches, receive completions).
    job_handle: JobSchedulerHandle,
    /// net-svc interface (receive protocol streams).
    net_handle: NetServiceHandle,
    /// Command channel from RPC / Bridge Core.
    command_rx: kanal::AsyncReceiver<SmCommand>,
}

impl<F: SmStateFactory> SmScheduler<F> {
    pub fn new(
        config: SmSchedulerConfig,
        factory: F,
        job_handle: JobSchedulerHandle,
        net_handle: NetServiceHandle,
    ) -> (Self, SmSchedulerHandle);

    /// Run on a dedicated monoio thread.
    pub fn run(self) -> std::thread::JoinHandle<()>;
}
```

### Event Loop

Uses `monoio::select!` to multiplex the three input sources:

```rust
async fn event_loop(mut self) {
    // On startup: restore all existing SMs from storage.
    self.restore_all().await;

    loop {
        monoio::select! {
            // Job completion — route back to originating SM.
            completion = self.job_handle.recv() => {
                match completion {
                    Ok(c) => self.handle_job_completion(c).await,
                    Err(_) => break, // Job system shut down.
                }
            }

            // Protocol message from a peer — route to correct SM.
            stream = self.net_handle.protocol_streams().recv() => {
                match stream {
                    Ok(s) => self.handle_protocol_message(s).await,
                    Err(_) => break, // net-svc shut down.
                }
            }

            // Command from RPC — init, deposit, withdrawal.
            cmd = self.command_rx.recv() => {
                match cmd {
                    Ok(c) => self.handle_command(c).await,
                    Err(_) => break, // RPC shut down.
                }
            }
        }
    }

    tracing::info!("SM scheduler shutting down");
}
```

### Input Handlers

#### Job Completion → SM

When the job system completes an action, route the result back to the
originating SM:

```rust
async fn handle_job_completion(&mut self, completion: JobCompletion) {
    let peer_id = completion.peer_id;
    let Some(peer) = self.peers.get_mut(&peer_id) else {
        tracing::warn!(?peer_id, "completion for unknown peer");
        return;
    };

    let batch = match completion.completion {
        ActionCompletion::Garbler { id, result } => {
            match executor::garbler_handle_completion(
                &mut peer.garbler, id, result,
            ).await {
                Ok(actions) => JobBatch {
                    peer_id,
                    actions: JobActions::Garbler(actions),
                },
                Err(e) => {
                    tracing::error!(?e, ?peer_id, "garbler STF error");
                    return;
                }
            }
        }
        ActionCompletion::Evaluator { id, result } => {
            match executor::evaluator_handle_completion(
                &mut peer.evaluator, id, result,
            ).await {
                Ok(actions) => JobBatch {
                    peer_id,
                    actions: JobActions::Evaluator(actions),
                },
                Err(e) => {
                    tracing::error!(?e, ?peer_id, "evaluator STF error");
                    return;
                }
            }
        }
    };

    // Submit emitted actions to job system.
    if !batch.is_empty() {
        if let Err(e) = self.job_handle.submit(batch).await {
            tracing::error!(?e, "job submission failed");
        }
    }
}
```

#### Protocol Message → SM

When a protocol message arrives from a peer, deserialize it, build the
appropriate SM `Input`, and route to the correct SM:

```rust
async fn handle_protocol_message(&mut self, mut stream: Stream) {
    let peer_id = stream.peer;

    // 1. Read and deserialize the protocol message.
    let msg = match read_and_deserialize(&mut stream).await {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!(?e, ?peer_id, "failed to read protocol message");
            return;
        }
    };

    // 2. Ensure peer SM exists.
    let Some(peer) = self.peers.get_mut(&peer_id) else {
        tracing::warn!(?peer_id, "message from unknown peer");
        return;
    };

    // 3. Route by message type to the correct SM.
    //
    // Garbler receives:  ChallengeMsg, AdaptorMsgChunk
    // Evaluator receives: CommitMsgHeader, CommitMsgChunk,
    //                     ChallengeResponseMsgHeader, ChallengeResponseMsgChunk
    let batch = match msg {
        Msg::ChallengeMsg(m) => {
            let input = garbler::Input::RecvChallengeMsg(m);
            match executor::garbler_handle_event(&mut peer.garbler, input).await {
                Ok(actions) => JobBatch {
                    peer_id,
                    actions: JobActions::Garbler(actions),
                },
                Err(e) => {
                    tracing::error!(?e, ?peer_id, "garbler STF error");
                    return;
                }
            }
        }
        Msg::CommitMsgHeader(m) => {
            let input = evaluator::Input::RecvCommitMsgHeader(m);
            match executor::evaluator_handle_event(&mut peer.evaluator, input).await {
                Ok(actions) => JobBatch {
                    peer_id,
                    actions: JobActions::Evaluator(actions),
                },
                Err(e) => {
                    tracing::error!(?e, ?peer_id, "evaluator STF error");
                    return;
                }
            }
        }
        // ... CommitMsgChunk, ChallengeResponseMsgHeader,
        //     ChallengeResponseMsgChunk, AdaptorMsgChunk
    };

    // 4. Ack the message (protocol streams require explicit ack).
    if let Err(e) = ack_stream(&mut stream).await {
        tracing::warn!(?e, ?peer_id, "failed to ack protocol message");
    }

    // 5. Submit emitted actions to job system.
    if !batch.is_empty() {
        if let Err(e) = self.job_handle.submit(batch).await {
            tracing::error!(?e, "job submission failed");
        }
    }
}
```

#### RPC Command → SM

When Bridge Core sends a command (init, deposit, withdrawal), create or
look up the peer SM and process:

```rust
async fn handle_command(&mut self, cmd: SmCommand) {
    match cmd {
        SmCommand::InitGarbler { peer_id, data } => {
            // Create fresh state handle from factory.
            let mut garbler_state = self.factory.garbler_state(&peer_id);
            let evaluator_state = self.factory.evaluator_state(&peer_id);

            match executor::garbler_handle_event(
                &mut garbler_state,
                garbler::Input::Init(data),
            ).await {
                Ok(actions) => {
                    self.peers.insert(peer_id, PeerSm {
                        garbler: garbler_state,
                        evaluator: evaluator_state,
                    });
                    let _ = self.job_handle.submit(JobBatch {
                        peer_id,
                        actions: JobActions::Garbler(actions),
                    }).await;
                }
                Err(e) => tracing::error!(?e, "garbler init failed"),
            }
        }

        SmCommand::InitEvaluator { peer_id, data } => {
            // Similar to InitGarbler but for evaluator.
            let garbler_state = self.factory.garbler_state(&peer_id);
            let mut evaluator_state = self.factory.evaluator_state(&peer_id);

            match executor::evaluator_handle_event(
                &mut evaluator_state,
                evaluator::Input::Init(data),
            ).await {
                Ok(actions) => {
                    self.peers.insert(peer_id, PeerSm {
                        garbler: garbler_state,
                        evaluator: evaluator_state,
                    });
                    let _ = self.job_handle.submit(JobBatch {
                        peer_id,
                        actions: JobActions::Evaluator(actions),
                    }).await;
                }
                Err(e) => tracing::error!(?e, "evaluator init failed"),
            }
        }

        SmCommand::DepositInitGarbler { peer_id, deposit_id, data } => {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::error!(?peer_id, "deposit init for unknown peer");
                return;
            };
            let input = garbler::Input::DepositInit(deposit_id, data);
            match executor::garbler_handle_event(&mut peer.garbler, input).await {
                Ok(actions) => {
                    let _ = self.job_handle.submit(JobBatch {
                        peer_id,
                        actions: JobActions::Garbler(actions),
                    }).await;
                }
                Err(e) => tracing::error!(?e, "garbler deposit init failed"),
            }
        }

        SmCommand::DisputedWithdrawal { peer_id, deposit_id, withdrawal_input } => {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::error!(?peer_id, "disputed withdrawal for unknown peer");
                return;
            };
            let input = garbler::Input::DisputedWithdrawal(deposit_id, withdrawal_input);
            match executor::garbler_handle_event(&mut peer.garbler, input).await {
                Ok(actions) => {
                    let _ = self.job_handle.submit(JobBatch {
                        peer_id,
                        actions: JobActions::Garbler(actions),
                    }).await;
                }
                Err(e) => tracing::error!(?e, "disputed withdrawal failed"),
            }
        }

        // ... UndisputedWithdrawal, DepositInitEvaluator
    }
}
```

### Restore on Startup

On startup, the scheduler loads all existing peer SMs from storage and
restores their pending actions:

```rust
async fn restore_all(&mut self) {
    // The state factory provides a way to enumerate known peers.
    // For each peer, create state handles, call restore, and submit actions.
    //
    // Note: the exact mechanism for enumerating peers depends on the storage
    // backend. For FDB, this might be a range scan on the peer key prefix.
    // For in-memory, it's the HashMap keys.

    for peer_id in self.factory.known_peers().await {
        let mut garbler_state = self.factory.garbler_state(&peer_id);
        let evaluator_state = self.factory.evaluator_state(&peer_id);

        // Restore garbler.
        match executor::garbler_restore(&garbler_state).await {
            Ok(actions) if !actions.is_empty() => {
                let _ = self.job_handle.submit(JobBatch {
                    peer_id,
                    actions: JobActions::Garbler(actions),
                }).await;
            }
            Err(e) => tracing::error!(?e, ?peer_id, "garbler restore failed"),
            _ => {}
        }

        // Restore evaluator.
        match executor::evaluator_restore(&evaluator_state).await {
            Ok(actions) if !actions.is_empty() => {
                let _ = self.job_handle.submit(JobBatch {
                    peer_id,
                    actions: JobActions::Evaluator(actions),
                }).await;
            }
            Err(e) => tracing::error!(?e, ?peer_id, "evaluator restore failed"),
            _ => {}
        }

        self.peers.insert(peer_id, PeerSm {
            garbler: garbler_state,
            evaluator: evaluator_state,
        });
    }
}
```

## Message Routing

Protocol messages are routed to the correct SM based on message type:

| Message | Recipient SM | SM Input variant |
|---------|-------------|-----------------|
| `CommitMsgHeader` | Evaluator | `Input::RecvCommitMsgHeader` |
| `CommitMsgChunk` | Evaluator | `Input::RecvCommitMsgChunk` |
| `ChallengeMsg` | Garbler | `Input::RecvChallengeMsg` |
| `ChallengeResponseMsgHeader` | Evaluator | `Input::RecvChallengeResponseMsgHeader` |
| `ChallengeResponseMsgChunk` | Evaluator | `Input::RecvChallengeResponseMsgChunk` |
| `AdaptorMsgChunk` | Garbler | `Input::DepositRecvAdaptorMsgChunk` |

Bridge Core commands are routed by the `SmCommand` variant which specifies
the role explicitly.

## Data Flow

### Setup Phase (per peer)

```
Bridge Core                SM Scheduler              Job System
    │                          │                          │
    ├─ InitGarbler ───────────►│                          │
    │                          ├─ garbler STF(Init)       │
    │                          ├─ JobBatch(G1×165) ──────►│  generate poly commitments
    │                          │                          │
    │                          │◄─ JobCompletion(G1) ─────┤
    │                          ├─ garbler STF(Complete)    │
    │                          │  ... (164 more G1s) ...  │
    │                          │                          │
    │                          ├─ JobBatch(G2×182) ──────►│  generate shares
    │                          │  ... completions ...     │
    │                          │                          │
    │                          ├─ JobBatch(G3×181) ──────►│  generate table commitments
    │                          │  ... completions ...     │
    │                          │                          │
    │                          ├─ JobBatch(G4,G5×164)───►│  send commit msg
    │                          │  ... acks ...            │
    │                          │                          │
    │              Evaluator receives CommitMsg from net   │
    │                          ├─ evaluator STF(Recv)     │
    │                          ├─ JobBatch(E1) ──────────►│  send challenge
    │                          │                          │
    │              Garbler receives ChallengeMsg from net  │
    │                          ├─ garbler STF(Recv)       │
    │                          ├─ JobBatch(G6,G7×174) ──►│  send challenge response
    │                          │  ... acks ...            │
    │                          │                          │
    │                          ├─ JobBatch(G8×7) ────────►│  transfer garbling tables
    │                          │                          │
```

### Deposit Phase

```
Bridge Core                SM Scheduler              Job System
    │                          │                          │
    ├─ DepositInitEvaluator ──►│                          │
    │                          ├─ evaluator STF(Deposit)  │
    │                          ├─ JobBatch(E5,E6×4) ────►│  generate adaptors
    │                          │  ... completions ...     │
    │                          ├─ JobBatch(E7×4) ────────►│  send adaptor chunks
    │                          │                          │
    │              Garbler receives AdaptorMsgChunks       │
    │                          ├─ garbler STF(Recv×4)     │
    │                          ├─ JobBatch(G9) ──────────►│  verify adaptors
    │                          │                          │
```

## Threading Model

| Component | Thread | Runtime |
|-----------|--------|---------|
| SM Scheduler event loop | 1 dedicated thread | monoio |
| SM STF execution | On scheduler thread (sequential per-SM, interleaved at await points) | monoio |
| Job light pool | 1 thread, 32 concurrency | monoio |
| Job heavy pool | 2 threads, 8 concurrency | monoio |
| Job garbling coordinator | 1 + N worker threads | monoio |
| net-svc | 1 dedicated thread | tokio |
| S3 TableStore | 1 dedicated thread | tokio |
| RPC server | Shared with net-svc or separate | tokio |

The SM Scheduler runs on a single monoio thread. SMs are sequential per-peer
(FASM requires exclusive `&mut State`), but multiple peers interleave at await
points. The STF itself is CPU-light (validation, state updates, action
emission). Heavy work (crypto, garbling, network I/O) is delegated to the job
system.

## Storage

### SmStateFactory

The scheduler needs `StateMut` handles for each peer. The `SmStateFactory`
trait abstracts over the storage backend:

```rust
pub trait SmStateFactory: Send + Sync + 'static {
    type GarblerState: garbler::StateMut + Send;
    type EvaluatorState: evaluator::StateMut + Send;

    fn garbler_state(&self, peer_id: &PeerId) -> Self::GarblerState;
    fn evaluator_state(&self, peer_id: &PeerId) -> Self::EvaluatorState;

    /// List all peers with persisted state (for restore on startup).
    fn known_peers(&self) -> impl Future<Output = Vec<PeerId>> + Send;
}
```

### In-Memory (Testing)

```rust
impl SmStateFactory for InMemoryStateFactory {
    type GarblerState = StoredGarblerState;       // from storage/inmemory
    type EvaluatorState = StoredEvaluatorState;   // from storage/inmemory
    // ...
}
```

### FDB (Production)

```rust
impl SmStateFactory for FdbStateFactory {
    type GarblerState = FdbGarblerState;
    type EvaluatorState = FdbEvaluatorState;

    fn garbler_state(&self, peer_id: &PeerId) -> FdbGarblerState {
        FdbGarblerState::new(self.db.clone(), *peer_id)
    }
    // ...
}
```

Where `FdbGarblerState` implements `garbler::StateMut` with each `get_*` /
`put_*` call performing an FDB read/write. This is Sapin's deliverable
(KvStore layer).

## Atomicity

FASM requires that the STF is atomic: if it returns `Err`, state must be
unchanged. Two approaches:

**Transactional (FDB)**: Each STF call runs within an FDB transaction. All
`put_*` calls are buffered. On success, the transaction commits atomically.
On error, it aborts and all writes are discarded.

**In-memory**: The `StoredGarblerState` / `StoredEvaluatorState` mutate
in-place. If the STF returns `Err`, the caller must discard the state and
reload. For testing this is fine; for production, the FDB transactional model
is preferred.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Executor is stateless functions, not a trait | No abstraction needed — just 6 wrapper functions. Testing uses in-memory `StateMut`. |
| Scheduler owns state handles in `HashMap<PeerId, PeerSm>` | SMs are sequential per-peer. Scheduler is the single owner. No concurrent access. |
| `SmStateFactory` for storage abstraction | Decouples scheduler from FDB specifics. Tests use in-memory. |
| Single monoio thread | STF is CPU-light. Heavy work goes to job system. One thread handles all peers. |
| `monoio::select!` for input multiplexing | Native async multiplexing — no polling, no busy loops. |
| Protocol message ack AFTER STF + state commit | Ensures at-least-once delivery. If the scheduler crashes before acking, the peer retransmits. |
| Actions submitted immediately after STF | No buffering. Each STF call emits actions that go straight to the job system. |
# Mosaic Architecture

Mosaic is the garbled circuits component of **Strata Bridge**, a Bitcoin ↔ Alpen L2 bridge with **1-of-N trust** (any single honest operator ensures correctness).

## Operator Stack

Each bridge operator runs three binaries:
- **Bridge Core** — Main bridge logic
- **Secret Service** — Key management for Bridge Core  
- **Mosaic** — Garbled circuit protocol (this repo)

Bridge Core communicates with Mosaic via private RPC.

## Mosaic Components

| Component | Runtime | Role |
|-----------|---------|------|
| SM Scheduler | monoio pool | Runs Garbler/Evaluator state machines (1 pair per peer) |
| JobScheduler | monoio | Routes actions to pools, manages requeue |
| Job Light Pool | monoio (1 thread) | Network I/O (sends, acks, bulk receives) |
| Job Heavy Pool | monoio (2 threads) | CPU-bound crypto (verification, polynomial ops, adaptors) |
| Garbling Coordinator | monoio (1+N threads) | Coordinated circuit reads + garbling/evaluation |
| net-svc | tokio (isolated) | P2P QUIC between Mosaic instances |
| S3TableStore | tokio (isolated) | Garbling table persistence via object_store |
| RpcService | tokio | Private API for Bridge Core |

## Message Flow

**Protocol messages** (CommitMsg, ChallengeMsg, etc.):
- Outgoing: SM → action → Job → net-svc → peer; job waits for ack
- Incoming: net-svc → SM Scheduler → SM input

**Bulk transfers** (garbling tables, ~43GB each):
- Outgoing: SM action → Job streams via net-svc
- Incoming: net-svc → JobScheduler → Job processes it

Key insight: Jobs handle all outgoing traffic. Incoming protocol messages go to SMs, but incoming bulk transfers go to Jobs.

## Crate Map

- `crates/cac/protocol/` — GarblerSM and EvaluatorSM implementations
- `crates/cac/types/` — Protocol message types, SM inputs/actions, StateRead/StateMut traits
- `crates/job/api/` — Executor traits (`ExecuteGarblerJob`, `ExecuteEvaluatorJob`), `CircuitSession`, `SessionFactory`, submission/completion types
- `crates/job/executors/` — `MosaicExecutor`, all 18 handler implementations, `GarblingSession`, `PolynomialCache`, circuit session types
- `crates/job/scheduler/` — `JobScheduler`, light/heavy pools, multi-threaded garbling coordinator, action classification, priority queue
- `crates/storage/api/` — `StorageProvider`, `StorageProviderMut`, `TableStore` traits
- `crates/storage/inmemory/` — In-memory `StateRead`/`StateMut` impl (testing)
- `crates/storage/s3/` — S3-backed `TableStore` via `object_store` + tokio bridge
- `crates/net/svc-api/` — Public API types for the network service (PeerId, Stream, config, handles)
- `crates/net/svc/` — QUIC networking service implementation (depends on svc-api)
- `crates/net/client/` — High-level typed client for protocol messages (depends on svc-api)
- `crates/net/wire/` — Wire format: length-prefixed framing (4 MiB max frame), stream headers
- `crates/vs3/` — Polynomial arithmetic, interpolation, commitments (VS3 scheme)
- `crates/adaptor-sigs/` — BIP-340 adaptor signature scheme (generate, verify, complete, extract)
- `crates/state-machine/` — FASM framework, executor (commented out of workspace)
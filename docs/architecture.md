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
| JobScheduler | monoio | Executes actions from SMs (crypto, I/O), returns results |
| net-svc | tokio (isolated) | P2P between Mosaic instances |
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
- `crates/cac/types/` — Protocol message types, SM inputs/actions
- `crates/net-svc/` — QUIC networking service
- `crates/net-wire/` — Wire format (framing, stream headers)
- `crates/net-types/` — Typed message layer (WIP)
- `crates/state-machine/` — FASM framework, executor
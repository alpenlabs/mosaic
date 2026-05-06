# Mosaic

Mosaic is the garbled-circuit component of [Strata Bridge](https://github.com/alpenlabs), a Bitcoin ↔ Alpen L2 bridge with **1-of-N trust** — a single honest operator suffices for correctness. Each bridge operator runs a Mosaic node alongside Bridge Core; Mosaic peers exchange garbling material over QUIC and execute the Mosaic protocol's Garbler and Evaluator state machines.

This repo contains the open-source reference implementation: the `mosaic` node binary, the protocol crates, and a functional-test harness.

> **Status:** pre-1.0. APIs and on-disk formats may change. Do not use in production yet.

## Repository layout

- `bin/mosaic` — node binary (composition root)
- `bin/mosaic-peer-id` — helper to generate Ed25519 signing keys / peer IDs
- `crates/cac/` — protocol state machines and message types
- `crates/job/` — job scheduler and executors (network I/O, crypto, garbling)
- `crates/net/` — QUIC transport and typed client
- `crates/storage/` — FoundationDB state store, S3/local table store
- `crates/vs3`, `crates/adaptor-sigs` — VS3 commitments, BIP-340 adaptor signatures
- `docker/` — Dockerfile and a 2-node `compose.yml` for local runs
- `functional-tests/` — Python-driven end-to-end tests
- `docs/` — deeper notes ([architecture](docs/architecture.md), [network](docs/network.md), [scheduler](docs/jobscheduler.md), [SM executor](docs/sm-executor.md))

## Run a local 2-node network (Docker)

The fastest way to see Mosaic running is the bundled compose file. It boots a FoundationDB instance plus two Mosaic nodes and wires them as peers.

```bash
cd docker
docker compose up -d --build
./init-fdb.sh           # one-time: configure the fresh FDB cluster
docker compose logs -f mosaic_1 mosaic_2
```

RPC is exposed on `127.0.0.1:8000` (node 1) and `127.0.0.1:8001` (node 2). To shut down:

```bash
docker compose down
```

The compose file mounts `artifacts/g16.v5c` as the circuit. Replace it with your own `.v5c` to run a different circuit.

## Build and run from source

### Prerequisites

- Rust **nightly** (`rustup toolchain install nightly`)
- FoundationDB **7.3.x** client library — install from the [FDB releases](https://github.com/apple/foundationdb/releases) (the `foundationdb-clients` package on Linux, the `.pkg` on macOS)
- A running FoundationDB cluster reachable via a `fdb.cluster` file
- A Mosaic circuit artifact (`.v5c`)

### Build

```bash
cargo build --release --bin mosaic
cargo build --release --bin mosaic-peer-id
```

### Generate a peer identity

Each node needs a 32-byte Ed25519 signing key. Its public key is the peer ID that other nodes use to address it.

```bash
./target/release/mosaic-peer-id
# signing_key_hex=...
# peer_id=...
```

### Configure

Copy [`bin/mosaic/config/config.example.toml`](bin/mosaic/config/config.example.toml) and fill in:

- `circuit.path` — path to your `.v5c` circuit
- `network.signing_key_hex` — this node's signing key (from `mosaic-peer-id`)
- `network.bind_addr` — QUIC listen address
- `[[network.peers]]` — one entry per other operator (`peer_id_hex` + `addr`)
- `storage.cluster_file` — path to your `fdb.cluster`
- `table_store` — `local_filesystem` (set `root`) or `s3_compatible` (set `bucket`, `region`, credentials)
- `rpc.bind_addr` — private RPC for Bridge Core

### Run

```bash
./target/release/mosaic path/to/config.toml
```

Logs go to stderr; level is controlled by `logging.filter` (env-filter syntax, e.g. `info,mosaic_job_scheduler=debug`). Send `SIGINT`/`SIGTERM` for clean shutdown.

## Tests

Unit tests:

```bash
cargo nextest run --workspace
```

End-to-end functional tests (spawn local FDB + Mosaic instances; require `fdbserver`, `fdbcli`, and [`uv`](https://docs.astral.sh/uv/)):

```bash
cd functional-tests
./run_tests.sh
```

See [`functional-tests/README.md`](functional-tests/README.md) for setup details.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: please email **security@alpenlabs.io** instead of opening a public issue ([SECURITY.md](SECURITY.md)).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

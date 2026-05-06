<div align="center">

# 🧩 Mosaic

### ✨ *The garbled-circuit engine powering the next generation of Bitcoin bridges* ✨

🔐 **Trust-minimized** &nbsp;•&nbsp; ⚡ **High-performance** &nbsp;•&nbsp; 🦀 **Built in Rust**

</div>

---

## 🌉 What is Mosaic?

**Mosaic** is the garbled-circuit component of [**Strata Bridge**](https://github.com/alpenlabs) — a cutting-edge Bitcoin ↔ Alpen L2 bridge featuring **🛡️ 1-of-N trust**: a *single* honest operator is enough to keep the bridge correct. 🎯

Every bridge operator runs a Mosaic node. Peers exchange garbling material over blazing-fast **QUIC** 🚀 and cooperate to execute Mosaic's **Garbler** and **Evaluator** state machines.

This repository is the **open-source reference implementation**, including:

- 📦 The `mosaic` node binary
- 🧪 The full set of protocol crates
- 🔬 A functional-test harness

> ⚠️ **Status:** pre-1.0. APIs and on-disk formats may change. Please do **not** use in production yet.

---

## 🗂️ Repository Layout

| Path | Description |
| :--- | :--- |
| 🚀 `bin/mosaic` | Node binary (composition root) |
| 🔑 `bin/mosaic-peer-id` | Helper to generate Ed25519 signing keys / peer IDs |
| 🧠 `crates/cac/` | Protocol state machines & message types |
| ⚙️ `crates/job/` | Job scheduler and executors (network I/O, crypto, garbling) |
| 🌐 `crates/net/` | QUIC transport and typed client |
| 💾 `crates/storage/` | FoundationDB state store, S3/local table store |
| ✍️ `crates/vs3`, `crates/adaptor-sigs` | VS3 commitments & BIP-340 adaptor signatures |
| 🐳 `docker/` | Dockerfile and a 2-node `compose.yml` for local runs |
| 🧪 `functional-tests/` | Python-driven end-to-end tests |
| 📚 `docs/` | Deep dives — [architecture](docs/architecture.md) · [network](docs/network.md) · [scheduler](docs/jobscheduler.md) · [SM executor](docs/sm-executor.md) |

---

## 🐳 Quickstart: Spin Up a Local 2-Node Network

The **fastest** way to see Mosaic in action is the bundled compose file. It boots a FoundationDB instance plus two Mosaic nodes and wires them up as peers — all with one command. 🪄

```bash
cd docker
docker compose up -d --build
./init-fdb.sh           # 🛠️  one-time: configure the fresh FDB cluster
docker compose logs -f mosaic_1 mosaic_2
```

🎉 **You're live!** RPC is exposed at:

- 🟢 `127.0.0.1:8000` — Node 1
- 🟣 `127.0.0.1:8001` — Node 2

To shut everything down cleanly:

```bash
docker compose down
```

> 💡 **Tip:** The compose file mounts `artifacts/g16.v5c` as the circuit. Drop in your own `.v5c` to run a different circuit.

---

## 🔧 Build and Run from Source

### 📋 Prerequisites

- 🦀 Rust **nightly** — `rustup toolchain install nightly`
- 🗄️ FoundationDB **7.3.x** client library — grab it from the [FDB releases](https://github.com/apple/foundationdb/releases) (the `foundationdb-clients` package on Linux, the `.pkg` installer on macOS)
- ☁️ A running FoundationDB cluster reachable via a `fdb.cluster` file
- 🧩 A Mosaic circuit artifact (`.v5c`)

### 🏗️ Build

```bash
cargo build --release --bin mosaic
cargo build --release --bin mosaic-peer-id
```

### 🆔 Generate a Peer Identity

Each node needs a 32-byte **Ed25519** signing key. The public key becomes the **peer ID** that other nodes use to address it. 📬

```bash
./target/release/mosaic-peer-id
# signing_key_hex=...
# peer_id=...
```

### ⚙️ Configure

Copy [`bin/mosaic/config/config.example.toml`](bin/mosaic/config/config.example.toml) and fill in:

- 🧩 `circuit.path` — path to your `.v5c` circuit
- 🔑 `network.signing_key_hex` — this node's signing key (from `mosaic-peer-id`)
- 📡 `network.bind_addr` — QUIC listen address
- 👥 `[[network.peers]]` — one entry per other operator (`peer_id_hex` + `addr`)
- 🗄️ `storage.cluster_file` — path to your `fdb.cluster`
- 📦 `table_store` — `local_filesystem` (set `root`) or `s3_compatible` (set `bucket`, `region`, credentials)
- 🔌 `rpc.bind_addr` — private RPC for Bridge Core

### ▶️ Run

```bash
./target/release/mosaic path/to/config.toml
```

📜 Logs go to **stderr**; level is controlled by `logging.filter` (env-filter syntax, e.g. `info,mosaic_job_scheduler=debug`). Send `SIGINT` / `SIGTERM` for clean shutdown. 👋

---

## 🧪 Tests

### 🔬 Unit Tests

```bash
cargo nextest run --workspace
```

### 🌐 End-to-End Functional Tests

Spawn local FDB + Mosaic instances. Requires `fdbserver`, `fdbcli`, and [`uv`](https://docs.astral.sh/uv/).

```bash
cd functional-tests
./run_tests.sh
```

📖 See [`functional-tests/README.md`](functional-tests/README.md) for setup details.

---

## 🤝 Contributing

We ❤️ contributions! Check out [**CONTRIBUTING.md**](CONTRIBUTING.md) to get started.

> 🔒 **Found a security issue?** Please email **[security@alpenlabs.io](mailto:security@alpenlabs.io)** instead of opening a public issue. See [SECURITY.md](SECURITY.md) for our full disclosure policy.

---

## 📜 License

Dual-licensed under [**MIT**](LICENSE-MIT) **or** [**Apache 2.0**](LICENSE-APACHE) — at your option. 🎈

<div align="center">

---

### 🧩 *Bridging Bitcoin, one garbled gate at a time.* 🧩

</div>

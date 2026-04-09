# Mosaic Tests

## Prerequisites

### `fdbserver` (FoundationDB)

The functional tests spawn FoundationDB server instances. You need both `fdbserver` and `fdbcli` binaries installed.

```bash
# for macOS (Apple Silicon)
curl -LO https://github.com/apple/foundationdb/releases/download/7.3.43/FoundationDB-7.3.43_arm64.pkg
sudo installer -pkg FoundationDB-7.3.43_arm64.pkg -target /

# for macOS (Intel)
curl -LO https://github.com/apple/foundationdb/releases/download/7.3.43/FoundationDB-7.3.43_x86_64.pkg
sudo installer -pkg FoundationDB-7.3.43_x86_64.pkg -target /
```

```bash
# for Linux (x86_64)
curl -fsSLO --proto "=https" --tlsv1.2 https://github.com/apple/foundationdb/releases/download/7.3.43/foundationdb-clients_7.3.43-1_amd64.deb
curl -fsSLO --proto "=https" --tlsv1.2 https://github.com/apple/foundationdb/releases/download/7.3.43/foundationdb-server_7.3.43-1_amd64.deb
sudo dpkg -i foundationdb-clients_7.3.43-1_amd64.deb
sudo dpkg -i foundationdb-server_7.3.43-1_amd64.deb
rm -f foundationdb-clients_7.3.43-1_amd64.deb foundationdb-server_7.3.43-1_amd64.deb
```

```bash
# check installed version
fdbcli --version
```

> **Note:** The functional tests share a single FDB server instance across all test
> environments. Each environment uses a unique root directory (e.g., `test-basic-a1b2c3d4`)
> within FDB's directory layer for isolation.

### `uv`

> [!NOTE]
> Make sure you have installed Python 3.10 or higher.

We use [`uv`](https://github.com/astral-sh/uv) for managing the test dependencies.

First, install `uv` following the instructions at <https://docs.astral.sh/uv/>.


Check, that `uv` is installed:

```bash
uv --version
```

Now you can run tests with:

```bash
uv run python entry.py
```


## Running tests
```bash
# Run all tests
./run_test.sh

# Run a specific test by path
./run_test.sh -t tests/fn_mosaic_setup.py

# Run all tests in a group (subdirectory)
./run_test.sh -g e2e

# Run multiple groups
./run_test.sh -g foo bar
```

## Debugging

### Service Logs
Logs are written in tests data directory:
```bash
🧪 functional-tests/
└── 📦 _dd/
    └── 🆔 <test_run_id>/            # Unique identifier for each test run
        ├── 🗄️ _shared_fdb/          # Shared FDB instance (one per test run)
        │   ├── 📄 service.log
        │   ├── 📄 fdb.cluster
        │   ├── 📁 data/             # FDB on-disk storage
        │   └── 📁 logs/             # FDB internal logs
        └── 🌍 <env_name>/           # Environment (e.g., "basic", "network")
            ├── 👷 <mosaic-i>/     # Mosaic instance (e.g., mosaic-0, mosaic-1)
            │   └── 📄 service.log
            └── 🧾 logs/              # Logs per test module
                └── 📄 fn_rpc_test.log
```

## Test Circuit

The custom [circuit](./functional-tests/artifacts/mosaic_depositidx_ckt.v5c) used in the functional tests mirrors the full circuit's input/output wire structure but with simplified logic: its output is determined entirely by the least significant bit (LSB) of the deposit inputs. This allows valid and invalid counter-proofs to be trivially simulated for tests by choosing odd or even deposit indices.

The circuit was generated from [g16@`2cc9a03`](https://github.com/alpenlabs/g16/commit/2cc9a03682833c68a2f64fa0098b0ec46f8d8a15).
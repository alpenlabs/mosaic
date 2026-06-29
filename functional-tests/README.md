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

The circuit was generated from [g16@`7779611`](https://github.com/alpenlabs/g16/commit/7779611ab3cbf69113dce0e0e22b48a721fca5d6).

This is the **same circuit** as the unit-test artifact at `artifacts/g16.v5c` (referenced from
`crates/cac/protocol/src/tests.rs`); the two files are byte-identical, just stored under different
names. See the regeneration steps in the comment above `tests::test_e2e` in that file. Because they
are the same artifact, both copies must be regenerated together whenever the `ckt` dependency is
bumped (e.g. a header-format change) — updating only one will pass unit tests but break the
functional tests (or vice versa). After regenerating, copy the resulting `g16.v5c` to both
`artifacts/g16.v5c` and `functional-tests/artifacts/mosaic_depositidx_ckt.v5c`.
#!/bin/bash
set -e
cd $(dirname $(realpath $0))
source env.bash

# Sets up PATH for built binaries.
setup_path() {
  # shellcheck disable=2155
  export PATH=$(realpath ../target/release/):$PATH
}

# Builds the binary.
build() {
    # --release: keep arc serialization time reasonable
    # -F reduced-circuits: use smaller number of circuits for tests 
    cargo build --release -F reduced-circuits --bin mosaic
}

# Runs tests.
run_tests() {
    uv sync
    uv run entry.py "$@"
}

setup_path
build
run_tests "$@"

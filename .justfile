# List all the available commands
default:
    just --list

# Fix Rust formatting
fmt:
    cargo fmt --all

# Fix TOML formatting with `taplo`
toml-fmt:
    taplo format

# Check Rust formatting (matches CI: lint.yml fmt job)
check-fmt:
    cargo fmt --all --check

# Rust `clippy` lints (matches CI: lint.yml clippy job — warnings are errors)
clippy:
    RUSTFLAGS="-D warnings" cargo clippy --workspace --examples --tests --benches --all-features --all-targets --locked

# TOML lint with `taplo` (matches CI: lint.yml taplo job)
toml-lint:
    taplo lint

# Check TOML formatting with `taplo` (matches CI: lint.yml taplo job)
toml-check-fmt:
    taplo format --check

# Check docs build without warnings (matches CI: docs.yml)
docs:
    RUSTDOCFLAGS="-A rustdoc::private-doc-tests -D warnings" cargo doc --no-deps

# Rust unit tests with `cargo-nextest` (matches CI: unit.yml test job)
unit-test:
    cargo --locked nextest run --all-features --workspace --release

# Rust documentation tests (matches CI: unit.yml doc job)
doctest:
    cargo test --doc --all-features

# Run all lints and formatting checks (matches CI: lint.yml)
lints: toml-check-fmt toml-lint check-fmt clippy

# Run all tests (matches CI: unit.yml)
test: unit-test doctest

# Run the full CI suite locally (lints + docs + tests)
ci: lints docs test

# Publish crate to crates.io
publish:
    cargo publish --token $CARGO_REGISTRY_TOKEN

# Check supply chain security analysis with `cargo-audit`
audit:
    cargo audit

# Check GitHub Actions security analysis with `zizmor`
check-github-actions-security:
    zizmor .

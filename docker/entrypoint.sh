#!/usr/bin/env bash
# Entrypoint for the mosaic Docker container.
#
# Expected volume mounts:
#   /etc/mosaic/config.toml  – mosaic configuration (TOML)
#   /etc/mosaic/circuit.v5c  – circuit artifact (v5c format)
#
# The config file's [circuit] section should reference:
#   path = "/etc/mosaic/circuit.v5c"
#
# Test-mode binary (built with --features=reduced-circuits): for CI/test
# environments only. This binary uses cut-and-choose parameters that are
# explicitly documented as insecure (see crates/common/src/constants.rs)
# and provides ~3 bits of challenge entropy versus the 40-bit production
# target. To enable it you must set BOTH:
#
#     MOSAIC_UNSAFE_TEST=1
#     MOSAIC_UNSAFE_TEST_I_UNDERSTAND_THIS_IS_NOT_PRODUCTION=1
#
# Setting only MOSAIC_UNSAFE_TEST=1 will refuse to start. The double-flag
# is a deliberate footgun mitigation: it prevents accidental enablement
# via a single environment-variable injection or a stray test config
# being copied into a production deploy.
#
# Any extra arguments are forwarded to the mosaic binary.

set -euo pipefail

CONFIG_PATH="${MOSAIC_CONFIG_PATH:-/etc/mosaic/config.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "ERROR: config file not found at $CONFIG_PATH" >&2
    echo "Mount config as a volume: -v /path/to/config.toml:$CONFIG_PATH:ro" >&2
    exit 1
fi

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
        *) return 1 ;;
    esac
}

MOSAIC_BIN="/usr/local/bin/mosaic"

if is_truthy "${MOSAIC_UNSAFE_TEST:-}"; then
    if ! is_truthy "${MOSAIC_UNSAFE_TEST_I_UNDERSTAND_THIS_IS_NOT_PRODUCTION:-}"; then
        cat >&2 <<'EOF'
ERROR: MOSAIC_UNSAFE_TEST=1 is set, but
       MOSAIC_UNSAFE_TEST_I_UNDERSTAND_THIS_IS_NOT_PRODUCTION is not.

The reduced-circuits binary uses cut-and-choose parameters that are
explicitly insecure (see crates/common/src/constants.rs) and must
NEVER be deployed in production. To run it intentionally for testing,
set both flags:

    MOSAIC_UNSAFE_TEST=1
    MOSAIC_UNSAFE_TEST_I_UNDERSTAND_THIS_IS_NOT_PRODUCTION=1

Refusing to start.
EOF
        exit 1
    fi

    cat >&2 <<'EOF'
================================================================================
WARNING: Running mosaic-unsafe-test (reduced-circuits build).

This binary uses test-only cut-and-choose parameters that provide ~3 bits
of challenge entropy instead of the 40-bit production target. It is NOT
SAFE for production use under any circumstances.

If you see this message in a production environment, stop the container
immediately and audit the deployment for environment-variable injection
or test-config contamination.
================================================================================
EOF
    MOSAIC_BIN="/usr/local/bin/mosaic-unsafe-test"
fi

exec "$MOSAIC_BIN" "$CONFIG_PATH" "$@"

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
# Set MOSAIC_UNSAFE_TEST=1 to run in test mode, which is faster.
# **WARNING**: Test mode is UNSAFE, and MUST NOT be used in production.
#
# Any extra arguments are forwarded to the mosaic binary.

set -euo pipefail

CONFIG_PATH="${MOSAIC_CONFIG_PATH:-/etc/mosaic/config.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "ERROR: config file not found at $CONFIG_PATH" >&2
    echo "Mount config as a volume: -v /path/to/config.toml:$CONFIG_PATH:ro" >&2
    exit 1
fi

MOSAIC_BIN="/usr/local/bin/mosaic"

case "${MOSAIC_UNSAFE_TEST:-}" in
    1|true|TRUE|yes|YES|on|ON)
        MOSAIC_BIN="/usr/local/bin/mosaic-unsafe-test"
        ;;
esac

exec "$MOSAIC_BIN" "$CONFIG_PATH" "$@"

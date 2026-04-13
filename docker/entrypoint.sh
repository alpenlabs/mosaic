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
# Set MOSAIC_REDUCED_CIRCUITS=1 to run the reduced-circuits build.
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

case "${MOSAIC_REDUCED_CIRCUITS:-}" in
    1|true|TRUE|yes|YES|on|ON)
        MOSAIC_BIN="/usr/local/bin/mosaic-reduced"
        ;;
esac

exec "$MOSAIC_BIN" "$CONFIG_PATH" "$@"

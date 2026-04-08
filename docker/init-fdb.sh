#!/usr/bin/env bash
# Initialize FoundationDB storage (idempotent - safe to run multiple times).
# Run this after `docker compose up` when starting with a fresh FDB instance.

set -euo pipefail

if docker compose exec -T foundationdb fdbcli --no-status --exec "status minimal" 2>/dev/null | grep -q "The database is available"; then
    echo "FoundationDB already configured, skipping..."
else
    docker compose exec -T foundationdb fdbcli --exec "configure new single ssd"
    echo -e "\n\033[36m======== FDB_INITIALIZED ========\033[0m\n"
fi

#!/bin/bash
# ==============================================================================
# SafeOps - Tier 1 Customer Collector Runner
# ==============================================================================
# Runs Tier 1 Customer Collector on its own dedicated port (default 8001)
# with its own dedicated database (collector_local.db), delivering outbound
# telemetry to the SaaS address specified in config/collector_config.json (or SAAS_URL).
# ==============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

exec ./start.sh collector

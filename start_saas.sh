#!/bin/bash
# ==============================================================================
# SafeOps - Tier 2 SaaS Platform Runner
# ==============================================================================
# Runs Tier 2 SaaS Cloud Platform on its own dedicated port (default 8002)
# with its own dedicated database (saas_cloud.db).
# Use this when running SaaS on a separate laptop or VM.
# ==============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

exec ./start.sh saas

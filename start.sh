#!/bin/bash
# ==============================================================================
# SafeOps - Single Command Startup Script (Mac & Linux)
# ==============================================================================
# Launches Tier 1 (Customer Collector) and Tier 2 (SaaS Cloud Platform) as
# separate processes on different ports, each with its own independent database.
#
# Usage:
#   ./start.sh            # Run both Collector (8001) and SaaS (8002) [Default]
#   ./start.sh both       # Run both processes
#   ./start.sh saas       # Run Tier 2 SaaS only (for SaaS laptop/host)
#   ./start.sh collector  # Run Tier 1 Collector only (for customer laptop/host)
# ==============================================================================

set -e

# Change directory to SafeOps root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${1:-both}"
COLLECTOR_PORT="${COLLECTOR_PORT:-8001}"
SAAS_PORT="${SAAS_PORT:-8002}"
COLLECTOR_HOST="${COLLECTOR_HOST:-0.0.0.0}"
SAAS_HOST="${SAAS_HOST:-0.0.0.0}"

echo "======================================================================"
echo "               SafeOps: Secure Two-Tier AIOps Platform                "
echo "======================================================================"

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required but was not found on your system."
    echo "Please install Python 3.11 or newer and try again."
    exit 1
fi

echo "[1/4] Checking Python virtual environment..."
if [ ! -d ".venv" ]; then
    echo "      Creating isolated Python virtual environment (.venv)..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# 2. Install dependencies
echo "[2/4] Verifying required Python packages..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

# 3. Clean shutdown handler
cleanup() {
    echo ""
    echo "======================================================================"
    echo "Shutting down SafeOps services..."
    if [ -n "$SAAS_PID" ]; then
        kill "$SAAS_PID" 2>/dev/null || true
    fi
    if [ -n "$COLLECTOR_PID" ]; then
        kill "$COLLECTOR_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    echo "All SafeOps services have been stopped safely. Goodbye!"
    echo "======================================================================"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Determine target SaaS address for collector
TARGET_SAAS_URL="${SAAS_URL:-$(python3 -c '
import json, os
try:
    with open("config/collector_config.json") as f:
        c = json.load(f)
    print(c.get("saas_url") or c.get("saas_address") or "http://127.0.0.1:8002")
except Exception:
    print("http://127.0.0.1:8002")
')}"

# Determine SSL parameters if self-signed cert exists
SAAS_SSL_ARGS=""
if [ -f "certs/cert.pem" ] && [ -f "certs/key.pem" ]; then
    SAAS_SSL_ARGS="--ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem"
fi

if [ "$MODE" = "saas" ]; then
    echo "[3/3] Starting Tier 2: SaaS Cloud Platform on port $SAAS_PORT (HTTPS Enabled)..."
    echo "      - Database: saas_cloud.db"
    echo "      - Listening on: $SAAS_HOST:$SAAS_PORT"
    echo ""
    echo "======================================================================"
    echo " Tier 2: SaaS Platform is RUNNING!"
    echo "======================================================================"
    echo "  -> Multi-Tenant Dashboard:  https://127.0.0.1:$SAAS_PORT/dashboard"
    echo "  -> AIOps & Remediation:     https://127.0.0.1:$SAAS_PORT/incidents"
    echo "  -> Reliability SLA Panel:   https://127.0.0.1:$SAAS_PORT/reliability"
    echo ""
    echo " To connect a Collector from a second laptop, set in config/collector_config.json:"
    echo "   \"saas_url\": \"https://<THIS_LAPTOP_IP>:$SAAS_PORT\""
    echo "======================================================================"
    exec python -m uvicorn tier2_saas.app:app --host "$SAAS_HOST" --port "$SAAS_PORT" $SAAS_SSL_ARGS

elif [ "$MODE" = "collector" ]; then
    echo "[3/3] Starting Tier 1: Customer Collector on port $COLLECTOR_PORT..."
    echo "      - Database: collector_local.db"
    echo "      - Configured SaaS Address: $TARGET_SAAS_URL"
    echo "      - Listening on: $COLLECTOR_HOST:$COLLECTOR_PORT"
    echo ""
    echo "======================================================================"
    echo " Tier 1: Customer Collector is RUNNING!"
    echo "======================================================================"
    echo "  -> Egress Proof Panel:      http://127.0.0.1:$COLLECTOR_PORT/egress"
    echo "  -> Chaos & Demo Controls:   http://127.0.0.1:$COLLECTOR_PORT/control"
    echo "  -> Outbound Target:         $TARGET_SAAS_URL"
    echo "======================================================================"
    exec python -m uvicorn tier1_collector.app:app --host "$COLLECTOR_HOST" --port "$COLLECTOR_PORT"

else
    # Default: Run BOTH as separate processes on different ports, each with own DB
    echo "[3/4] Launching Tier 2 SaaS Process (Port $SAAS_PORT, Database: saas_cloud.db, HTTPS Enabled)..."
    python -m uvicorn tier2_saas.app:app --host "$SAAS_HOST" --port "$SAAS_PORT" $SAAS_SSL_ARGS --log-level warning &
    SAAS_PID=$!

    # Wait briefly for Tier 2 to start listening
    sleep 1.5

    echo "[4/4] Launching Tier 1 Collector Process (Port $COLLECTOR_PORT, Database: collector_local.db)..."
    echo "      -> Target SaaS URL: $TARGET_SAAS_URL (from config/collector_config.json)"
    python -m uvicorn tier1_collector.app:app --host "$COLLECTOR_HOST" --port "$COLLECTOR_PORT" --log-level warning &
    COLLECTOR_PID=$!

    sleep 1.5

    echo ""
    echo "======================================================================"
    echo " SafeOps is now RUNNING as 2 Separate Processes!"
    echo "======================================================================"
    echo ""
    echo "  [Tier 1: Customer-Side Collector Process]"
    echo "  - Port:                     $COLLECTOR_PORT"
    echo "  - Database:                 collector_local.db (independent)"
    echo "  - Configured SaaS Target:   $TARGET_SAAS_URL"
    echo "  - Egress Proof Panel:       http://127.0.0.1:$COLLECTOR_PORT/egress"
    echo "  - Chaos & Demo Controls:    http://127.0.0.1:$COLLECTOR_PORT/control"
    echo ""
    echo "  [Tier 2: Cloud-Side SaaS Platform Process]"
    echo "  - Port:                     $SAAS_PORT"
    echo "  - Database:                 saas_cloud.db (independent)"
    echo "  - Multi-Tenant Dashboard:   https://127.0.0.1:$SAAS_PORT/dashboard"
    echo "  - AIOps & Remediation:      https://127.0.0.1:$SAAS_PORT/incidents"
    echo "  - Reliability SLA Panel:    https://127.0.0.1:$SAAS_PORT/reliability"
    echo ""
    echo "  [Multi-Laptop Note]"
    echo "  To move Tier 2 SaaS to a second laptop:"
    echo "  1. On Laptop 2: Run ./start.sh saas"
    echo "  2. On Laptop 1: In config/collector_config.json, set:"
    echo "       \"saas_url\": \"http://<LAPTOP_2_IP>:$SAAS_PORT\""
    echo "     (or: export SAAS_URL=\"http://<LAPTOP_2_IP>:$SAAS_PORT\")"
    echo "     Then run ./start.sh collector"
    echo "======================================================================"
    echo " Press Ctrl+C at any time to gracefully stop all services."
    echo "======================================================================"

    wait $SAAS_PID $COLLECTOR_PID
fi

#!/bin/bash
# ==============================================================================
# SafeOps - Graceful Backend Shutdown Script
# ==============================================================================
echo "Stopping SafeOps backend processes on ports 8001 and 8002..."

PIDS=$(lsof -t -i:8001 -i:8002 2>/dev/null || true)

if [ -n "$PIDS" ]; then
    echo "Terminating process IDs: $PIDS"
    kill -TERM $PIDS 2>/dev/null || true
    sleep 1
    # Force kill any stubborn remaining process
    REMAINING=$(lsof -t -i:8001 -i:8002 2>/dev/null || true)
    if [ -n "$REMAINING" ]; then
        kill -9 $REMAINING 2>/dev/null || true
    fi
    echo "[OK] SafeOps Tier 1 (Port 8001) and Tier 2 (Port 8002) have been stopped."
else
    echo "[INFO] No SafeOps backend processes found running on port 8001 or 8002."
fi

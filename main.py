"""
SafeOps - Unified Serverless Entrypoint for Cloud Deployments (Vercel)
======================================================================
Mounts Tier 2 SaaS Platform (Dashboard, Incidents, Reliability SLA, APIs)
and Tier 1 Collector Panels (Egress Proof, Demo Control) into a single FastAPI instance.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

# Ensure SQLite databases write to writable /tmp directory in serverless environments
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    os.environ.setdefault("SAAS_DB_PATH", "/tmp/saas_cloud.db")
    os.environ.setdefault("COLLECTOR_DB_PATH", "/tmp/collector_local.db")

from tier2_saas.app import app as saas_app
from tier1_collector.app import app as collector_app

app = FastAPI(title="SafeOps Unified Cloud Platform")

# Copy routes from Tier 2 SaaS
for route in saas_app.routes:
    app.routes.append(route)

# Copy routes from Tier 1 Collector (egress, control, chaos endpoints) without colliding
saas_paths = {r.path for r in saas_app.routes}
for route in collector_app.routes:
    if route.path not in saas_paths:
        app.routes.append(route)

"""
SafeOps - SaaS Cloud Web Server (Tier 2 Cloud Side)
===================================================
FastAPI application running on port 8002.
Provides:
1. Ingestion endpoint (/api/v1/ingest) with API key auth and deduplication by payload_id
2. Heartbeat beacon receiver (/api/v1/heartbeat) for collector offline detection (60s)
3. Multi-Tenant Dashboard (Tenant A vs Tenant B isolation)
4. AIOps Anomaly, Correlation & Explainable Remediation Engine
5. Live Reliability & SLA Verification Panel (p95 latency, zero loss, zero dupes)
"""

import datetime
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from tier2_saas.aiops_engine import AIOpsEngine
from tier2_saas.auth import verify_collector_api_key
from tier2_saas.health_engine import HealthEngine
from tier2_saas.storage import SaaSStorage

# Initialize SaaS services with dedicated database
default_saas_db = "/tmp/saas_cloud.db" if os.environ.get("VERCEL") else "saas_cloud.db"
SAAS_DB_PATH = os.environ.get("SAAS_DB_PATH", default_saas_db)
SAAS_REGION = os.environ.get("SAAS_REGION", "us-east-1")
STORAGE = SaaSStorage(SAAS_DB_PATH)
HEALTH_ENGINE = HealthEngine(STORAGE)
AIOPS_ENGINE = AIOpsEngine(STORAGE, correlation_window_sec=120.0, zscore_threshold=3.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    saas_port = os.environ.get("SAAS_PORT", "8002")
    print("=" * 60)
    print(f"Starting SafeOps Tier 2 SaaS Cloud Platform on port {saas_port}")
    print(f"Server Assigned Region: {SAAS_REGION}")
    print(f"Using Dedicated SaaS Database: {SAAS_DB_PATH}")
    print("Multi-Tenant Isolation & Data Residency: Active")
    print("AIOps Anomaly Correlation Engine: Active")
    print("=" * 60)
    yield
    print("SafeOps Tier 2 SaaS Platform stopped.")


app = FastAPI(title="SafeOps Tier 2 SaaS Platform", lifespan=lifespan)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


# ==========================================
# Ingestion & Heartbeat Endpoints
# ==========================================

@app.post("/api/v1/ingest")
async def ingest_telemetry_batch(
    payloads: List[Dict[str, Any]] = Body(...),
    response: Response = None,
    authenticated_tenant: str = Depends(verify_collector_api_key)
):
    """
    Tier 2 Ingestion Endpoint:
    1. Validates API key and tenant mapping.
    2. De-duplicates by payload_id (Idempotent delivery).
    3. Evaluates health states and logs state changes.
    4. Passes to AIOps engine for anomaly detection and 2-min correlation.
    """
    if response:
        response.headers["X-Processed-Region"] = SAAS_REGION

    arrival_ts = time.time()
    arrival_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    inserted_count = 0
    duplicate_count = 0

    for p in payloads:
        tenant_id = p.get("tenant_id")
        if tenant_id != authenticated_tenant:
            # Prevent tenant spoofing inside batch
            continue

        # Evaluate threshold health & reason
        computed_health, reason = HEALTH_ENGINE.evaluate_payload_health(p)
        p["health_state"] = computed_health
        p["short_context"] = reason

        # Deduplicate and store sorted by event_time_utc (Out-of-order handling)
        inserted, status = STORAGE.ingest_payload(p, arrival_utc, arrival_ts)

        if inserted:
            inserted_count += 1
            # Check for health state change history
            HEALTH_ENGINE.check_state_transition(p, computed_health, reason)
            # Run through AIOps Anomaly & Correlation Engine
            AIOPS_ENGINE.process_incoming_metric(p)
        else:
            duplicate_count += 1

    return JSONResponse(
        content={
            "status": "success",
            "inserted": inserted_count,
            "duplicates_rejected": duplicate_count,
            "processed_region": SAAS_REGION
        },
        headers={"X-Processed-Region": SAAS_REGION},
        status_code=200
    )


@app.post("/api/v1/heartbeat")
async def receive_heartbeat(
    hb_data: Dict[str, Any] = Body(...),
    response: Response = None,
    authenticated_tenant: str = Depends(verify_collector_api_key)
):
    """Stores collector health beacon. Checked for 60s offline timeout."""
    if response:
        response.headers["X-Processed-Region"] = SAAS_REGION
    hb_data["tenant_id"] = authenticated_tenant
    STORAGE.update_heartbeat(hb_data)

    # Process any recovery confirmations returned by collector
    confirmations = hb_data.get("remediation_confirmations", [])
    for conf in confirmations:
        inc_id = conf.get("incident_id")
        t_id = conf.get("tenant_id") or authenticated_tenant
        conf_time = conf.get("confirmed_at_utc", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        STORAGE.mark_remediation_confirmed(inc_id, t_id, conf_time)
        STORAGE.log_remediation_action({
            "incident_id": inc_id,
            "tenant_id": t_id,
            "action_name": f"confirm_{conf.get('action', 'fix')}",
            "status": "CONFIRMED",
            "policy_check": "RECOVERY CONFIRMED: Collector verified local chaos cleared and normal telemetry restored",
            "operator": "CollectorDaemon",
            "details": {
                "source_id": conf.get("source_id"),
                "confirmed_at_utc": conf_time,
                "message": f"Recovery confirmed by collector at {conf_time}"
            }
        })

    # Retrieve any pending approved actions to return in heartbeat response for collector pull
    pending_actions = STORAGE.get_pending_remediations(authenticated_tenant)

    return JSONResponse(
        content={
            "status": "acknowledged",
            "processed_region": SAAS_REGION,
            "pending_approved_actions": pending_actions
        },
        headers={"X-Processed-Region": SAAS_REGION}
    )


# ==========================================
# Web UI Endpoints
# ==========================================

@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    html_file = os.path.join(TEMPLATES_DIR, "dashboard.html")
    with open(html_file, "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page():
    html_file = os.path.join(TEMPLATES_DIR, "incidents.html")
    with open(html_file, "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/reliability", response_class=HTMLResponse)
async def reliability_page():
    html_file = os.path.join(TEMPLATES_DIR, "reliability.html")
    with open(html_file, "r") as f:
        return HTMLResponse(content=f.read())


# ==========================================
# Frontend JSON APIs (Multi-Tenant Isolated)
# ==========================================

@app.get("/api/v1/dashboard/data")
async def get_dashboard_data(tenant_id: str = "tenant-a"):
    """Returns strictly tenant-filtered host metrics, health states, and state change history."""
    col_status = STORAGE.get_collector_status(tenant_id)
    hosts_map = STORAGE.get_latest_metrics_per_source(tenant_id)
    residency = STORAGE.get_tenant_residency(tenant_id)

    # Check for stale data (>30s)
    HEALTH_ENGINE.check_stale_data_for_hosts(tenant_id, hosts_map)

    # Compute overview tallies
    total_hosts = len(hosts_map)
    healthy_hosts = sum(1 for h in hosts_map.values() if h.get("overall_health") in ("EXCELLENT", "GOOD"))
    fair_hosts = sum(1 for h in hosts_map.values() if h.get("overall_health") == "FAIR")
    poor_hosts = sum(1 for h in hosts_map.values() if h.get("overall_health") == "POOR")
    has_stale = any(h.get("is_stale") for h in hosts_map.values())

    history = STORAGE.get_state_change_history(tenant_id, limit=25)
    reliability = STORAGE.get_reliability_stats(tenant_id)

    return JSONResponse(content={
        "tenant_id": tenant_id,
        "collector_status": col_status,
        "residency": residency,
        "server_region": SAAS_REGION,
        "reliability": reliability,
        "overview": {
            "total_hosts": total_hosts,
            "healthy_hosts": healthy_hosts,
            "fair_hosts": fair_hosts,
            "poor_hosts": poor_hosts,
            "has_stale_data": has_stale
        },
        "hosts": hosts_map,
        "history": history
    })


@app.get("/api/v1/residency/status")
async def get_residency_status():
    """Returns active SaaS server region, registered tenant residency boundaries, and audit log."""
    policies = STORAGE.get_all_residency_policies()
    audits = STORAGE.get_residency_audit_log(limit=25)
    return JSONResponse(content={
        "server_region": SAAS_REGION,
        "policies": policies,
        "recent_audits": audits
    })


@app.post("/api/v1/residency/replicate")
async def test_cross_region_replication(payload: Dict[str, Any] = Body(...)):
    """
    Verifies tenant data residency boundary:
    Attempts to replicate tenant metadata or telemetry across regions.
    Blocked with 403 Forbidden unless a verified policy approval token is presented.
    """
    tenant_id = payload.get("tenant_id")
    target_region = payload.get("target_region")
    policy_token = payload.get("policy_approval_token")
    operator = payload.get("operator", "AuditOperator")

    if not tenant_id or not target_region:
        raise HTTPException(status_code=400, detail="Missing 'tenant_id' or 'target_region' in payload")

    allowed, message = STORAGE.check_and_log_replication(tenant_id, target_region, policy_token, operator)
    if not allowed:
        return JSONResponse(content={
            "status": "BLOCKED",
            "decision": "DENIED",
            "policy_violation": True,
            "detail": message
        }, status_code=403)

    return JSONResponse(content={
        "status": "APPROVED",
        "decision": "PERMITTED",
        "policy_violation": False,
        "detail": message
    }, status_code=200)


@app.get("/api/v1/incidents/data")
async def get_incidents_data(tenant_id: str = "tenant-a"):
    """Returns correlated AIOps incidents and safe remediation audit logs."""
    incidents = STORAGE.get_incidents(tenant_id)
    audit = STORAGE.get_remediation_audit(tenant_id)
    return JSONResponse(content={
        "tenant_id": tenant_id,
        "incidents": incidents,
        "audit": audit
    })


@app.post("/api/v1/incidents/remediate")
async def remediate_incident(payload: Dict[str, Any] = Body(...)):
    """Executes safe remediation with policy check and audit logging."""
    incident_id = payload.get("incident_id")
    tenant_id = payload.get("tenant_id")
    action = payload.get("action", "approved_fix")
    operator = payload.get("operator", "DemoUser")

    if not incident_id or not tenant_id:
        raise HTTPException(status_code=400, detail="Missing incident_id or tenant_id")

    res = AIOPS_ENGINE.execute_remediation(incident_id, tenant_id, action, operator)
    return JSONResponse(content=res)


@app.post("/api/v1/incidents/rollback")
async def rollback_incident(payload: Dict[str, Any] = Body(...)):
    """Rolls back applied remediation."""
    incident_id = payload.get("incident_id")
    tenant_id = payload.get("tenant_id")
    operator = payload.get("operator", "DemoUser")

    if not incident_id or not tenant_id:
        raise HTTPException(status_code=400, detail="Missing incident_id or tenant_id")

    res = AIOPS_ENGINE.rollback_remediation(incident_id, tenant_id, operator)
    return JSONResponse(content=res)


@app.get("/api/v1/reliability/data")
async def get_reliability_data(tenant_id: str = "tenant-a"):
    """Returns live SLA audit accounting: p95 latency, duplicates rejected, loss=0."""
    stats = STORAGE.get_reliability_stats(tenant_id)
    stats["server_region"] = SAAS_REGION
    return JSONResponse(content=stats)


@app.post("/api/v1/control/reset")
async def reset_demo_data_endpoint():
    """Clears all telemetry, incidents, counters, and audit trails from SaaS database."""
    STORAGE.reset_database()
    AIOPS_ENGINE.metric_history.clear()
    return JSONResponse(content={
        "status": "success",
        "message": "SaaS cloud database and AIOps caches cleared."
    })


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("SAAS_HOST", "0.0.0.0")
    port = int(os.environ.get("SAAS_PORT", 8002))
    uvicorn.run("tier2_saas.app:app", host=host, port=port, reload=False)

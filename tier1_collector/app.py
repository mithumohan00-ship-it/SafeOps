"""
SafeOps - Collector Web Server (Tier 1 Customer Side)
=====================================================
FastAPI application running on port 8001.
Provides:
1. Egress Proof Panel (side-by-side raw input vs sanitized egress JSON)
2. Chaos & Demo Control Page (buttons for 8 judge scenarios)
3. Background telemetry collection loop (every 2 seconds)
4. Outbound resilient buffer sender with backoff and heartbeat to Tier 2
5. External HTTP adapter endpoint (/api/v1/adapter/push) for custom organizer streams
"""

import asyncio
import datetime
import json
import os
import re
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from tier1_collector.adapters import UniversalFeedAdapter
from tier1_collector.buffer_sender import BufferSender
from tier1_collector.pipeline import CollectorPipeline
from tier1_collector.storage import CollectorStorage

# Load configuration
CONFIG_PATH = os.environ.get("COLLECTOR_CONFIG_PATH") or os.path.join(os.path.dirname(__file__), "..", "config", "collector_config.json")
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as f:
        COLLECTOR_CONFIG = json.load(f)
else:
    COLLECTOR_CONFIG = {}

# Check for environment variable overrides for SaaS address
env_saas = os.environ.get("SAAS_URL") or os.environ.get("SAAS_ADDRESS") or os.environ.get("SAFEOPS_SAAS_URL")
if env_saas:
    COLLECTOR_CONFIG["saas_url"] = env_saas

# Normalize SaaS URL config
saas_url = COLLECTOR_CONFIG.get("saas_url") or COLLECTOR_CONFIG.get("saas_address") or "http://127.0.0.1:8002"
if not saas_url.startswith(("http://", "https://")):
    saas_url = f"http://{saas_url}"
COLLECTOR_CONFIG["saas_url"] = saas_url.rstrip("/")

# Initialize Dedicated Collector Storage (separate database)
default_col_db = "/tmp/collector_local.db" if os.environ.get("VERCEL") else "collector_local.db"
COLLECTOR_DB_PATH = "/tmp/collector_local.db" if os.environ.get("VERCEL") else (os.environ.get("COLLECTOR_DB_PATH") or COLLECTOR_CONFIG.get("db_path", "collector_local.db"))
STORAGE = CollectorStorage(COLLECTOR_DB_PATH)
ADAPTER = UniversalFeedAdapter(COLLECTOR_CONFIG)
PIPELINE = CollectorPipeline(salt=COLLECTOR_CONFIG.get("pseudonym_salt", "safeops_salt"))
BUFFER_SENDER = BufferSender(COLLECTOR_CONFIG, STORAGE, ADAPTER)

# Global flag to control background collector loop
IS_COLLECTOR_RUNNING = True


async def background_collector_loop():
    """Fetches telemetry every 2 seconds, filters, redacts, pseudonymizes, and buffers."""
    interval = COLLECTOR_CONFIG.get("collect_interval_seconds", 2.0)
    while IS_COLLECTOR_RUNNING:
        try:
            # Fetch from active input adapter (Simulator, JSON Lines, CSV, Syslog, or HTTP)
            records = ADAPTER.fetch_records()

            for raw_record in records:
                # Local isolation: Store raw event with full logs & ambient secrets
                raw_id = STORAGE.store_raw_event(raw_record)

                # Execute Zero-Trust Pipeline: Filter, Redact, Pseudonymize, Local Analysis, Allow-List
                egress_payloads = PIPELINE.process_raw_record(raw_record)

                # Enqueue into durable outbound SQLite buffer
                for payload in egress_payloads:
                    STORAGE.enqueue_payload(raw_id, payload)

            await asyncio.sleep(interval)
        except Exception as e:
            print(f"[Collector Loop Error]: {e}")
            await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    col_port = os.environ.get("COLLECTOR_PORT", "8001")
    print("=" * 60)
    print(f"Starting SafeOps Tier 1 Customer Collector on port {col_port}")
    print(f"Targeting Tier 2 SaaS Platform at: {BUFFER_SENDER.saas_url}")
    print(f"Using Dedicated Collector Database: {COLLECTOR_DB_PATH}")
    print("Zero-Trust Pipeline: Active")
    print("=" * 60)

    # Start sender worker (heartbeat & HTTP delivery)
    await BUFFER_SENDER.start()

    # Start telemetry collection loop
    collector_task = asyncio.create_task(background_collector_loop())

    yield

    # Shutdown tasks
    global IS_COLLECTOR_RUNNING
    IS_COLLECTOR_RUNNING = False
    collector_task.cancel()
    await BUFFER_SENDER.stop()
    print("SafeOps Tier 1 Customer Collector stopped.")


app = FastAPI(title="SafeOps Tier 1 Collector", lifespan=lifespan)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


# ==========================================
# UI Endpoints
# ==========================================

@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/egress")


@app.get("/egress", response_class=HTMLResponse)
async def egress_proof_page():
    """Serves the Egress Proof Panel web page."""
    html_file = os.path.join(TEMPLATES_DIR, "egress.html")
    with open(html_file, "r") as f:
        content = f.read()
    # Dynamically inject the configured SaaS address into navigation links
    content = content.replace("http://127.0.0.1:8002", BUFFER_SENDER.saas_url)
    return HTMLResponse(content=content)


@app.get("/control", response_class=HTMLResponse)
async def chaos_control_page():
    """Serves the Chaos & Demo Control Page."""
    html_file = os.path.join(TEMPLATES_DIR, "control.html")
    with open(html_file, "r") as f:
        content = f.read()
    # Dynamically inject the configured SaaS address into navigation links
    content = content.replace("http://127.0.0.1:8002", BUFFER_SENDER.saas_url)
    return HTMLResponse(content=content)


# ==========================================
# API Endpoints
# ==========================================

@app.get("/api/v1/egress/data")
async def get_egress_data(search: str = "", limit: int = 40):
    """Returns side-by-side raw input vs sanitized egress payload pairs + live buffer stats."""
    pairs = STORAGE.get_egress_pairs(search=search, limit=limit)
    stats = STORAGE.get_buffer_stats()
    stats["saas_url"] = BUFFER_SENDER.saas_url
    return JSONResponse(content={"stats": stats, "pairs": pairs, "saas_url": BUFFER_SENDER.saas_url})


@app.get("/api/v1/egress/reconciliation")
async def get_egress_reconciliation(tenant_id: str = "tenant-a"):
    """Returns exact list of sent and pending payload IDs for mathematical reconciliation."""
    sent_ids = STORAGE.get_tenant_sent_payload_ids(tenant_id)
    pending_ids = STORAGE.get_tenant_pending_payload_ids(tenant_id)
    stats = STORAGE.get_tenant_buffer_stats(tenant_id)
    return JSONResponse(content={
        "tenant_id": tenant_id,
        "sent_count": stats.get("total_sent_to_saas", 0),
        "pending_count": stats.get("pending_in_buffer", 0),
        "sent_payload_ids": sent_ids,
        "pending_payload_ids": pending_ids
    })


@app.post("/api/v1/chaos/inject")
async def inject_chaos_endpoint(payload: Dict[str, Any] = Body(...)):
    """Triggers one of the 8 hackathon test scenarios on the simulator."""
    scenario = payload.get("scenario")
    params = payload.get("params", {})
    if not scenario:
        raise HTTPException(status_code=400, detail="Missing 'scenario' in payload")

    if scenario == "duplicate_events":
        target_tenant = params.get("tenant_id", "tenant-a")
        dup_info = STORAGE.requeue_duplicate_payload(target_tenant)
        ooo_info = STORAGE.requeue_out_of_order_payload(target_tenant)
        fixed_host = "srv-prod-web-01.internal"
        pseudonym = "host-5a29f93e"
        action_msg = f"Injected on {fixed_host} \u2192 pseudonym {pseudonym}"
        return JSONResponse(content={
            "status": "injected",
            "scenario": "duplicate_events",
            "host": fixed_host,
            "real_host": fixed_host,
            "pseudonym": pseudonym,
            "duplicate_requeued": dup_info,
            "out_of_order_requeued": ooo_info,
            "message": action_msg,
            "detail": f"{action_msg} (Duplicate & out-of-order event generation)"
        })

    result = ADAPTER.inject_chaos(scenario, params)
    return JSONResponse(content=result)


@app.post("/api/v1/control/reset")
async def reset_demo_data_endpoint():
    """Clears all raw telemetry, outbound buffer, and egress audit logs from collector."""
    STORAGE.reset_database()
    return JSONResponse(content={
        "status": "success",
        "message": "Collector database and queues reset to 0."
    })


@app.post("/api/v1/adapter/mode")
async def switch_adapter_mode(payload: Dict[str, Any] = Body(...)):
    """Switches input format mode: simulator, jsonl, csv, syslog, http, auto."""
    mode = payload.get("mode")
    if not mode:
        raise HTTPException(status_code=400, detail="Missing 'mode' in payload")
    ADAPTER.set_mode(mode)
    current_mode = ADAPTER.get_mode()
    return JSONResponse(content={
        "status": "updated",
        "current_format": current_mode,
        "mode": current_mode
    })


@app.post("/api/v1/adapter/push")
async def push_external_telemetry(request: Request):
    """
    Organizer / External Stream Hook:
    Accepts JSON, JSON Lines, CSV, or Syslog payloads via HTTP POST.
    """
    content_type = request.headers.get("content-type", "")
    forced_fmt = None
    if "csv" in content_type:
        forced_fmt = "csv"
    elif "json" in content_type:
        try:
            body_json = await request.json()
            ADAPTER.push_external_payload(body_json)
            return JSONResponse(content={"status": "received", "format": "json"})
        except Exception:
            pass

    # Fallback to reading raw body text
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")
    ADAPTER.push_external_payload(body_text, forced_format=forced_fmt)
    return JSONResponse(content={"status": "received", "length": len(body_text)})


@app.post("/api/v1/adapter/load_sample")
async def load_sample_feed(payload: Dict[str, Any] = Body(...)):
    """Copies sample CSV, Syslog, or JSONL into feed_file_path with live timestamps for immediate streaming, or resets to simulator."""
    import re
    format_type = payload.get("format", "csv").lower()
    if format_type in ("simulator", "reset_simulator", "reset"):
        ADAPTER.set_mode("simulator")
        return JSONResponse(content={
            "status": "loaded",
            "format": "simulator",
            "mode": "simulator",
            "message": "Switched adapter back to default simulator."
        })

    source_map = {
        "csv": "data_feed/sample_telemetry.csv",
        "syslog": "data_feed/sample_telemetry.log",
        "jsonl": "data_feed/sample_telemetry.jsonl"
    }
    src_file = source_map.get(format_type)
    if not src_file or not os.path.exists(src_file):
        raise HTTPException(status_code=404, detail=f"Sample file for '{format_type}' not found")

    target_file = ADAPTER.feed_file_path
    os.makedirs(os.path.dirname(target_file) if os.path.dirname(target_file) else ".", exist_ok=True)
    with open(src_file, "r") as sf:
        raw_content = sf.read()

    # Rewrite static timestamps with fresh UTC timestamps so SaaS never flags sample records as stale
    now_utc_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    live_content = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?", now_utc_str, raw_content)

    with open(target_file, "w") as tf:
        tf.write(live_content)

    # Switch adapter mode to match and reset file offset
    ADAPTER.set_mode(format_type)
    ADAPTER.file_last_position = 0
    return JSONResponse(content={
        "status": "loaded",
        "format": format_type,
        "mode": format_type,
        "target_file": target_file,
        "message": f"Loaded {format_type.upper()} feed into {target_file}. Streaming live with fresh timestamps."
    })


@app.get("/api/v1/status")
async def get_collector_status():
    """Returns live telemetry adapter status, active format mode, and buffer metrics."""
    adapter_status = ADAPTER.get_status()
    buffer_stats = STORAGE.get_buffer_stats()
    return JSONResponse(content={
        "collector_version": COLLECTOR_CONFIG.get("collector_version"),
        "saas_url": BUFFER_SENDER.saas_url,
        "db_path": COLLECTOR_DB_PATH,
        "input_format": ADAPTER.get_mode(),
        "saas_outage_simulated": adapter_status.get("saas_outage_simulated", False),
        "adapter": adapter_status,
        "buffer": buffer_stats
    })


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("COLLECTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("COLLECTOR_PORT", 8001))
    uvicorn.run("tier1_collector.app:app", host=host, port=port, reload=False)

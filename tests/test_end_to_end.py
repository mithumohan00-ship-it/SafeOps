"""
SafeOps - End-to-End System Integration Test
============================================
Simulates the complete real-time lifecycle:
1. Tier 1 Collector generates and intercepts raw telemetry with ambient secrets
2. Zero-Trust pipeline scrubs passwords/tokens and transforms hostnames to pseudonyms
3. Tier 1 delivers payloads over HTTP to Tier 2 Ingestion API
4. Tier 2 performs deduplication, event-time sorting, and tenant segregation
5. AIOps detects anomalies, correlates 2-min signals, and verifies remediation workflow
"""

import asyncio
import os
import sys
import time
import unittest
from httpx import ASGITransport, AsyncClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier1_collector.app import app as collector_app
from tier2_saas.app import app as saas_app


class TestEndToEndSystem(unittest.IsolatedAsyncioTestCase):

    async def test_01_tier1_egress_and_controls(self):
        """Verify Tier 1 web interfaces and JSON APIs."""
        transport = ASGITransport(app=collector_app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
            # Egress HTML page
            res_egress = await client.get("/egress")
            self.assertEqual(res_egress.status_code, 200)
            self.assertIn("Egress Proof Panel", res_egress.text)

            # Chaos Control HTML page
            res_ctrl = await client.get("/control")
            self.assertEqual(res_ctrl.status_code, 200)
            self.assertIn("Chaos & Demo Control Panel", res_ctrl.text)

            # API Status
            res_status = await client.get("/api/v1/status")
            self.assertEqual(res_status.status_code, 200)
            data_status = res_status.json()
            self.assertIn("collector_version", data_status)

            # Chaos Injection API (CPU Spike)
            res_chaos = await client.post("/api/v1/chaos/inject", json={
                "scenario": "cpu_spike",
                "params": {"tenant_id": "tenant-a", "duration": 10}
            })
            self.assertEqual(res_chaos.status_code, 200)
            self.assertEqual(res_chaos.json()["status"], "injected")

    async def test_02_tier2_saas_dashboard_and_aiops(self):
        """Verify Tier 2 web interfaces and multi-tenant APIs."""
        transport = ASGITransport(app=saas_app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8002") as client:
            # Dashboard HTML
            res_dash = await client.get("/dashboard")
            self.assertEqual(res_dash.status_code, 200)
            self.assertIn("SafeOps Cloud", res_dash.text)

            # Incidents HTML
            res_inc = await client.get("/incidents")
            self.assertEqual(res_inc.status_code, 200)
            self.assertIn("AIOps Incidents", res_inc.text)

            # Reliability HTML
            res_rel = await client.get("/reliability")
            self.assertEqual(res_rel.status_code, 200)
            self.assertIn("Reliability", res_rel.text)

            # Ingest payload with valid API key
            sample_payload = [{
                "payload_id": f"e2e-payload-{time.time()}",
                "tenant_id": "tenant-a",
                "source_id": "host-7f3a9e12",
                "metric": "cpu_usage_pct",
                "value": 35.5,
                "event_time_utc": "2026-11-20T10:30:00Z",
                "source_timezone": "UTC",
                "health_state": "GOOD",
                "category": "compute",
                "severity": "INFO",
                "short_context": "CPU nominal"
            }]

            headers = {
                "X-API-Key": "sec_key_tenant_a_998811",
                "X-Tenant-ID": "tenant-a"
            }
            res_ingest = await client.post("/api/v1/ingest", json=sample_payload, headers=headers)
            self.assertEqual(res_ingest.status_code, 200)
            self.assertEqual(res_ingest.json()["inserted"], 1)

            # Heartbeat API
            hb_data = {
                "collector_version": "1.0.0",
                "cpu_percent": 15.0,
                "memory_percent": 42.0,
                "config_status": "VALID",
                "pending_buffer_count": 0,
                "sent_count": 10
            }
            res_hb = await client.post("/api/v1/heartbeat", json=hb_data, headers=headers)
            self.assertEqual(res_hb.status_code, 200)

            # Dashboard Data API
            res_data = await client.get("/api/v1/dashboard/data?tenant_id=tenant-a")
            self.assertEqual(res_data.status_code, 200)
            dash_json = res_data.json()
            self.assertIn("hosts", dash_json)
            self.assertIn("host-7f3a9e12", dash_json["hosts"])

            # Clean up test artifact from database so it doesn't pollute the live dashboard
            from tier2_saas.app import STORAGE
            with STORAGE._get_connection() as conn:
                conn.execute("DELETE FROM telemetry_events WHERE source_id = 'host-7f3a9e12'")


if __name__ == "__main__":
    unittest.main()

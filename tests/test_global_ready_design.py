"""
SafeOps - Global-Ready Design Automated Test Suite
==================================================
Verifies the 5 Core Pillars of Global-Ready Architecture:
1. Regional Ingest: Collectors send to nearest/assigned regional endpoint, respecting jurisdiction.
2. Tenant Data Residency: Metadata/telemetry strictly stored in chosen region; unapproved cross-border replication blocked.
3. UTC Timestamps & Timezones: Payloads carry UTC time plus source timezone for correct worldwide dashboard rendering.
4. Out-of-Order Handling: Late/reordered events placed by event time, preserving chronological trends.
5. Idempotent Delivery: Unique UUID payload ID ensures 100% duplicate rejection upon replay.
"""

import datetime
import os
import shutil
import tempfile
import unittest
import uuid
from httpx import ASGITransport, AsyncClient

from tier1_collector.buffer_sender import BufferSender
from tier1_collector.storage import CollectorStorage
from tier1_collector.adapters import SimulatedTelemetryAdapter
from tier1_collector.pipeline import CollectorPipeline, ALLOWED_EGRESS_FIELDS
from tier2_saas.storage import SaaSStorage
from tier2_saas.app import app as saas_app


class TestGlobalReadyDesign(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.collector_db = os.path.join(self.temp_dir, "test_collector.db")
        self.saas_db = os.path.join(self.temp_dir, "test_saas.db")
        self.storage = SaaSStorage(db_path=self.saas_db)

        self.collector_config = {
            "saas_url": "http://127.0.0.1:8002",
            "default_region": "us-east-1",
            "regional_endpoints": {
                "us-east-1": "http://127.0.0.1:8002",
                "eu-central-1": "http://127.0.0.1:8002",
                "ap-southeast-1": "http://127.0.0.1:8002"
            },
            "tenants": {
                "tenant-a": {
                    "name": "Customer A (Financial Cloud)",
                    "api_key": "token-a",
                    "data_residency_region": "us-east-1",
                    "jurisdiction": "US-Domestic",
                    "source_timezone": "America/New_York",
                    "hosts": ["srv-prod-web-01.internal"]
                },
                "tenant-b": {
                    "name": "Customer B (Healthcare Core)",
                    "api_key": "token-b",
                    "data_residency_region": "eu-central-1",
                    "jurisdiction": "EU-GDPR",
                    "source_timezone": "Europe/Frankfurt",
                    "hosts": ["corp-payment-01.local"]
                }
            }
        }

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------
    # Pillar 1: Regional Ingest & Jurisdictional Headers
    # -------------------------------------------------------------
    def test_pillar1_regional_ingest_resolution_and_headers(self):
        """Verifies collectors send to assigned regional endpoint and set jurisdiction headers."""
        col_storage = CollectorStorage(db_path=self.collector_db)
        adapter = SimulatedTelemetryAdapter(self.collector_config)
        sender = BufferSender(config=self.collector_config, storage=col_storage, adapter=adapter)

        # Tenant A resolves to us-east-1 endpoint
        url_a, region_a, jur_a = sender.get_tenant_endpoint("tenant-a")
        self.assertIn("8002", url_a)
        self.assertEqual(region_a, "us-east-1")
        self.assertEqual(jur_a, "US-Domestic")

        # Headers for Tenant A (US-Domestic)
        headers_a = sender.get_tenant_regional_headers("tenant-a")
        self.assertEqual(headers_a.get("X-Region-ID"), "us-east-1")
        self.assertEqual(headers_a.get("X-Jurisdiction"), "US-Domestic")
        self.assertEqual(headers_a.get("X-Data-Residency"), "us-east-1")

        # Headers for Tenant B (EU-GDPR)
        url_b, region_b, jur_b = sender.get_tenant_endpoint("tenant-b")
        self.assertEqual(region_b, "eu-central-1")
        self.assertEqual(jur_b, "EU-GDPR")

        headers_b = sender.get_tenant_regional_headers("tenant-b")
        self.assertEqual(headers_b.get("X-Region-ID"), "eu-central-1")
        self.assertEqual(headers_b.get("X-Jurisdiction"), "EU-GDPR")
        self.assertEqual(headers_b.get("X-Data-Residency"), "eu-central-1")

    # -------------------------------------------------------------
    # Pillar 2: Tenant Data Residency & Replication Boundaries
    # -------------------------------------------------------------
    async def test_pillar2_tenant_data_residency_boundaries(self):
        """Verifies metadata is locked to sovereign region and cross-region replication blocked."""
        # 1. Verify registered home regions
        res_a = self.storage.get_tenant_residency("tenant-a")
        self.assertEqual(res_a["home_region"], "us-east-1")
        self.assertEqual(res_a["jurisdiction"], "US-Domestic")

        res_b = self.storage.get_tenant_residency("tenant-b")
        self.assertEqual(res_b["home_region"], "eu-central-1")
        self.assertEqual(res_b["jurisdiction"], "EU-GDPR")

        # 2. Intra-region access is allowed
        allowed, msg = self.storage.check_and_log_replication("tenant-a", "us-east-1")
        self.assertTrue(allowed)
        self.assertIn("ALLOWED", msg)

        # 3. Cross-region access without policy approval is BLOCKED
        blocked, block_msg = self.storage.check_and_log_replication("tenant-a", "eu-central-1")
        self.assertFalse(blocked)
        self.assertIn("DATA_RESIDENCY_VIOLATION", block_msg)

        # 4. Cross-region access WITH valid policy approval is APPROVED
        appr, appr_msg = self.storage.check_and_log_replication(
            "tenant-a", "eu-central-1", policy_token="POL_APPR_DPO_VALID_123"
        )
        self.assertTrue(appr)
        self.assertIn("APPROVED", appr_msg)

        # 5. Verify audit log captures all attempts
        audits = self.storage.get_residency_audit_log(limit=10)
        decisions = [a["decision"] for a in audits if a["tenant_id"] == "tenant-a"]
        self.assertIn("ALLOWED", decisions)
        self.assertIn("BLOCKED", decisions)
        self.assertIn("APPROVED", decisions)

        # 6. Verify SaaS HTTP API enforces 403 Forbidden on unapproved cross-region replication
        transport = ASGITransport(app=saas_app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8002") as client:
            # Denied attempt -> 403
            res_denied = await client.post("/api/v1/residency/replicate", json={
                "tenant_id": "tenant-a",
                "target_region": "eu-central-1"
            })
            self.assertEqual(res_denied.status_code, 403)
            self.assertEqual(res_denied.json()["decision"], "DENIED")

            # Approved attempt with policy token -> 200
            res_approved = await client.post("/api/v1/residency/replicate", json={
                "tenant_id": "tenant-a",
                "target_region": "eu-central-1",
                "policy_approval_token": "POL_APPR_AUTHORIZED_99"
            })
            self.assertEqual(res_approved.status_code, 200)
            self.assertEqual(res_approved.json()["decision"], "PERMITTED")

    # -------------------------------------------------------------
    # Pillar 3: UTC Timestamps & Source Timezone Preservation
    # -------------------------------------------------------------
    def test_pillar3_utc_timestamps_and_source_timezone(self):
        """Verifies ISO 8601 UTC timestamp and source_timezone are attached and stored."""
        adapter = SimulatedTelemetryAdapter(self.collector_config)
        records = adapter.fetch_records()

        # Find records for tenant-a and tenant-b
        rec_a = next(r for r in records if r["tenant_id"] == "tenant-a")
        rec_b = next(r for r in records if r["tenant_id"] == "tenant-b")

        self.assertEqual(rec_a["source_timezone"], "America/New_York")
        self.assertTrue(rec_a["timestamp_utc"].endswith("Z") or "+00:00" in rec_a["timestamp_utc"])

        self.assertEqual(rec_b["source_timezone"], "Europe/Frankfurt")
        self.assertTrue(rec_b["timestamp_utc"].endswith("Z") or "+00:00" in rec_b["timestamp_utc"])

        # Check Pipeline allows source_timezone in egress
        pipeline = CollectorPipeline()
        egress_payloads = pipeline.process_raw_record(rec_b)
        self.assertGreater(len(egress_payloads), 0)
        self.assertEqual(egress_payloads[0]["source_timezone"], "Europe/Frankfurt")
        self.assertIn("source_timezone", ALLOWED_EGRESS_FIELDS)

        # Ingest into SaaS Storage and verify both UTC and timezone are persisted
        payload_id = str(uuid.uuid4())
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()

        payload = {
            "payload_id": payload_id,
            "tenant_id": "tenant-b",
            "source_id": "host-eu-node-01",
            "metric": "cpu_usage_pct",
            "value": 42.5,
            "event_time_utc": now_utc,
            "source_timezone": "Europe/Frankfurt",
            "health_state": "GOOD"
        }

        inserted, reason = self.storage.ingest_payload(payload, arrival_utc=now_utc, arrival_ts=now_ts)
        self.assertTrue(inserted)

        hosts = self.storage.get_latest_metrics_per_source("tenant-b")
        self.assertIn("host-eu-node-01", hosts)
        self.assertEqual(hosts["host-eu-node-01"]["source_timezone"], "Europe/Frankfurt")

    # -------------------------------------------------------------
    # Pillar 4: Out-of-Order Handling by Event Time
    # -------------------------------------------------------------
    def test_pillar4_out_of_order_event_time_handling(self):
        """Verifies late/delayed events do not corrupt latest state and are placed chronologically."""
        tenant = "tenant-a"
        source = "srv-compute-alpha"
        metric = "memory_usage_pct"

        base_time = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        time_t1 = (base_time + datetime.timedelta(seconds=10)).isoformat()
        time_t2 = (base_time + datetime.timedelta(seconds=20)).isoformat()  # Latest event
        time_t0 = (base_time).isoformat()  # Backdated / late-arriving event

        # 1. Ingest event at T1 (value 50)
        self.storage.ingest_payload({
            "payload_id": "p-1",
            "tenant_id": tenant,
            "source_id": source,
            "metric": metric,
            "value": 50.0,
            "event_time_utc": time_t1,
            "health_state": "GOOD"
        }, arrival_utc=time_t1, arrival_ts=base_time.timestamp() + 10)

        # 2. Ingest event at T2 (value 95, state POOR)
        self.storage.ingest_payload({
            "payload_id": "p-2",
            "tenant_id": tenant,
            "source_id": source,
            "metric": metric,
            "value": 95.0,
            "event_time_utc": time_t2,
            "health_state": "POOR"
        }, arrival_utc=time_t2, arrival_ts=base_time.timestamp() + 20)

        # Verify current state is POOR (T2)
        state_before = self.storage.get_latest_metrics_per_source(tenant)
        self.assertEqual(state_before[source]["overall_health"], "POOR")
        self.assertEqual(state_before[source]["metrics"][metric]["value"], 95.0)

        # 3. Simulate delayed/out-of-order event at T0 (value 20, state GOOD) arriving LATER in arrival_ts
        self.storage.ingest_payload({
            "payload_id": "p-0",
            "tenant_id": tenant,
            "source_id": source,
            "metric": metric,
            "value": 20.0,
            "event_time_utc": time_t0,
            "health_state": "GOOD"
        }, arrival_utc=time_t2, arrival_ts=base_time.timestamp() + 30)  # Arrived at T+30s

        # 4. Verify latest state is STILL POOR (T2) because MAX(event_ts) was preserved
        state_after = self.storage.get_latest_metrics_per_source(tenant)
        self.assertEqual(state_after[source]["overall_health"], "POOR")
        self.assertEqual(state_after[source]["metrics"][metric]["value"], 95.0)

        # 5. Verify historical series places T0 at the beginning chronologically
        history = self.storage.get_metric_history(tenant, source, metric)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["payload_id"], "p-0")  # T0 first
        self.assertEqual(history[1]["payload_id"], "p-1")  # T1 second
        self.assertEqual(history[2]["payload_id"], "p-2")  # T2 third

    # -------------------------------------------------------------
    # Pillar 5: Idempotent Delivery & Deduplication
    # -------------------------------------------------------------
    def test_pillar5_idempotent_delivery_by_uuid(self):
        """Verifies duplicate payload IDs from network retries/replays are rejected without duplicate rows."""
        tenant = "tenant-a"
        payload_id = "unique-uuid-999-aaa"
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()

        payload = {
            "payload_id": payload_id,
            "tenant_id": tenant,
            "source_id": "host-idempotent-test",
            "metric": "cpu_usage_pct",
            "value": 33.3,
            "event_time_utc": now_utc,
            "health_state": "GOOD"
        }

        # First delivery -> Accepted
        inserted_1, reason_1 = self.storage.ingest_payload(payload, arrival_utc=now_utc, arrival_ts=now_ts)
        self.assertTrue(inserted_1)
        self.assertEqual(reason_1, "INSERTED")

        # Second delivery (replay/retry of same payload_id) -> Rejected
        inserted_2, reason_2 = self.storage.ingest_payload(payload, arrival_utc=now_utc, arrival_ts=now_ts + 1)
        self.assertFalse(inserted_2)
        self.assertEqual(reason_2, "DUPLICATE_PAYLOAD_ID_IGNORED")

        # Third delivery -> Rejected
        inserted_3, reason_3 = self.storage.ingest_payload(payload, arrival_utc=now_utc, arrival_ts=now_ts + 2)
        self.assertFalse(inserted_3)

        # Check reliability stats
        stats = self.storage.get_reliability_stats(tenant)
        self.assertEqual(stats["total_payloads_received"], 1)
        self.assertEqual(stats["duplicates_detected_and_rejected"], 2)
        self.assertEqual(stats["lost_payloads"], 0)


if __name__ == "__main__":
    unittest.main()

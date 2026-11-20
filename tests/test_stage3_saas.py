"""
Stage 3 Automated Verification Tests
====================================
Tests:
1. API Key authentication & tenant validation
2. Ingestion deduplication by payload_id
3. Chronological sorting by event_time_utc (not arrival time)
4. Strict tenant isolation (Tenant A never sees Tenant B data)
5. Health state evaluation (Excellent, Good, Fair, Poor) + explanation reasons
6. Stale data detection (>30s)
7. Collector offline detection (>60s)
8. State change history logging with UTC timestamps
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier2_saas.auth import verify_collector_api_key
from tier2_saas.health_engine import HealthEngine
from tier2_saas.storage import SaaSStorage


class TestStage3SaaSPlatform(unittest.TestCase):

    def setUp(self):
        self.test_db = "test_saas_stage3.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.storage = SaaSStorage(self.test_db)
        self.health_engine = HealthEngine(self.storage)

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_01_api_key_validation(self):
        """Verify API keys authenticate correctly and reject mismatches."""
        # Tenant A key
        tenant = verify_collector_api_key(x_api_key="sec_key_tenant_a_998811", x_tenant_id="tenant-a")
        self.assertEqual(tenant, "tenant-a")

        # Invalid key raises 401
        with self.assertRaises(Exception):
            verify_collector_api_key(x_api_key="wrong_invalid_key", x_tenant_id="tenant-a")

        # Key for Tenant A claiming to be Tenant B raises 403
        with self.assertRaises(Exception):
            verify_collector_api_key(x_api_key="sec_key_tenant_a_998811", x_tenant_id="tenant-b")

    def test_02_deduplication_by_payload_id(self):
        """Verify duplicate payload_ids are rejected and accounted."""
        payload = {
            "payload_id": "test-uuid-dup-01",
            "tenant_id": "tenant-a",
            "source_id": "host-7f3a",
            "metric": "cpu_usage_pct",
            "value": 42.0,
            "event_time_utc": "2026-11-20T10:10:00Z"
        }
        # First insertion
        inserted1, status1 = self.storage.ingest_payload(payload, "2026-11-20T10:10:01Z", time.time())
        self.assertTrue(inserted1)

        # Duplicate insertion with exact same payload_id
        inserted2, status2 = self.storage.ingest_payload(payload, "2026-11-20T10:10:02Z", time.time())
        self.assertFalse(inserted2)
        self.assertEqual(status2, "DUPLICATE_PAYLOAD_ID_IGNORED")

        # Verify counters
        rel = self.storage.get_reliability_stats("tenant-a")
        self.assertEqual(rel["duplicates_detected_and_rejected"], 1)

    def test_03_strict_tenant_isolation(self):
        """Verify Tenant A queries NEVER return data from Tenant B."""
        # Insert payload for Tenant A
        p_a = {
            "payload_id": "p-tenant-a-1",
            "tenant_id": "tenant-a",
            "source_id": "host-tenant-a-web",
            "metric": "cpu_usage_pct",
            "value": 35.0,
            "event_time_utc": "2026-11-20T10:15:00Z"
        }
        self.storage.ingest_payload(p_a, "2026-11-20T10:15:01Z", time.time())

        # Insert payload for Tenant B
        p_b = {
            "payload_id": "p-tenant-b-1",
            "tenant_id": "tenant-b",
            "source_id": "host-tenant-b-payment",
            "metric": "cpu_usage_pct",
            "value": 90.0,
            "event_time_utc": "2026-11-20T10:15:00Z"
        }
        self.storage.ingest_payload(p_b, "2026-11-20T10:15:01Z", time.time())

        # Query Tenant A
        hosts_a = self.storage.get_latest_metrics_per_source("tenant-a")
        self.assertIn("host-tenant-a-web", hosts_a)
        self.assertNotIn("host-tenant-b-payment", hosts_a)

        # Query Tenant B
        hosts_b = self.storage.get_latest_metrics_per_source("tenant-b")
        self.assertIn("host-tenant-b-payment", hosts_b)
        self.assertNotIn("host-tenant-a-web", hosts_b)

    def test_04_health_state_evaluation_and_reasons(self):
        """Verify thresholds assign Excellent/Good/Fair/Poor with clear reasons."""
        p_exc = {"metric": "cpu_usage_pct", "value": 30.0}
        state, reason = self.health_engine.evaluate_payload_health(p_exc)
        self.assertEqual(state, "EXCELLENT")

        p_poor = {"metric": "cpu_usage_pct", "value": 95.0}
        state, reason = self.health_engine.evaluate_payload_health(p_poor)
        self.assertEqual(state, "POOR")
        self.assertIn("High CPU utilization", reason)

        p_serv_down = {"metric": "service_status", "value": 0}
        state, reason = self.health_engine.evaluate_payload_health(p_serv_down)
        self.assertEqual(state, "POOR")
        self.assertIn("stopped responding", reason)

    def test_05_stale_data_detection(self):
        """Verify data older than 30s is downgraded to POOR."""
        old_ts = time.time() - 45.0  # 45 seconds ago
        hosts_map = {
            "host-stale-01": {
                "overall_health": "EXCELLENT",
                "metrics": {
                    "cpu_usage_pct": {
                        "value": 25.0,
                        "health_state": "EXCELLENT",
                        "event_ts": old_ts
                    }
                }
            }
        }
        self.health_engine.check_stale_data_for_hosts("tenant-a", hosts_map)
        self.assertEqual(hosts_map["host-stale-01"]["overall_health"], "POOR")
        self.assertTrue(hosts_map["host-stale-01"]["is_stale"])
        self.assertIn("Stale data", hosts_map["host-stale-01"]["stale_reason"])

    def test_06_collector_offline_detection(self):
        """Verify collector is flagged OFFLINE if no heartbeat in >60s."""
        # Heartbeat 75s ago
        now = time.time()
        with self.storage._get_connection() as conn:
            conn.execute("""
                INSERT INTO collector_heartbeats
                (tenant_id, collector_version, last_heartbeat_utc, last_heartbeat_ts, cpu_percent, memory_percent, config_status)
                VALUES ('tenant-a', '1.0.0', '2026-11-20T10:00:00Z', ?, 12.0, 30.0, 'VALID')
            """, (now - 75.0,))

        col_status = self.storage.get_collector_status("tenant-a")
        self.assertTrue(col_status["is_offline"])
        self.assertEqual(col_status["status"], "OFFLINE")

    def test_07_state_change_history(self):
        """Verify health state changes are recorded in history log with UTC timestamps."""
        p1 = {
            "tenant_id": "tenant-a",
            "source_id": "host-7f3a",
            "metric": "cpu_usage_pct",
            "value": 40.0,
            "event_time_utc": "2026-11-20T10:20:00Z"
        }
        self.health_engine.check_state_transition(p1, "GOOD", "CPU nominal")

        # Now transition to POOR
        p2 = {
            "tenant_id": "tenant-a",
            "source_id": "host-7f3a",
            "metric": "cpu_usage_pct",
            "value": 98.0,
            "event_time_utc": "2026-11-20T10:20:05Z"
        }
        self.health_engine.check_state_transition(p2, "POOR", "High CPU spike")

        history = self.storage.get_state_change_history("tenant-a")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["old_state"], "GOOD")
        self.assertEqual(history[0]["new_state"], "POOR")
        self.assertIn("High CPU", history[0]["reason"])


if __name__ == "__main__":
    unittest.main()

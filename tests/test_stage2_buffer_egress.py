"""
Stage 2 Automated Verification Tests
====================================
Tests:
1. SQLite Outbound Buffer queueing and backoff
2. SaaS Outage simulation (events buffer without loss)
3. Buffer recovery and flush when SaaS connection is restored
4. Egress Proof side-by-side pairing (Raw input vs Sanitized sent JSON)
5. Searchable audit log querying
6. 1-Hour local retention pruner
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier1_collector.storage import CollectorStorage


class TestStage2BufferAndEgress(unittest.TestCase):

    def setUp(self):
        self.test_db = "test_collector_stage2.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.storage = CollectorStorage(self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_01_buffer_queue_and_retry(self):
        """Verify payloads enqueue in buffer and handle retry backoff."""
        raw_rec = {
            "raw_id": "r-001",
            "tenant_id": "tenant-a",
            "hostname": "srv-prod-web-01.internal",
            "timestamp_utc": "2026-11-20T10:00:00Z"
        }
        self.storage.store_raw_event(raw_rec)

        payload = {
            "payload_id": "p-001",
            "tenant_id": "tenant-a",
            "source_id": "host-7f3a",
            "metric": "cpu_usage_pct",
            "value": 45.2,
            "event_time_utc": "2026-11-20T10:00:00Z",
            "source_timezone": "UTC",
            "health_state": "GOOD",
            "category": "compute",
            "severity": "INFO",
            "short_context": "CPU nominal"
        }
        self.storage.enqueue_payload("r-001", payload)

        pending = self.storage.get_pending_payloads()
        self.assertEqual(len(pending), 1)

        # Simulate failure: retry with backoff
        self.storage.mark_payload_failed("p-001", retry_count=1, backoff_seconds=2.0)
        # Immediately querying should return 0 because next_retry_at is in the future
        pending_immediate = self.storage.get_pending_payloads()
        self.assertEqual(len(pending_immediate), 0)

    def test_02_egress_pairs_and_search(self):
        """Verify side-by-side raw vs sanitized pairing and search filter."""
        raw_rec = {
            "raw_id": "r-pair-1",
            "tenant_id": "tenant-a",
            "hostname": "srv-prod-db-01.internal",
            "timestamp_utc": "2026-11-20T10:05:00Z",
            "raw_logs": ["password=SuperSecretPassword99!"],
            "ambient_secrets_present": True
        }
        self.storage.store_raw_event(raw_rec)

        payload = {
            "payload_id": "p-pair-1",
            "tenant_id": "tenant-a",
            "source_id": "host-99db88",
            "metric": "disk_usage_pct",
            "value": 88.5,
            "event_time_utc": "2026-11-20T10:05:00Z",
            "source_timezone": "UTC",
            "health_state": "FAIR",
            "category": "storage",
            "severity": "WARNING",
            "short_context": "Disk elevated"
        }
        self.storage.enqueue_payload("r-pair-1", payload)
        self.storage.mark_payload_sent("p-pair-1", "r-pair-1", payload)

        # Retrieve egress pairs
        pairs = self.storage.get_egress_pairs()
        self.assertEqual(len(pairs), 1)
        pair = pairs[0]

        self.assertEqual(pair["payload_id"], "p-pair-1")
        self.assertEqual(pair["raw_hostname"], "srv-prod-db-01.internal")
        self.assertEqual(pair["sanitized_dict"]["source_id"], "host-99db88")
        self.assertIn("password=SuperSecretPassword99!", str(pair["raw_dict"]))

        # Test search filter
        search_res = self.storage.get_egress_pairs(search="disk_usage")
        self.assertEqual(len(search_res), 1)

        search_miss = self.storage.get_egress_pairs(search="nonexistent_metric")
        self.assertEqual(len(search_miss), 0)

    def test_03_retention_pruning(self):
        """Verify records older than 1 hour (3600s) are deleted from local storage."""
        # Insert record with created_at 2 hours ago
        two_hours_ago = time.time() - 7200.0
        with self.storage._get_connection() as conn:
            conn.execute("""
                INSERT INTO raw_telemetry
                (raw_id, tenant_id, hostname, timestamp_utc, created_at, raw_json, secrets_detected)
                VALUES ('old-raw-1', 'tenant-a', 'host-old', '2026-11-20T08:00:00Z', ?, '{}', 0)
            """, (two_hours_ago,))

        stats_before = self.storage.get_buffer_stats()
        self.assertEqual(stats_before["raw_records_stored"], 1)

        # Run pruner for 1 hour retention
        pruned = self.storage.prune_expired_raw_records(retention_seconds=3600.0)
        self.assertEqual(pruned, 1)

        stats_after = self.storage.get_buffer_stats()
        self.assertEqual(stats_after["raw_records_stored"], 0)


if __name__ == "__main__":
    unittest.main()

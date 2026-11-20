"""
Stage 1 Automated Verification Tests
====================================
Tests:
1. Telemetry generation across 2 tenants and 3 hosts each
2. Redaction of passwords, tokens, internal IPs, and emails
3. Pseudonymization of hostnames (e.g., srv-prod-web-01.internal -> host-7f3a...)
4. Local security detection of repeated failed logins (summary only, raw lines discarded)
5. Strict allow-list enforcement (only 11 fields permitted)
6. SQLite local raw storage & outbound buffering
"""

import os
import sys
import unittest

# Add workspace to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier1_collector.adapters import SimulatedTelemetryAdapter
from tier1_collector.pipeline import (
    ALLOWED_EGRESS_FIELDS,
    CollectorPipeline,
    LocalSecurityAnalyzer,
    pseudonymize_hostname,
    redact_text,
)
from tier1_collector.storage import CollectorStorage

TEST_CONFIG = {
    "tenants": {
        "tenant-a": {
            "name": "Customer A",
            "hosts": ["srv-prod-web-01.internal", "srv-prod-app-01.internal", "srv-prod-db-01.internal"]
        },
        "tenant-b": {
            "name": "Customer B",
            "hosts": ["corp-payment-01.local", "corp-order-01.local", "corp-auth-01.local"]
        }
    }
}


class TestStage1Collector(unittest.TestCase):

    def setUp(self):
        self.test_db = "test_collector_stage1.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.storage = CollectorStorage(self.test_db)
        self.adapter = SimulatedTelemetryAdapter(TEST_CONFIG)
        self.pipeline = CollectorPipeline(salt="test_salt_123")

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_01_telemetry_generation(self):
        """Verify simulator generates records for 2 tenants and 3 hosts each (total 6 records)."""
        records = self.adapter.fetch_records()
        self.assertEqual(len(records), 6, "Expected exactly 6 host records (2 tenants x 3 hosts)")

        tenants_found = set(r["tenant_id"] for r in records)
        self.assertEqual(tenants_found, {"tenant-a", "tenant-b"})

        for r in records:
            metrics = r["metrics"]
            self.assertIn("cpu_usage_pct", metrics)
            self.assertIn("memory_usage_pct", metrics)
            self.assertIn("disk_usage_pct", metrics)
            self.assertIn("bandwidth_mbps", metrics)
            self.assertIn("latency_ms", metrics)
            self.assertIn("packet_loss_pct", metrics)
            self.assertIn("service_status", metrics)
            self.assertIn("hostname", r)
            self.assertIn("raw_logs", r)

    def test_02_secret_redaction(self):
        """Verify regex accurately scrubs passwords, API keys, IPs, and emails."""
        raw_string = "Error on 192.168.1.55 by user=john.doe@company.org with password=SecretPassword99! and api_key=sk_live_abcdef12345678"
        redacted = redact_text(raw_string)

        self.assertNotIn("SecretPassword99!", redacted)
        self.assertNotIn("sk_live_abcdef12345678", redacted)
        self.assertNotIn("192.168.1.55", redacted)
        self.assertNotIn("john.doe@company.org", redacted)

        self.assertIn("[REDACTED_PASSWORD]", redacted)
        self.assertIn("[REDACTED_TOKEN]", redacted)
        self.assertIn("[REDACTED_IP]", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)

    def test_03_pseudonymization(self):
        """Verify hostnames are transformed into pseudonymous hashes."""
        host = "srv-prod-web-01.internal"
        pseudonym = pseudonymize_hostname("tenant-a", host, "test_salt_123")

        self.assertTrue(pseudonym.startswith("host-"))
        self.assertNotIn("srv-prod", pseudonym)
        self.assertNotIn("internal", pseudonym)

        # Deterministic: same inputs give same pseudonym
        pseudonym2 = pseudonymize_hostname("tenant-a", host, "test_salt_123")
        self.assertEqual(pseudonym, pseudonym2)

        # Different tenant or host gives different pseudonym
        pseudonym_diff = pseudonymize_hostname("tenant-b", host, "test_salt_123")
        self.assertNotEqual(pseudonym, pseudonym_diff)

    def test_04_local_security_analysis(self):
        """Verify brute force failed logins are aggregated locally without sending raw logs."""
        analyzer = LocalSecurityAnalyzer(window_seconds=30.0, threshold_count=3)
        logs = [
            "FAILED LOGIN: host=srv-prod-web-01.internal user=root source_ip=192.168.1.10 password=badpass reason=invalid_credentials",
            "FAILED LOGIN: host=srv-prod-web-01.internal user=root source_ip=192.168.1.10 password=badpass reason=invalid_credentials",
            "FAILED LOGIN: host=srv-prod-web-01.internal user=root source_ip=192.168.1.10 password=badpass reason=invalid_credentials"
        ]
        count, severity, summary = analyzer.process_logs("srv-prod-web-01.internal", logs)
        self.assertEqual(count, 3)
        self.assertEqual(severity, "WARNING")
        self.assertIn("Brute force anomaly detected", summary)
        self.assertNotIn("badpass", summary)

    def test_05_allow_list_enforcement(self):
        """Verify only the 11 allowed fields exist in egress payloads."""
        raw_record = {
            "raw_id": "test-uuid-001",
            "tenant_id": "tenant-a",
            "hostname": "srv-prod-web-01.internal",
            "timestamp_utc": "2026-11-20T10:00:00Z",
            "source_timezone": "UTC",
            "metrics": {"cpu_usage_pct": 82.5},
            "raw_logs": ["User login success password=plaintext!"],
            "internal_tags": {"rack": "RU-12", "secret_admin": "confidential"},
            "ambient_secrets_present": True
        }

        egress_list = self.pipeline.process_raw_record(raw_record)
        self.assertGreater(len(egress_list), 0)

        for p in egress_list:
            keys = set(p.keys())
            # Keys must be a subset of ALLOWED_EGRESS_FIELDS
            self.assertTrue(keys.issubset(ALLOWED_EGRESS_FIELDS))
            # Ensure none of the internal tags or raw logs leaked
            self.assertNotIn("raw_logs", keys)
            self.assertNotIn("internal_tags", keys)
            self.assertNotIn("hostname", keys)
            self.assertIn("source_id", keys)
            self.assertTrue(p["source_id"].startswith("host-"))

    def test_06_storage_and_buffer(self):
        """Verify raw events are saved locally and payloads are enqueued in SQLite buffer."""
        raw_record = {
            "raw_id": "raw-12345",
            "tenant_id": "tenant-a",
            "hostname": "srv-prod-app-01.internal",
            "timestamp_utc": "2026-11-20T10:00:00Z",
            "ambient_secrets_present": True,
            "metrics": {"memory_usage_pct": 74.0}
        }
        self.storage.store_raw_event(raw_record)

        payload = {
            "payload_id": "pay-99999",
            "tenant_id": "tenant-a",
            "source_id": "host-abc12345",
            "metric": "memory_usage_pct",
            "value": 74.0,
            "event_time_utc": "2026-11-20T10:00:00Z",
            "source_timezone": "UTC",
            "health_state": "GOOD",
            "category": "compute",
            "severity": "INFO",
            "short_context": "Memory normal at 74.0%"
        }
        self.storage.enqueue_payload("raw-12345", payload)

        pending = self.storage.get_pending_payloads()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["payload_id"], "pay-99999")

        # Mark sent
        self.storage.mark_payload_sent("pay-99999", "raw-12345", payload)
        stats = self.storage.get_buffer_stats()
        self.assertEqual(stats["pending_in_buffer"], 0)
        self.assertEqual(stats["total_sent_to_saas"], 1)
        self.assertEqual(stats["raw_records_stored"], 1)


if __name__ == "__main__":
    unittest.main()

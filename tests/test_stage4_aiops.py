"""
Stage 4 Automated Verification Tests
====================================
Tests:
1. Dynamic statistical baseline calculation (rolling mean & std)
2. 3-Sigma Anomaly Detection (z-score > 3.0)
3. Incident correlation: alerts on same host within 2 minutes merge into ONE incident
4. Explainable recommendations with exact contributing numbers, confidence %, likely cause, and reasoning
5. Safe remediation execution: policy check -> Approve -> Audit log -> Rollback
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier2_saas.aiops_engine import AIOpsEngine
from tier2_saas.storage import SaaSStorage


class TestStage4AIOps(unittest.TestCase):

    def setUp(self):
        self.test_db = "test_saas_stage4.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.storage = SaaSStorage(self.test_db)
        self.aiops = AIOpsEngine(self.storage, correlation_window_sec=120.0, zscore_threshold=3.0)

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_01_baseline_and_zscore_anomaly(self):
        """Feed normal baseline values, then inject a spike that exceeds z-score > 3."""
        tenant = "tenant-a"
        host = "host-7f3a"
        metric = "cpu_usage_pct"

        # Feed 10 normal baseline observations around 30% (with small variance)
        for i in range(10):
            p = {
                "tenant_id": tenant,
                "source_id": host,
                "metric": metric,
                "value": 30.0 + (i % 3),
                "event_time_utc": f"2026-11-20T10:00:{i:02d}Z"
            }
            res = self.aiops.process_incoming_metric(p)
            self.assertIsNone(res, "Nominal baseline points should not trigger anomaly")

        # Now inject a major spike (CPU 99.0%)
        spike_payload = {
            "tenant_id": tenant,
            "source_id": host,
            "metric": metric,
            "value": 99.0,
            "event_time_utc": "2026-11-20T10:01:00Z"
        }
        res_spike = self.aiops.process_incoming_metric(spike_payload)
        self.assertIsNotNone(res_spike, "CPU 99% with baseline 30% must trigger anomaly")
        self.assertEqual(res_spike["status"], "OPEN")
        self.assertGreater(res_spike["affected_components"][0]["z_score"], 3.0)

    def test_02_incident_correlation_2min_window(self):
        """Verify that alerts on the same host within 2 minutes merge into ONE incident."""
        tenant = "tenant-a"
        host = "host-99cc"

        # Feed baseline for CPU & Latency
        for i in range(6):
            self.aiops.process_incoming_metric({
                "tenant_id": tenant, "source_id": host, "metric": "cpu_usage_pct", "value": 32.0, "event_time_utc": "2026-11-20T10:00:00Z"
            })
            self.aiops.process_incoming_metric({
                "tenant_id": tenant, "source_id": host, "metric": "latency_ms", "value": 20.0, "event_time_utc": "2026-11-20T10:00:00Z"
            })

        # 1. Trigger CPU spike
        self.aiops.process_incoming_metric({
            "tenant_id": tenant, "source_id": host, "metric": "cpu_usage_pct", "value": 98.5, "event_time_utc": "2026-11-20T10:02:00Z"
        })

        # 2. Trigger Latency rise 10 seconds later on same host
        self.aiops.process_incoming_metric({
            "tenant_id": tenant, "source_id": host, "metric": "latency_ms", "value": 450.0, "event_time_utc": "2026-11-20T10:02:10Z"
        })

        # Query open incidents for tenant
        incidents = self.storage.get_incidents(tenant)
        self.assertEqual(len(incidents), 1, "Expected correlated alerts to merge into exactly ONE incident")

        inc = incidents[0]
        affected = inc["affected_components"]
        self.assertEqual(len(affected), 2, "Incident must contain both correlated signals")
        metrics_in_incident = set(c["metric"] for c in affected)
        self.assertEqual(metrics_in_incident, {"cpu_usage_pct", "latency_ms"})

    def test_03_explainable_recommendation(self):
        """Verify incident includes explainable signals, confidence %, likely cause, action, and reasoning."""
        tenant = "tenant-a"
        host = "host-service-01"

        # Immediate service down event
        self.aiops.process_incoming_metric({
            "tenant_id": tenant, "source_id": host, "metric": "service_status", "value": 0, "event_time_utc": "2026-11-20T10:05:00Z"
        })

        incidents = self.storage.get_incidents(tenant)
        self.assertEqual(len(incidents), 1)
        rec = incidents[0]["recommendation"]

        self.assertIn("flagged_summary", rec)
        self.assertIn("contributing_signals", rec)
        self.assertGreaterEqual(rec["confidence_pct"], 80)
        self.assertIn("likely_cause", rec)
        self.assertIn("suggested_action", rec)
        self.assertIn("why_reasoning", rec)
        self.assertIn("policy_check", rec)

    def test_04_remediation_workflow_and_rollback(self):
        """Verify Approve -> Remediation execution -> Audit trail -> Rollback option."""
        tenant = "tenant-a"
        host = "host-remedy-01"

        # Create incident
        inc = self.aiops._correlate_into_incident(
            tenant_id=tenant, source_id=host, metric="cpu_usage_pct",
            value=98.0, mean=35.0, std=2.0, z_score=31.5,
            event_time_utc="2026-11-20T10:10:00Z", now_ts=time.time()
        )
        incident_id = inc["incident_id"]

        # 1. Execute safe remediation (Approve)
        rem_res = self.aiops.execute_remediation(incident_id, tenant, "scale_cpu_quota", operator="AliceSRE")
        self.assertEqual(rem_res["status"], "success")
        self.assertTrue(rem_res["rollback_available"])

        # Check incident status updated to REMEDIATED
        updated_inc = next(i for i in self.storage.get_incidents(tenant) if i["incident_id"] == incident_id)
        self.assertEqual(updated_inc["status"], "REMEDIATED")

        # Check audit record
        audit = self.storage.get_remediation_audit(tenant)
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["action_name"], "scale_cpu_quota")
        self.assertEqual(audit[0]["operator"], "AliceSRE")

        # 2. Rollback remediation
        rb_res = self.aiops.rollback_remediation(incident_id, tenant, operator="AliceSRE")
        self.assertEqual(rb_res["status"], "success")

        # Incident status back to OPEN
        reopened_inc = next(i for i in self.storage.get_incidents(tenant) if i["incident_id"] == incident_id)
        self.assertEqual(reopened_inc["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

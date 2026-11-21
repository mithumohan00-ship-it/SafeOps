"""
Tests for SafeOps Real Multi-Source Telemetry & Probes
======================================================
Covers:
1. Agent (psutil real hardware metrics & 10 standard column names)
2. NetworkProbe (ICMP ping latency_ms & packet_loss_pct)
3. WebAppProbe (HTTP GET response time & service_status up/down)
4. DatabaseProbe (SELECT 1 query latency on SQLite)
5. SyslogUDPListener (UDP 5514 log receiver, secret scrubbing, brute force analysis)
6. Zero-Trust Pipeline integration (all sources sanitized & allow-listed)
"""

import json
import os
import platform
import socket
import ssl
import time
import unittest
from unittest.mock import MagicMock, patch

from agent.agent import SafeOpsAgent
from tier1_collector.format_parser import UniversalFormatParser
from tier1_collector.pipeline import CollectorPipeline
from tier1_collector.probes import DatabaseProbe, NetworkProbe, ProbeManager, SyslogUDPListener, WebAppProbe


class TestRealTelemetryAndProbes(unittest.TestCase):

    def setUp(self):
        self.pipeline = CollectorPipeline(salt="test_salt_verification_2026")
        self.parser = UniversalFormatParser()
        self.base_config = {
            "network_probe": {
                "enabled": True,
                "interval_seconds": 5.0,
                "tenant_id": "tenant-a",
                "targets": [{"target": "127.0.0.1", "hostname": "srv-prod-web-01.internal", "tenant_id": "tenant-a"}]
            },
            "webapp_probe": {
                "enabled": True,
                "interval_seconds": 5.0,
                "tenant_id": "tenant-a",
                "targets": [{"name": "srv-prod-web-01.internal", "url": "https://httpbin.org/status/200", "tenant_id": "tenant-a"}]
            },
            "database_probe": {
                "enabled": True,
                "interval_seconds": 5.0,
                "db_type": "sqlite",
                "db_path": ":memory:",
                "tenant_id": "tenant-a",
                "hostname": "srv-prod-db-01.internal"
            },
            "syslog_udp": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 5519,  # Use distinct test port
                "default_tenant_id": "tenant-b"
            }
        }

    def test_01_agent_hardware_sampling_standard_columns(self):
        """Verifies SafeOps standalone agent samples real CPU, RAM, Disk, and Net IO with 10 standard columns."""
        agent = SafeOpsAgent(
            collector_url="http://127.0.0.1:8001/api/v1/adapter/push",
            tenant_id="tenant-b",
            hostname="laptop-test-01.local"
        )
        sample = agent.sample_metrics()

        expected_columns = {
            "tenant_id", "hostname", "timestamp_utc", "cpu_usage_pct",
            "memory_usage_pct", "disk_usage_pct", "bandwidth_mbps",
            "latency_ms", "packet_loss_pct", "service_status"
        }
        self.assertEqual(set(sample.keys()), expected_columns)
        self.assertEqual(sample["tenant_id"], "tenant-b")
        self.assertEqual(sample["hostname"], "laptop-test-01.local")
        self.assertGreaterEqual(sample["cpu_usage_pct"], 0.0)
        self.assertLessEqual(sample["cpu_usage_pct"], 100.0)
        self.assertGreater(sample["memory_usage_pct"], 0.0)
        self.assertGreater(sample["disk_usage_pct"], 0.0)
        self.assertGreaterEqual(sample["bandwidth_mbps"], 0.0)
        self.assertEqual(sample["service_status"], 1)

    def test_02_agent_payload_passes_zero_trust_pipeline(self):
        """Verifies that an agent telemetry sample transforms into 11-field allow-listed payloads."""
        agent = SafeOpsAgent(tenant_id="tenant-b", hostname="corp-order-01.local")
        sample = agent.sample_metrics()

        # Wrap in standard raw record
        raw_record = self.parser.parse_jsonl_line(json.dumps(sample))
        self.assertIsNotNone(raw_record)

        egress_payloads = self.pipeline.process_raw_record(raw_record)
        self.assertGreater(len(egress_payloads), 0)

        # Allow-list check: every field must belong to the 11 whitelisted fields
        allowed_fields = {
            "payload_id", "tenant_id", "source_id", "metric", "value",
            "event_time_utc", "source_timezone", "health_state", "category",
            "severity", "short_context"
        }
        for p in egress_payloads:
            self.assertTrue(set(p.keys()).issubset(allowed_fields))
            self.assertEqual(p["tenant_id"], "tenant-b")
            self.assertTrue(p["source_id"].startswith("host-"))
            self.assertNotEqual(p["source_id"], "corp-order-01.local")  # Pseudonymized!

    def test_03_network_probe_ping(self):
        """Verifies NetworkProbe pings 127.0.0.1 and extracts latency_ms and packet_loss_pct."""
        net_probe = NetworkProbe(self.base_config)
        records = net_probe.collect()
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertIn("metrics", rec)
        metrics = rec["metrics"]
        self.assertIn("latency_ms", metrics)
        self.assertIn("packet_loss_pct", metrics)
        self.assertLess(metrics["packet_loss_pct"], 50.0)  # Localhost ping shouldn't have high loss
        self.assertGreater(metrics["latency_ms"], 0.0)

        # Pass through pipeline
        egress = self.pipeline.process_raw_record(rec)
        metric_names = [e["metric"] for e in egress]
        self.assertIn("latency_ms", metric_names)
        self.assertIn("packet_loss_pct", metric_names)

    def test_04_webapp_probe_up_and_down(self):
        """Verifies WebAppProbe reports service_status=1 for reachable URLs and service_status=0 for down URLs."""
        # 1. Reachable mock URL (status 200)
        web_probe = WebAppProbe(self.base_config)
        target_up = {"name": "srv-prod-web-01.internal", "url": "https://httpbin.org/status/200", "tenant_id": "tenant-a"}

        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_open.return_value.__enter__.return_value = mock_resp

            rec_up = web_probe.probe_url(target_up)
            self.assertIsNotNone(rec_up)
            self.assertEqual(rec_up["metrics"]["service_status"], 1)

            # Pass through pipeline
            egress = self.pipeline.process_raw_record(rec_up)
            status_egress = next(e for e in egress if e["metric"] == "service_status")
            self.assertEqual(status_egress["health_state"], "EXCELLENT")
            self.assertEqual(status_egress["severity"], "INFO")

        # 2. Down mock URL (status 503 or ConnectionRefused)
        target_down = {"name": "srv-prod-web-01.internal", "url": "http://127.0.0.1:9999/down", "tenant_id": "tenant-a"}
        rec_down = web_probe.probe_url(target_down)
        self.assertIsNotNone(rec_down)
        self.assertEqual(rec_down["metrics"]["service_status"], 0)

        # Pass down record through pipeline
        egress_down = self.pipeline.process_raw_record(rec_down)
        down_status_egress = next(e for e in egress_down if e["metric"] == "service_status")
        self.assertEqual(down_status_egress["health_state"], "POOR")
        self.assertEqual(down_status_egress["severity"], "CRITICAL")
        self.assertIn("DOWN", down_status_egress["short_context"])

    def test_05_database_probe_sqlite_select_1(self):
        """Verifies DatabaseProbe executes SELECT 1 and records latency and service_status."""
        db_probe = DatabaseProbe(self.base_config)
        records = db_probe.collect()
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertEqual(rec["metrics"]["service_status"], 1)
        self.assertGreater(rec["metrics"]["latency_ms"], 0.0)

        # Pass through pipeline
        egress = self.pipeline.process_raw_record(rec)
        names = [e["metric"] for e in egress]
        self.assertIn("service_status", names)
        self.assertIn("latency_ms", names)

    def test_06_syslog_udp_listener_and_secret_redaction(self):
        """Verifies UDP listener receives syslog messages, scrubs passwords, and analyzes failed logins."""
        listener = SyslogUDPListener(self.base_config, self.parser)
        listener.start()
        time.sleep(0.1)

        try:
            # Send UDP message containing ambient password and failed login
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            msg = "<134>1 2026-11-21T12:00:00Z corp-auth-01.local app 1234 - - FAILED LOGIN user=admin password=SecretPassword99! invalid_credentials"
            client_sock.sendto(msg.encode("utf-8"), ("127.0.0.1", 5519))
            client_sock.close()

            time.sleep(0.2)
            drained = listener.drain_records()
            self.assertEqual(len(drained), 1)

            rec = drained[0]
            # Ensure raw logs contain the message
            self.assertIn("raw_logs", rec)

            # Pass through Zero-Trust Pipeline
            egress = self.pipeline.process_raw_record(rec)

            # Check that raw password is NEVER leaked in any egress payload short_context or values
            for e in egress:
                self.assertNotIn("SecretPassword99!", json.dumps(e))

        finally:
            listener.stop()

    def test_07_probe_manager_coordination(self):
        """Verifies ProbeManager runs active probes and drains records."""
        manager = ProbeManager(self.base_config, self.parser)
        # Manually trigger collections without background loop wait
        batch = manager.network_probe.collect()
        self.assertGreater(len(batch), 0)

        with manager._lock:
            manager._pending_records.extend(batch)

        collected = manager.collect_records()
        self.assertEqual(len(collected), len(batch))
        # Subsequent drain should be empty
        self.assertEqual(len(manager.collect_records()), 0)


if __name__ == "__main__":
    unittest.main()

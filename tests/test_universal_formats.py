"""
SafeOps - Universal Multi-Format Adapter Test Suite
===================================================
Tests support for:
1. JSON Lines (default)
2. CSV format with flexible column alias mapping
3. Syslog (RFC 5424 and RFC 3164)
4. Runtime format mode switching
5. HTTP REST push telemetry ingest
6. Auto-detection of unknown data streams
7. Sample feed loading and simulator resetting
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tier1_collector.format_parser import UniversalFormatParser
from tier1_collector.adapters import UniversalFeedAdapter
from tier1_collector.pipeline import CollectorPipeline
from starlette.testclient import TestClient
from tier1_collector.app import app as collector_app


class TestUniversalFormatParser(unittest.TestCase):

    def setUp(self):
        self.parser = UniversalFormatParser()

    def test_01_json_lines_parsing(self):
        """Verify JSON Lines parsing for both nested and flat structures."""
        # Nested format
        nested_line = '{"tenant_id": "tenant-a", "hostname": "web-01", "metrics": {"cpu_usage_pct": 78.5}, "log_lines": ["User login ok"]}'
        rec = self.parser.parse_line(nested_line, forced_format="jsonl")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["tenant_id"], "tenant-a")
        self.assertEqual(rec["hostname"], "web-01")
        self.assertEqual(rec["metrics"]["cpu_usage_pct"], 78.5)
        self.assertEqual(rec["log_lines"], ["User login ok"])

        # Flat format
        flat_line = '{"tenant_id": "tenant-b", "hostname": "db-01", "metric": "memory_used_pct", "value": 85.0, "severity": "WARNING"}'
        rec_flat = self.parser.parse_line(flat_line, forced_format="jsonl")
        self.assertIsNotNone(rec_flat)
        self.assertEqual(rec_flat["tenant_id"], "tenant-b")
        self.assertEqual(rec_flat["metrics"]["memory_usage_pct"], 85.0)

    def test_02_csv_parsing_with_aliases(self):
        """Verify CSV line parsing with alias column names and quoted log strings."""
        # Headers with aliases: host instead of hostname, cpu instead of value
        header = "tenant,host,metric,value,level,log"
        data_line = 'tenant-a,srv-prod-web-01.internal,cpu_usage_pct,92.4,CRITICAL,"Spike detected with password=SuperSecret123!"'
        
        # Parse header
        self.parser.parse_line(header, forced_format="csv")
        # Parse data row
        rec = self.parser.parse_line(data_line, forced_format="csv")
        
        self.assertIsNotNone(rec)
        self.assertEqual(rec["tenant_id"], "tenant-a")
        self.assertEqual(rec["hostname"], "srv-prod-web-01.internal")
        self.assertEqual(rec["metrics"]["cpu_usage_pct"], 92.4)
        self.assertEqual(rec["severity"], "CRITICAL")
        self.assertIn("password=SuperSecret123!", rec["log_lines"][0])

    def test_03_syslog_rfc5424_parsing(self):
        """Verify RFC 5424 Syslog parsing with key-value pairs."""
        syslog_line = "<134>1 2026-11-20T10:00:00Z srv-prod-web-01.internal SafeOpsApp - - tenant=tenant-a metric=cpu_usage_pct value=89.2 severity=WARNING token=ak_live_secret_44"
        rec = self.parser.parse_line(syslog_line, forced_format="syslog")
        
        self.assertIsNotNone(rec)
        self.assertEqual(rec["tenant_id"], "tenant-a")
        self.assertEqual(rec["hostname"], "srv-prod-web-01.internal")
        self.assertEqual(rec["metrics"]["cpu_usage_pct"], 89.2)
        self.assertEqual(rec["severity"], "WARNING")
        self.assertIn("ak_live_secret_44", rec["log_lines"][0])

    def test_04_syslog_rfc3164_parsing(self):
        """Verify RFC 3164 legacy BSD Syslog parsing."""
        legacy_syslog = "Nov 20 14:22:01 srv-db-01 SafeOpsApp[1024]: tenant=tenant-b metric=disk_used_pct value=95.5 severity=CRITICAL disk partition full"
        rec = self.parser.parse_line(legacy_syslog, forced_format="syslog")
        
        self.assertIsNotNone(rec)
        self.assertEqual(rec["tenant_id"], "tenant-b")
        self.assertEqual(rec["hostname"], "srv-db-01")
        self.assertEqual(rec["metrics"]["disk_usage_pct"], 95.5)

    def test_05_auto_detection(self):
        """Verify automatic sniffing of JSON, CSV, and Syslog format types."""
        json_sample = '{"tenant_id": "tenant-a", "metric": "cpu", "value": 10}'
        csv_sample = "tenant_id,hostname,metric,value\ntenant-a,h1,cpu,50"
        syslog_sample = "<134>1 2026-11-20T10:00:00Z h1 App - - tenant=tenant-a metric=cpu value=40"

        self.assertEqual(UniversalFormatParser.detect_format(json_sample), "jsonl")
        self.assertEqual(UniversalFormatParser.detect_format(csv_sample), "csv")
        self.assertEqual(UniversalFormatParser.detect_format(syslog_sample), "syslog")

    def test_06_malformed_lines_graceful(self):
        """Verify bad lines do not crash the parser."""
        bad_json = '{"broken": json without closing'
        self.assertIsNone(self.parser.parse_line(bad_json, forced_format="jsonl"))
        self.assertIsNone(self.parser.parse_line("", forced_format="jsonl"))
        self.assertIsNone(self.parser.parse_line("   ", forced_format="csv"))


class TestUniversalFeedAdapter(unittest.TestCase):

    def test_01_mode_switching_and_file_tailing(self):
        """Verify UniversalFeedAdapter switches modes and tails CSV file."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as tmp:
            tmp_path = tmp.name
            tmp.write("tenant_id,hostname,metric,value,category,severity\n")
            tmp.write("tenant-a,host-test-01,cpu_usage_pct,77.5,system,WARNING\n")
            tmp.flush()

        adapter = UniversalFeedAdapter(feed_file_path=tmp_path, default_mode="csv")
        self.assertEqual(adapter.get_mode(), "csv")

        # Fetch records
        records = adapter.fetch_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["hostname"], "host-test-01")
        self.assertEqual(records[0]["metrics"]["cpu_usage_pct"], 77.5)

        # Switch mode to http and test push queue
        adapter.set_mode("http")
        self.assertEqual(adapter.get_mode(), "http")
        adapter.push_external_payload({
            "tenant_id": "tenant-b",
            "hostname": "host-http-01",
            "metrics": {"network_latency_ms": 120.0}
        })
        records_http = adapter.fetch_records()
        self.assertEqual(len(records_http), 1)
        self.assertEqual(records_http[0]["hostname"], "host-http-01")

        if os.path.exists(tmp_path):
            os.remove(tmp_path)


class TestCollectorUniversalEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(collector_app)

    def test_01_status_contains_input_format(self):
        """Verify GET /api/v1/status reports active input format."""
        res = self.client.get("/api/v1/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("input_format", data)

    def test_02_switch_adapter_mode_api(self):
        """Verify POST /api/v1/adapter/mode updates mode."""
        res = self.client.post("/api/v1/adapter/mode", json={"mode": "csv"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["current_format"], "csv")

        # Switch back to simulator
        res2 = self.client.post("/api/v1/adapter/mode", json={"mode": "simulator"})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["current_format"], "simulator")

    def test_03_load_sample_feed_api(self):
        """Verify POST /api/v1/adapter/load_sample loads CSV/Syslog/JSONL samples."""
        for fmt in ["csv", "syslog", "jsonl"]:
            res = self.client.post("/api/v1/adapter/load_sample", json={"format": fmt})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["status"], "loaded")
            self.assertEqual(res.json()["format"], fmt)

        # Test reset
        res_reset = self.client.post("/api/v1/adapter/load_sample", json={"format": "simulator"})
        self.assertEqual(res_reset.status_code, 200)
        self.assertEqual(res_reset.json()["format"], "simulator")

    def test_04_http_push_endpoint(self):
        """Verify POST /api/v1/adapter/push accepts JSON, CSV, and Syslog strings."""
        # 1. JSON push
        json_payload = {
            "tenant_id": "tenant-a",
            "hostname": "srv-api-01",
            "metric": "cpu_usage_pct",
            "value": 82.0,
            "category": "system",
            "severity": "NORMAL"
        }
        res_json = self.client.post("/api/v1/adapter/push", json=json_payload)
        self.assertEqual(res_json.status_code, 200)
        self.assertEqual(res_json.json()["status"], "received")

        # 2. CSV push
        csv_payload = "tenant_id,hostname,metric,value\ntenant-a,srv-api-02,memory_used_pct,66.0"
        res_csv = self.client.post(
            "/api/v1/adapter/push",
            content=csv_payload,
            headers={"Content-Type": "text/csv"}
        )
        self.assertEqual(res_csv.status_code, 200)
        self.assertEqual(res_csv.json()["status"], "received")

        # 3. Syslog push
        syslog_payload = "<134>1 2026-11-20T10:00:00Z srv-api-03 SafeOps - - tenant=tenant-b metric=bandwidth_mbps value=450.0"
        res_syslog = self.client.post(
            "/api/v1/adapter/push",
            content=syslog_payload,
            headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(res_syslog.status_code, 200)
        self.assertEqual(res_syslog.json()["status"], "received")

    def test_05_redaction_and_sanitization_on_pushed_telemetry(self):
        """Verify secrets pushed via CSV/Syslog are 100% redacted before egress."""
        pipeline = CollectorPipeline()
        parser = UniversalFormatParser()
        
        # CSV with secret
        csv_line = 'tenant-a,srv-leak-01,cpu_usage_pct,99.0,system,CRITICAL,"Admin token=ak_live_secret_998811 login failed"'
        rec = parser.parse_line(csv_line, forced_format="csv")
        self.assertIsNotNone(rec)

        payloads = pipeline.process_raw_record(rec)
        self.assertTrue(len(payloads) > 0)
        for p in payloads:
            # Sensitive hostname must be pseudonymous
            self.assertFalse("srv-leak-01" in p["source_id"])
            self.assertTrue(p["source_id"].startswith("host-"))
            # Secret token must not be in short_context
            self.assertNotIn("ak_live_secret_998811", p["short_context"])


if __name__ == "__main__":
    unittest.main()
